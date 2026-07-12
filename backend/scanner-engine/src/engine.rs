use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use tokio::sync::{RwLock, Semaphore, watch};
use tokio::task::JoinHandle;
use tracing::{info, warn, error, instrument};

use crate::error::{Result, ScannerError};
use crate::rate_limiter::DynamicRateLimiter;
use crate::result::VulnerabilityResult;
use crate::target::{Target, TargetManager};
use crate::traits::{Detector, RateLimiter};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStatus {
    Idle,
    Scanning,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

impl ScanStatus {
    pub fn to_string(&self) -> &str {
        match self {
            ScanStatus::Idle => "idle",
            ScanStatus::Scanning => "scanning",
            ScanStatus::Paused => "paused",
            ScanStatus::Completed => "completed",
            ScanStatus::Failed => "failed",
            ScanStatus::Cancelled => "cancelled",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScanProgress {
    pub status: ScanStatus,
    pub total_targets: usize,
    pub completed_targets: usize,
    pub vulnerabilities_found: usize,
    pub current_target: Option<String>,
    pub start_time: Option<Instant>,
    pub end_time: Option<Instant>,
}

impl ScanProgress {
    pub fn new(total_targets: usize) -> Self {
        ScanProgress {
            status: ScanStatus::Idle,
            total_targets,
            completed_targets: 0,
            vulnerabilities_found: 0,
            current_target: None,
            start_time: None,
            end_time: None,
        }
    }

    pub fn percentage(&self) -> f64 {
        if self.total_targets == 0 {
            0.0
        } else {
            (self.completed_targets as f64 / self.total_targets as f64) * 100.0
        }
    }

    pub fn elapsed(&self) -> Option<std::time::Duration> {
        match (self.start_time, self.end_time) {
            (Some(start), Some(end)) => Some(end.duration_since(start)),
            (Some(start), None) => Some(Instant::now().duration_since(start)),
            _ => None,
        }
    }
}

/// 扫描生命周期管理器，负责任务的暂停、恢复和取消
#[derive(Debug)]
struct ScanLifecycle {
    cancelled: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
}

impl ScanLifecycle {
    fn new() -> Self {
        ScanLifecycle {
            cancelled: Arc::new(AtomicBool::new(false)),
            paused: Arc::new(AtomicBool::new(false)),
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
        self.paused.store(false, Ordering::SeqCst);
    }

    fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    async fn wait_if_paused(&self) {
        while self.is_paused() && !self.is_cancelled() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

pub struct ScannerEngine {
    target_manager: Arc<TargetManager>,
    detectors: Vec<Arc<dyn Detector + 'static>>,
    rate_limiter: Arc<RwLock<DynamicRateLimiter>>,
    semaphore: Arc<Semaphore>,
    progress: Arc<watch::Sender<ScanProgress>>,
    lifecycle: Arc<ScanLifecycle>,
    scan_handle: Option<JoinHandle<Result<Vec<VulnerabilityResult>>>>,
}

impl ScannerEngine {
    pub fn new(
        target_manager: Arc<TargetManager>,
        detectors: Vec<Arc<dyn Detector + 'static>>,
        concurrent_targets: usize,
        requests_per_second: f64,
    ) -> Self {
        let (progress_tx, _) = watch::channel(ScanProgress::new(0));

        ScannerEngine {
            target_manager,
            detectors: detectors.into_iter()
                .filter(|d| d.enabled())
                .collect(),
            rate_limiter: Arc::new(RwLock::new(DynamicRateLimiter::new(
                requests_per_second, 1.0, 20.0,
            ))),
            semaphore: Arc::new(Semaphore::new(concurrent_targets)),
            progress: Arc::new(progress_tx),
            lifecycle: Arc::new(ScanLifecycle::new()),
            scan_handle: None,
        }
    }

    #[instrument(skip(self), fields(engine = "scanner"))]
    pub async fn scan(&mut self) -> Result<Vec<VulnerabilityResult>> {
        if self.is_scanning().await {
            warn!("Scan already in progress, rejecting new scan request");
            return Err(ScannerError::Validation("Scan already in progress".to_string()));
        }

        let targets = self.target_manager.get_authorized_targets().await;
        if targets.is_empty() {
            warn!("No authorized targets to scan");
            return Err(ScannerError::Validation("No authorized targets to scan".to_string()));
        }

        info!(
            total_targets = targets.len(),
            detectors = self.detectors.len(),
            concurrent = self.semaphore.available_permits(),
            "Starting scan"
        );

        // 重置生命周期状态
        self.lifecycle = Arc::new(ScanLifecycle::new());

        let progress = ScanProgress {
            status: ScanStatus::Scanning,
            total_targets: targets.len(),
            completed_targets: 0,
            vulnerabilities_found: 0,
            current_target: None,
            start_time: Some(Instant::now()),
            end_time: None,
        };
        if let Err(e) = self.progress.send(progress) {
            warn!("Failed to send initial progress: {}", e);
        }

        let lifecycle = self.lifecycle.clone();
        let progress_tx = self.progress.clone();
        let rate_limiter = self.rate_limiter.clone();
        let semaphore = self.semaphore.clone();
        let detectors = self.detectors.clone();
        let total_targets = targets.len();

        let handle = tokio::spawn(async move {
            let scan_start = Instant::now();
            let results = Self::execute_scan_stream(
                targets,
                lifecycle,
                progress_tx,
                rate_limiter,
                semaphore,
                detectors,
                total_targets,
            ).await;

            let elapsed = scan_start.elapsed();
            match &results {
                Ok(res) => {
                    let total_vulns: usize = res.iter().map(|r| r.vulnerabilities.len()).sum();
                    info!(
                        total_targets = total_targets,
                        total_vulnerabilities = total_vulns,
                        elapsed_ms = elapsed.as_millis(),
                        "Scan completed successfully"
                    );
                }
                Err(e) => {
                    error!(error = %e, elapsed_ms = elapsed.as_millis(), "Scan failed");
                }
            }

            results
        });

        self.scan_handle = Some(handle);

        // 安全地等待扫描任务完成
        match self.scan_handle.as_mut() {
            Some(handle) => match handle.await {
                Ok(result) => result,
                Err(e) => {
                    error!("Scan task panicked: {}", e);
                    Err(ScannerError::Unknown(format!("Scan task panicked: {}", e)))
                }
            },
            None => {
                error!("Scan handle unexpectedly missing after spawn");
                Err(ScannerError::Unknown("Scan handle unexpectedly missing".to_string()))
            }
        }
    }

    #[instrument(skip_all, fields(total_targets))]
    async fn execute_scan_stream(
        targets: Vec<Target>,
        lifecycle: Arc<ScanLifecycle>,
        progress_tx: Arc<watch::Sender<ScanProgress>>,
        rate_limiter: Arc<RwLock<DynamicRateLimiter>>,
        semaphore: Arc<Semaphore>,
        detectors: Vec<Arc<dyn Detector + 'static>>,
        total_targets: usize,
    ) -> Result<Vec<VulnerabilityResult>> {
        let mut results = Vec::with_capacity(total_targets);
        let completed_targets = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let vulnerabilities_found = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // 使用 Stream API 实现流式并发处理
        let mut stream = stream::iter(targets)
            .map(|target| {
                let lifecycle = lifecycle.clone();
                let progress_tx = progress_tx.clone();
                let rate_limiter = rate_limiter.clone();
                let semaphore = semaphore.clone();
                let detectors = detectors.clone();
                let completed = completed_targets.clone();
                let vulns = vulnerabilities_found.clone();

                async move {
                    // 检查取消状态
                    if lifecycle.is_cancelled() {
                        return Ok(None);
                    }

                    // 等待暂停恢复
                    lifecycle.wait_if_paused().await;

                    if lifecycle.is_cancelled() {
                        return Ok(None);
                    }

                    let target_str = target.target_type.to_string();
                    info!(target = %target_str, "Scanning target");

                    if let Err(e) = progress_tx.send(ScanProgress {
                        status: ScanStatus::Scanning,
                        total_targets,
                        completed_targets: completed.load(Ordering::SeqCst),
                        vulnerabilities_found: vulns.load(Ordering::SeqCst),
                        current_target: Some(target_str.clone()),
                        start_time: None,
                        end_time: None,
                    }) {
                        warn!("Failed to send progress update: {}", e);
                    }

                    // 获取信号量许可，防止资源过载
                    let permit = match semaphore.acquire().await {
                        Ok(p) => p,
                        Err(e) => {
                            error!("Failed to acquire semaphore: {}", e);
                            return Err(ScannerError::Unknown(format!("Semaphore error: {}", e)));
                        }
                    };

                    let target_result = Self::scan_single_target(
                        &target,
                        &detectors,
                        &rate_limiter,
                        &lifecycle,
                    ).await;

                    // 显式释放许可，防止泄漏
                    drop(permit);

                    match target_result {
                        Ok(mut result) => {
                            let count = result.vulnerabilities.len();
                            result.complete();
                            completed.fetch_add(1, Ordering::SeqCst);
                            vulns.fetch_add(count, Ordering::SeqCst);
                            info!(
                                target = %target_str,
                                vulnerabilities = count,
                                "Target scan completed"
                            );
                            Ok(Some(result))
                        }
                        Err(e) => {
                            warn!(target = %target_str, error = %e, "Target scan failed");
                            completed.fetch_add(1, Ordering::SeqCst);
                            Ok(Some(VulnerabilityResult::new(target.id.clone())))
                        }
                    }
                }
            })
            .buffer_unordered(50); // 使用 Semaphore 控制并发，但保留 buffer_unordered 用于流式处理

        while let Some(item) = stream.next().await {
            match item {
                Ok(Some(result)) => {
                    results.push(result);
                }
                Ok(None) => {
                    // 扫描被取消
                    break;
                }
                Err(e) => {
                    error!(error = %e, "Stream item error");
                    // 继续处理其他目标，不中断整个扫描
                }
            }

            // 检查取消状态
            if lifecycle.is_cancelled() {
                info!("Scan cancelled by user");
                break;
            }
        }

        let final_completed = completed_targets.load(Ordering::SeqCst);
        let final_vulns = vulnerabilities_found.load(Ordering::SeqCst);

        if lifecycle.is_cancelled() {
            if let Err(e) = progress_tx.send(ScanProgress {
                status: ScanStatus::Cancelled,
                total_targets,
                completed_targets: final_completed,
                vulnerabilities_found: final_vulns,
                current_target: None,
                start_time: None,
                end_time: Some(Instant::now()),
            }) {
                warn!("Failed to send final cancelled progress: {}", e);
            }
            return Err(ScannerError::TaskCancelled);
        }

        if let Err(e) = progress_tx.send(ScanProgress {
            status: ScanStatus::Completed,
            total_targets,
            completed_targets: final_completed,
            vulnerabilities_found: final_vulns,
            current_target: None,
            start_time: None,
            end_time: Some(Instant::now()),
        }) {
            warn!("Failed to send final progress: {}", e);
        }

        Ok(results)
    }

    #[instrument(skip_all, fields(target_id = %target.id))]
    async fn scan_single_target(
        target: &Target,
        detectors: &[Arc<dyn Detector + 'static>],
        rate_limiter: &Arc<RwLock<DynamicRateLimiter>>,
        lifecycle: &ScanLifecycle,
    ) -> Result<VulnerabilityResult> {
        let mut target_result = VulnerabilityResult::new(target.id.clone());
        let target_str = target.target_type.to_string();

        for detector in detectors {
            if lifecycle.is_cancelled() {
                info!("Scan cancelled mid-target, stopping detectors");
                break;
            }

            lifecycle.wait_if_paused().await;

            if lifecycle.is_cancelled() {
                break;
            }

            let limiter = rate_limiter.read().await;
            match limiter.acquire(&target_str).await {
                Ok(_) => {
                    drop(limiter);
                    match detector.scan(target).await {
                        Ok(vulnerabilities) => {
                            let count = vulnerabilities.len();
                            for vuln in vulnerabilities {
                                target_result.add_vulnerability(vuln);
                            }
                            if count > 0 {
                                info!(
                                    detector = detector.name(),
                                    target = %target_str,
                                    vulnerabilities = count,
                                    "Vulnerabilities detected"
                                );
                            }
                            rate_limiter.write().await.record_success(&target_str).await;
                        }
                        Err(e) => {
                            warn!(
                                detector = detector.name(),
                                target = %target_str,
                                error = %e,
                                "Detector failed"
                            );
                            rate_limiter.write().await.record_failure(&target_str).await;
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        target = %target_str,
                        error = %e,
                        "Rate limit exceeded"
                    );
                }
            }
        }

        Ok(target_result)
    }

    #[instrument(skip(self))]
    pub async fn pause(&self) -> Result<()> {
        if !self.is_scanning().await {
            warn!("No scan in progress, cannot pause");
            return Err(ScannerError::Validation("No scan in progress".to_string()));
        }

        info!("Pausing scan");
        self.lifecycle.pause();

        let progress = self.get_progress().await;
        if let Err(e) = self.progress.send(ScanProgress {
            status: ScanStatus::Paused,
            ..progress
        }) {
            warn!("Failed to send paused progress: {}", e);
        }

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn resume(&self) -> Result<()> {
        let progress = self.get_progress().await;
        if progress.status != ScanStatus::Paused {
            warn!("Scan is not paused, cannot resume");
            return Err(ScannerError::Validation("Scan is not paused".to_string()));
        }

        info!("Resuming scan");
        self.lifecycle.resume();

        if let Err(e) = self.progress.send(ScanProgress {
            status: ScanStatus::Scanning,
            ..progress
        }) {
            warn!("Failed to send resumed progress: {}", e);
        }

        Ok(())
    }

    #[instrument(skip(self))]
    pub async fn cancel(&self) -> Result<()> {
        if !self.is_scanning().await && !self.is_paused().await {
            warn!("No scan in progress, cannot cancel");
            return Err(ScannerError::Validation("No scan in progress".to_string()));
        }

        info!("Cancelling scan");
        self.lifecycle.cancel();

        // 中止扫描任务句柄
        if let Some(handle) = &self.scan_handle {
            handle.abort();
            info!("Scan task aborted");
        }

        let progress = self.get_progress().await;
        if let Err(e) = self.progress.send(ScanProgress {
            status: ScanStatus::Cancelled,
            end_time: Some(Instant::now()),
            ..progress
        }) {
            warn!("Failed to send cancelled progress: {}", e);
        }

        Ok(())
    }

    pub async fn is_scanning(&self) -> bool {
        let progress = self.get_progress().await;
        progress.status == ScanStatus::Scanning
    }

    pub async fn is_paused(&self) -> bool {
        let progress = self.get_progress().await;
        progress.status == ScanStatus::Paused
    }

    pub async fn get_progress(&self) -> ScanProgress {
        self.progress.borrow().clone()
    }

    pub fn subscribe_progress(&self) -> watch::Receiver<ScanProgress> {
        self.progress.subscribe()
    }

    pub fn get_detectors(&self) -> Vec<&Arc<dyn Detector + 'static>> {
        self.detectors.iter().collect()
    }

    pub fn add_detector(&mut self, detector: Arc<dyn Detector + 'static>) {
        if detector.enabled() {
            self.detectors.push(detector);
        }
    }

    pub fn remove_detector(&mut self, name: &str) {
        self.detectors.retain(|d| d.name() != name);
    }

    pub fn set_concurrent_targets(&mut self, concurrent: usize) {
        self.semaphore = Arc::new(Semaphore::new(concurrent));
    }

    pub fn set_requests_per_second(&mut self, rate: f64) {
        let mut limiter = self.rate_limiter.blocking_write();
        limiter.set_rate_limit(rate);
    }

    /// 清理资源，释放所有持有的句柄和信号量
    pub async fn shutdown(&mut self) {
        info!("Shutting down scanner engine");

        if let Err(e) = self.cancel().await {
            warn!("Error during shutdown cancel: {}", e);
        }

        // 等待扫描任务完全结束
        if let Some(handle) = self.scan_handle.take() {
            let _ = tokio::time::timeout(Duration::from_secs(5), handle).await;
        }

        self.detectors.clear();
        info!("Scanner engine shutdown complete");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::target::{Target, TargetType};
    use crate::traits::{Detector, VulnerabilitySeverity};
    use crate::result::Vulnerability;
    use async_trait::async_trait;
    use reqwest::Client;
    use std::sync::Arc;
    use url::Url;

    #[derive(Debug)]
    struct MockDetector {
        name: String,
        enabled: bool,
    }

    #[async_trait]
    impl Detector for MockDetector {
        fn name(&self) -> &str {
            &self.name
        }

        fn severity(&self) -> VulnerabilitySeverity {
            VulnerabilitySeverity::High
        }

        fn description(&self) -> &str {
            "Mock detector for testing"
        }

        async fn scan(&self, _target: &Target) -> Result<Vec<Vulnerability>> {
            Ok(vec![])
        }

        fn enabled(&self) -> bool {
            self.enabled
        }
    }

    fn create_test_engine() -> ScannerEngine {
        let validator = Arc::new(crate::target::DefaultTargetValidator::new(
            Arc::new(Client::new()),
        ));
        let target_manager = Arc::new(TargetManager::new(
            validator,
            Arc::new(Client::new()),
        ));
        ScannerEngine::new(target_manager, vec![], 50, 10.0)
    }

    #[test]
    fn test_scan_status_to_string() {
        assert_eq!(ScanStatus::Idle.to_string(), "idle");
        assert_eq!(ScanStatus::Scanning.to_string(), "scanning");
        assert_eq!(ScanStatus::Paused.to_string(), "paused");
        assert_eq!(ScanStatus::Completed.to_string(), "completed");
        assert_eq!(ScanStatus::Failed.to_string(), "failed");
        assert_eq!(ScanStatus::Cancelled.to_string(), "cancelled");
    }

    #[test]
    fn test_scan_progress_percentage() {
        let progress = ScanProgress::new(100);
        assert_eq!(progress.percentage(), 0.0);

        let progress = ScanProgress {
            completed_targets: 50,
            total_targets: 100,
            ..ScanProgress::new(100)
        };
        assert_eq!(progress.percentage(), 50.0);

        let progress = ScanProgress::new(0);
        assert_eq!(progress.percentage(), 0.0);
    }

    #[test]
    fn test_scan_lifecycle() {
        let lifecycle = ScanLifecycle::new();
        assert!(!lifecycle.is_cancelled());
        assert!(!lifecycle.is_paused());

        lifecycle.pause();
        assert!(lifecycle.is_paused());

        lifecycle.resume();
        assert!(!lifecycle.is_paused());

        lifecycle.cancel();
        assert!(lifecycle.is_cancelled());
        assert!(!lifecycle.is_paused());
    }

    #[test]
    fn test_scanner_engine_new() {
        let engine = create_test_engine();
        assert_eq!(engine.get_detectors().len(), 0);
    }

    #[test]
    fn test_add_and_remove_detector() {
        let mut engine = create_test_engine();
        let detector = Arc::new(MockDetector {
            name: "test".to_string(),
            enabled: true,
        });

        engine.add_detector(detector);
        assert_eq!(engine.get_detectors().len(), 1);

        engine.remove_detector("test");
        assert_eq!(engine.get_detectors().len(), 0);
    }

    #[test]
    fn test_set_concurrent_targets() {
        let mut engine = create_test_engine();
        engine.set_concurrent_targets(100);
        // 无法直接验证内部状态，但确保不会 panic
    }

    #[tokio::test]
    async fn test_engine_lifecycle_transitions() {
        let mut engine = create_test_engine();

        // 初始状态应为 Idle
        let progress = engine.get_progress().await;
        assert_eq!(progress.status, ScanStatus::Idle);

        // 未扫描时暂停应报错
        assert!(engine.pause().await.is_err());

        // 未扫描时恢复应报错
        assert!(engine.resume().await.is_err());

        // 未扫描时取消应报错
        assert!(engine.cancel().await.is_err());
    }

    #[tokio::test]
    async fn test_shutdown_cleans_resources() {
        let mut engine = create_test_engine();
        engine.shutdown().await;
        assert_eq!(engine.get_detectors().len(), 0);
    }
}
