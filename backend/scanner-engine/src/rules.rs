use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use notify::{RecommendedWatcher, RecursiveMode, Watcher, Config as NotifyConfig};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, mpsc};
use tracing::{info, warn, error, debug, instrument};

use crate::error::{Result, ScannerError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanRule {
    pub id: String,
    pub name: String,
    pub detector: String,
    pub severity: String,
    pub enabled: bool,
    pub priority: u32,
    pub payloads: Vec<String>,
    pub patterns: Vec<String>,
    pub description: String,
    pub remediation: String,
    pub cvss_vector: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleConfig {
    pub rules: Vec<ScanRule>,
    pub detector_configs: HashMap<String, DetectorConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DetectorConfig {
    pub enabled: bool,
    pub max_requests: Option<u32>,
    pub timeout_ms: Option<u64>,
    pub custom_settings: HashMap<String, String>,
}

/// 规则热加载事件类型
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleReloadEvent {
    RulesReloaded(usize),
    ReloadFailed(String),
}

#[derive(Debug, Clone)]
pub struct RuleManager {
    rules: Arc<RwLock<Vec<ScanRule>>>,
    detector_configs: Arc<RwLock<HashMap<String, DetectorConfig>>>,
    rules_directory: Option<String>,
    last_reload: Arc<RwLock<std::time::Instant>>,
    watcher_active: Arc<RwLock<bool>>,
}

impl RuleManager {
    pub fn new() -> Self {
        RuleManager {
            rules: Arc::new(RwLock::new(Vec::new())),
            detector_configs: Arc::new(RwLock::new(HashMap::new())),
            rules_directory: None,
            last_reload: Arc::new(RwLock::new(std::time::Instant::now())),
            watcher_active: Arc::new(RwLock::new(false)),
        }
    }

    pub fn with_rules_directory(mut self, directory: &str) -> Self {
        self.rules_directory = Some(directory.to_string());
        self
    }

    pub async fn load_rules(&self) -> Result<()> {
        if let Some(dir) = &self.rules_directory {
            self.load_rules_from_directory(dir).await
        } else {
            debug!("No rules directory configured, skipping load");
            Ok(())
        }
    }

    #[instrument(skip(self), fields(directory = %directory))]
    pub async fn load_rules_from_directory(&self, directory: &str) -> Result<()> {
        let path = Path::new(directory);
        if !path.exists() {
            return Err(ScannerError::Config(format!("Rules directory does not exist: {}", directory)));
        }

        if !path.is_dir() {
            return Err(ScannerError::Config(format!("Path is not a directory: {}", directory)));
        }

        let mut all_rules = Vec::new();
        let mut all_configs = HashMap::new();

        let entries = std::fs::read_dir(path)
            .map_err(ScannerError::Io)?;

        for entry in entries {
            let entry = entry.map_err(ScannerError::Io)?;
            let file_path = entry.path();

            if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
                let content = match std::fs::read_to_string(&file_path) {
                    Ok(c) => c,
                    Err(e) => {
                        warn!(path = %file_path.display(), error = %e, "Failed to read rule file");
                        continue;
                    }
                };

                match ext.to_lowercase().as_str() {
                    "yaml" | "yml" => {
                        match serde_yaml::from_str::<RuleConfig>(&content) {
                            Ok(config) => {
                                all_rules.extend(config.rules);
                                all_configs.extend(config.detector_configs);
                            }
                            Err(e) => {
                                warn!(path = %file_path.display(), error = %e, "Failed to parse YAML rule file");
                            }
                        }
                    }
                    "json" => {
                        match serde_json::from_str::<RuleConfig>(&content) {
                            Ok(config) => {
                                all_rules.extend(config.rules);
                                all_configs.extend(config.detector_configs);
                            }
                            Err(e) => {
                                warn!(path = %file_path.display(), error = %e, "Failed to parse JSON rule file");
                            }
                        }
                    }
                    _ => {
                        debug!(path = %file_path.display(), "Skipping unsupported file type");
                    }
                }
            }
        }

        let rules_count = all_rules.len();

        let mut rules_lock = self.rules.write().await;
        *rules_lock = all_rules;

        let mut configs_lock = self.detector_configs.write().await;
        *configs_lock = all_configs;

        let mut last_reload_lock = self.last_reload.write().await;
        *last_reload_lock = std::time::Instant::now();

        info!(
            rules_count = rules_count,
            directory = %directory,
            "Rules loaded successfully"
        );

        Ok(())
    }

    pub async fn load_rules_from_string(&self, content: &str, format: &str) -> Result<()> {
        let config: RuleConfig = match format.to_lowercase().as_str() {
            "yaml" | "yml" => serde_yaml::from_str(content)
                .map_err(ScannerError::YamlParse)?,
            "json" => serde_json::from_str(content)
                .map_err(ScannerError::JsonParse)?,
            _ => return Err(ScannerError::Config(format!("Unsupported format: {}", format))),
        };

        let mut rules_lock = self.rules.write().await;
        rules_lock.extend(config.rules);

        let mut configs_lock = self.detector_configs.write().await;
        configs_lock.extend(config.detector_configs);

        let mut last_reload_lock = self.last_reload.write().await;
        *last_reload_lock = std::time::Instant::now();

        info!(rules_count = rules_lock.len(), "Rules loaded from string");

        Ok(())
    }

    pub async fn add_rule(&self, rule: ScanRule) -> Result<()> {
        let mut rules = self.rules.write().await;

        if rules.iter().any(|r| r.id == rule.id) {
            return Err(ScannerError::Config(format!("Rule with id {} already exists", rule.id)));
        }

        rules.push(rule);
        Ok(())
    }

    pub async fn remove_rule(&self, id: &str) -> Result<bool> {
        let mut rules = self.rules.write().await;
        let original_len = rules.len();

        rules.retain(|r| r.id != id);

        Ok(original_len != rules.len())
    }

    pub async fn get_rule(&self, id: &str) -> Option<ScanRule> {
        let rules = self.rules.read().await;
        rules.iter().find(|r| r.id == id).cloned()
    }

    pub async fn get_rules(&self) -> Vec<ScanRule> {
        let rules = self.rules.read().await;
        rules.clone()
    }

    pub async fn get_rules_by_detector(&self, detector_name: &str) -> Vec<ScanRule> {
        let rules = self.rules.read().await;
        rules.iter()
            .filter(|r| r.detector == detector_name)
            .cloned()
            .collect()
    }

    pub async fn get_enabled_rules(&self) -> Vec<ScanRule> {
        let rules = self.rules.read().await;
        rules.iter()
            .filter(|r| r.enabled)
            .cloned()
            .collect()
    }

    pub async fn get_detector_config(&self, detector_name: &str) -> Option<DetectorConfig> {
        let configs = self.detector_configs.read().await;
        configs.get(detector_name).cloned()
    }

    pub async fn set_detector_config(&self, detector_name: &str, config: DetectorConfig) {
        let mut configs = self.detector_configs.write().await;
        configs.insert(detector_name.to_string(), config);
    }

    pub async fn get_last_reload_time(&self) -> std::time::Instant {
        *self.last_reload.read().await
    }

    pub async fn get_rules_count(&self) -> usize {
        let rules = self.rules.read().await;
        rules.len()
    }

    /// 启动文件监控实现热加载，返回一个接收器用于接收重载事件
    #[instrument(skip(self))]
    pub async fn start_hot_reload(&self) -> Result<mpsc::Receiver<RuleReloadEvent>> {
        let dir = match &self.rules_directory {
            Some(d) => d.clone(),
            None => return Err(ScannerError::Config("Rules directory not set".to_string())),
        };

        let path = Path::new(&dir);
        if !path.exists() || !path.is_dir() {
            return Err(ScannerError::Config(format!("Invalid rules directory: {}", dir)));
        }

        // 检查是否已有活跃的 watcher
        {
            let active = self.watcher_active.read().await;
            if *active {
                warn!("Hot reload watcher already active");
                return Err(ScannerError::Config("Watcher already active".to_string()));
            }
        }

        let (event_tx, event_rx) = mpsc::channel(32);
        let rules_manager = self.clone();

        // 使用 tokio::task::spawn_blocking 运行同步文件监控
        let watcher_handle = tokio::task::spawn_blocking(move || {
            let path = Path::new(&dir);
            let (notify_tx, notify_rx) = std::sync::mpsc::channel();

            let mut watcher = match RecommendedWatcher::new(
                notify_tx,
                NotifyConfig::default().with_poll_interval(Duration::from_secs(2)),
            ) {
                Ok(w) => w,
                Err(e) => {
                    error!("Failed to create file watcher: {}", e);
                    return;
                }
            };

            if let Err(e) = watcher.watch(path, RecursiveMode::NonRecursive) {
                error!("Failed to watch directory: {}", e);
                return;
            }

            info!(directory = %dir, "File watcher started for hot reload");

            // 设置活跃标志
            {
                let rt = match tokio::runtime::Handle::try_current() {
                    Ok(h) => h,
                    Err(_) => return,
                };
                let manager = rules_manager.clone();
                rt.block_on(async {
                    let mut active = manager.watcher_active.write().await;
                    *active = true;
                });
            }

            let debounce_duration = Duration::from_secs(2);
            let mut last_event_time = std::time::Instant::now();

            loop {
                match notify_rx.recv_timeout(Duration::from_secs(1)) {
                    Ok(event) => {
                        debug!(event = ?event, "File system event received");

                        // 简单的去抖处理
                        let now = std::time::Instant::now();
                        if now.duration_since(last_event_time) < debounce_duration {
                            continue;
                        }
                        last_event_time = now;

                        // 触发规则重载
                        let rt = match tokio::runtime::Handle::try_current() {
                            Ok(h) => h,
                            Err(_) => continue,
                        };

                        let manager = rules_manager.clone();
                        let tx = event_tx.clone();

                        rt.block_on(async move {
                            match manager.reload_rules().await {
                                Ok(_) => {
                                    let count = manager.get_rules_count().await;
                                    info!(rules_count = count, "Hot reload completed");
                                    let _ = tx.send(RuleReloadEvent::RulesReloaded(count)).await;
                                }
                                Err(e) => {
                                    error!(error = %e, "Hot reload failed");
                                    let _ = tx.send(RuleReloadEvent::ReloadFailed(e.to_string())).await;
                                }
                            }
                        });
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        // 正常超时，继续循环
                        continue;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        info!("File watcher channel disconnected, stopping watcher");
                        break;
                    }
                }
            }

            // 清除活跃标志
            {
                let rt = match tokio::runtime::Handle::try_current() {
                    Ok(h) => h,
                    Err(_) => return,
                };
                let manager = rules_manager;
                rt.block_on(async {
                    let mut active = manager.watcher_active.write().await;
                    *active = false;
                });
            }
        });

        // 分离 watcher 任务，让它在后台运行
        drop(watcher_handle);

        Ok(event_rx)
    }

    /// 停止热加载监控
    pub async fn stop_hot_reload(&self) {
        let mut active = self.watcher_active.write().await;
        *active = false;
        info!("Hot reload watcher stopped");
    }

    pub async fn reload_rules(&self) -> Result<()> {
        if let Some(dir) = &self.rules_directory {
            self.load_rules_from_directory(dir).await
        } else {
            Err(ScannerError::Config("Rules directory not set".to_string()))
        }
    }
}

impl Default for RuleManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_rule_manager_new() {
        let manager = RuleManager::new();
        assert_eq!(manager.get_rules_count().await, 0);
    }

    #[tokio::test]
    async fn test_add_rule() {
        let manager = RuleManager::new();

        let rule = ScanRule {
            id: "test-rule-1".to_string(),
            name: "Test Rule".to_string(),
            detector: "sql_injection".to_string(),
            severity: "critical".to_string(),
            enabled: true,
            priority: 10,
            payloads: vec!["' OR 1=1--".to_string()],
            patterns: vec![],
            description: "Test rule".to_string(),
            remediation: "Fix it".to_string(),
            cvss_vector: Some("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
        };

        assert!(manager.add_rule(rule).await.is_ok());
        assert_eq!(manager.get_rules_count().await, 1);
    }

    #[tokio::test]
    async fn test_add_duplicate_rule() {
        let manager = RuleManager::new();

        let rule1 = ScanRule {
            id: "test-rule-1".to_string(),
            name: "Test Rule".to_string(),
            detector: "sql_injection".to_string(),
            severity: "critical".to_string(),
            enabled: true,
            priority: 10,
            payloads: vec!["' OR 1=1--".to_string()],
            patterns: vec![],
            description: "Test rule".to_string(),
            remediation: "Fix it".to_string(),
            cvss_vector: None,
        };

        let rule2 = rule1.clone();

        assert!(manager.add_rule(rule1).await.is_ok());
        assert!(manager.add_rule(rule2).await.is_err());
    }

    #[tokio::test]
    async fn test_remove_rule() {
        let manager = RuleManager::new();

        let rule = ScanRule {
            id: "test-rule-1".to_string(),
            name: "Test Rule".to_string(),
            detector: "sql_injection".to_string(),
            severity: "critical".to_string(),
            enabled: true,
            priority: 10,
            payloads: vec!["' OR 1=1--".to_string()],
            patterns: vec![],
            description: "Test rule".to_string(),
            remediation: "Fix it".to_string(),
            cvss_vector: None,
        };

        assert!(manager.add_rule(rule).await.is_ok());
        assert!(manager.remove_rule("test-rule-1").await.unwrap());
        assert_eq!(manager.get_rules_count().await, 0);
    }

    #[tokio::test]
    async fn test_get_rule() {
        let manager = RuleManager::new();

        let rule = ScanRule {
            id: "test-rule-1".to_string(),
            name: "Test Rule".to_string(),
            detector: "sql_injection".to_string(),
            severity: "critical".to_string(),
            enabled: true,
            priority: 10,
            payloads: vec!["' OR 1=1--".to_string()],
            patterns: vec![],
            description: "Test rule".to_string(),
            remediation: "Fix it".to_string(),
            cvss_vector: None,
        };

        assert!(manager.add_rule(rule).await.is_ok());
        let retrieved = manager.get_rule("test-rule-1").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "Test Rule");
    }

    #[tokio::test]
    async fn test_load_rules_from_yaml_string() {
        let manager = RuleManager::new();

        let yaml_content = r#"
rules:
  - id: yaml-rule-1
    name: YAML Test Rule
    detector: xss
    severity: high
    enabled: true
    priority: 20
    payloads:
      - "<script>alert(1)</script>"
    patterns: []
    description: Test rule from YAML
    remediation: Fix it
    cvss_vector: "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"

detector_configs:
  xss:
    enabled: true
    max_requests: 100
    timeout_ms: 5000
    custom_settings:
      key: value
"#;

        assert!(manager.load_rules_from_string(yaml_content, "yaml").await.is_ok());
        assert_eq!(manager.get_rules_count().await, 1);
    }

    #[tokio::test]
    async fn test_load_rules_from_json_string() {
        let manager = RuleManager::new();

        let json_content = r#"{
            "rules": [
                {
                    "id": "json-rule-1",
                    "name": "JSON Test Rule",
                    "detector": "sql_injection",
                    "severity": "critical",
                    "enabled": true,
                    "priority": 10,
                    "payloads": ["' OR 1=1--"],
                    "patterns": [],
                    "description": "Test rule from JSON",
                    "remediation": "Fix it",
                    "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            ],
            "detector_configs": {}
        }"#;

        assert!(manager.load_rules_from_string(json_content, "json").await.is_ok());
        assert_eq!(manager.get_rules_count().await, 1);
    }

    #[tokio::test]
    async fn test_load_rules_from_directory() {
        let dir = tempdir().unwrap();
        let dir_path = dir.path().to_str().unwrap();

        let yaml_content = r#"
rules:
  - id: dir-rule-1
    name: Directory Test Rule
    detector: sensitive_file
    severity: medium
    enabled: true
    priority: 30
    payloads: []
    patterns: []
    description: Test rule from directory
    remediation: Fix it
    cvss_vector: null

detector_configs: {}
"#;

        let file_path = dir.path().join("rules.yaml");
        std::fs::write(&file_path, yaml_content).unwrap();

        let manager = RuleManager::new().with_rules_directory(dir_path);
        assert!(manager.load_rules().await.is_ok());
        assert_eq!(manager.get_rules_count().await, 1);
    }

    #[tokio::test]
    async fn test_get_rules_by_detector() {
        let manager = RuleManager::new();

        let rule1 = ScanRule {
            id: "rule-1".to_string(),
            name: "SQL Rule".to_string(),
            detector: "sql_injection".to_string(),
            severity: "critical".to_string(),
            enabled: true,
            priority: 10,
            payloads: vec!["' OR 1=1--".to_string()],
            patterns: vec![],
            description: "SQL rule".to_string(),
            remediation: "Fix it".to_string(),
            cvss_vector: None,
        };

        let rule2 = ScanRule {
            id: "rule-2".to_string(),
            name: "XSS Rule".to_string(),
            detector: "xss".to_string(),
            severity: "high".to_string(),
            enabled: true,
            priority: 20,
            payloads: vec!["<script>alert(1)</script>".to_string()],
            patterns: vec![],
            description: "XSS rule".to_string(),
            remediation: "Fix it".to_string(),
            cvss_vector: None,
        };

        assert!(manager.add_rule(rule1).await.is_ok());
        assert!(manager.add_rule(rule2).await.is_ok());

        let sql_rules = manager.get_rules_by_detector("sql_injection").await;
        assert_eq!(sql_rules.len(), 1);

        let xss_rules = manager.get_rules_by_detector("xss").await;
        assert_eq!(xss_rules.len(), 1);
    }

    #[tokio::test]
    async fn test_get_enabled_rules() {
        let manager = RuleManager::new();

        let rule1 = ScanRule {
            id: "rule-1".to_string(),
            name: "Enabled Rule".to_string(),
            detector: "sql_injection".to_string(),
            severity: "critical".to_string(),
            enabled: true,
            priority: 10,
            payloads: vec!["' OR 1=1--".to_string()],
            patterns: vec![],
            description: "Enabled rule".to_string(),
            remediation: "Fix it".to_string(),
            cvss_vector: None,
        };

        let rule2 = ScanRule {
            id: "rule-2".to_string(),
            name: "Disabled Rule".to_string(),
            detector: "xss".to_string(),
            severity: "high".to_string(),
            enabled: false,
            priority: 20,
            payloads: vec!["<script>alert(1)</script>".to_string()],
            patterns: vec![],
            description: "Disabled rule".to_string(),
            remediation: "Fix it".to_string(),
            cvss_vector: None,
        };

        assert!(manager.add_rule(rule1).await.is_ok());
        assert!(manager.add_rule(rule2).await.is_ok());

        let enabled_rules = manager.get_enabled_rules().await;
        assert_eq!(enabled_rules.len(), 1);
    }

    #[tokio::test]
    async fn test_detector_config() {
        let manager = RuleManager::new();

        let config = DetectorConfig {
            enabled: true,
            max_requests: Some(50),
            timeout_ms: Some(3000),
            custom_settings: HashMap::from([("key".to_string(), "value".to_string())]),
        };

        manager.set_detector_config("sql_injection", config).await;

        let retrieved = manager.get_detector_config("sql_injection").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().max_requests, Some(50));
    }

    #[tokio::test]
    async fn test_hot_reload_without_directory() {
        let manager = RuleManager::new();
        let result = manager.start_hot_reload().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rule_reload_event() {
        let event = RuleReloadEvent::RulesReloaded(5);
        assert_eq!(event, RuleReloadEvent::RulesReloaded(5));

        let event = RuleReloadEvent::ReloadFailed("test error".to_string());
        assert_eq!(event, RuleReloadEvent::ReloadFailed("test error".to_string()));
    }
}
