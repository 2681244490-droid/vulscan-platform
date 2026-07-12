use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};

use crate::error::{Result, ScannerError};
use crate::traits::RateLimiter;

/// 默认单目标最大请求速率: 10 req/s
const DEFAULT_MAX_RATE_PER_TARGET: f64 = 10.0;

/// 令牌桶状态
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    rate: f64,
    last_refill: std::time::Instant,
}

impl TokenBucket {
    fn new(rate: f64, capacity: f64) -> Self {
        TokenBucket {
            tokens: capacity,
            capacity,
            rate,
            last_refill: std::time::Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let tokens_to_add = elapsed * self.rate;

        self.tokens = (self.tokens + tokens_to_add).min(self.capacity);
        self.last_refill = now;
    }

    fn try_consume(&mut self, amount: f64) -> bool {
        self.refill();
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }

    fn wait_time_for(&self, amount: f64) -> Duration {
        let needed = amount - self.tokens;
        if needed <= 0.0 {
            Duration::from_secs(0)
        } else {
            Duration::from_secs_f64(needed / self.rate)
        }
    }
}

/// 基于令牌桶的速率限制器，确保单目标速率不超过阈值
#[derive(Debug)]
pub struct TokenBucketRateLimiter {
    state: Arc<RwLock<HashMap<String, TokenBucket>>>,
    requests_per_second: f64,
    max_rate_per_target: f64,
}

impl TokenBucketRateLimiter {
    pub fn new(requests_per_second: f64) -> Self {
        TokenBucketRateLimiter {
            state: Arc::new(RwLock::new(HashMap::new())),
            requests_per_second: requests_per_second.min(DEFAULT_MAX_RATE_PER_TARGET),
            max_rate_per_target: DEFAULT_MAX_RATE_PER_TARGET,
        }
    }

    /// 创建新的令牌桶
    fn create_bucket(&self) -> TokenBucket {
        let capacity = self.requests_per_second * 2.0;
        TokenBucket::new(self.requests_per_second, capacity)
    }

    /// 获取当前配置的单目标最大速率
    pub fn max_rate_per_target(&self) -> f64 {
        self.max_rate_per_target
    }

    /// 设置单目标最大速率（上限 10 req/s）
    pub fn set_max_rate_per_target(&mut self, rate: f64) {
        self.max_rate_per_target = rate.min(DEFAULT_MAX_RATE_PER_TARGET);
        self.requests_per_second = self.requests_per_second.min(self.max_rate_per_target);
    }
}

#[async_trait]
impl RateLimiter for TokenBucketRateLimiter {
    async fn acquire(&self, target: &str) -> Result<()> {
        let mut state = self.state.write().await;
        let bucket = state.entry(target.to_string())
            .or_insert_with(|| self.create_bucket());

        if bucket.try_consume(1.0) {
            debug!(target = %target, tokens = bucket.tokens, "Rate limit token acquired");
            Ok(())
        } else {
            let wait_time = bucket.wait_time_for(1.0);
            drop(state);

            debug!(target = %target, wait_ms = wait_time.as_millis(), "Rate limit reached, waiting");
            tokio::time::sleep(wait_time).await;

            let mut state = self.state.write().await;
            let bucket = state.entry(target.to_string())
                .or_insert_with(|| self.create_bucket());

            if bucket.try_consume(1.0) {
                Ok(())
            } else {
                Err(ScannerError::RateLimit(format!(
                    "Rate limit exceeded for {}: max {} req/s",
                    target,
                    self.max_rate_per_target
                )))
            }
        }
    }

    fn set_rate_limit(&mut self, requests_per_second: f64) {
        self.requests_per_second = requests_per_second.min(self.max_rate_per_target);
        info!(
            new_rate = self.requests_per_second,
            max_rate = self.max_rate_per_target,
            "Rate limit updated"
        );
    }

    fn get_rate_limit(&self) -> f64 {
        self.requests_per_second
    }

    fn reset(&self, target: &str) {
        let mut state = self.state.blocking_write();
        state.remove(target);
        debug!(target = %target, "Rate limiter reset for target");
    }
}

/// 动态速率限制器，根据成功率动态调整请求速率
#[derive(Debug)]
pub struct DynamicRateLimiter {
    inner: Arc<RwLock<TokenBucketRateLimiter>>,
    min_rate: f64,
    max_rate: f64,
    failure_threshold: f64,
    recovery_factor: f64,
    failure_counts: Arc<RwLock<HashMap<String, u32>>>,
    success_counts: Arc<RwLock<HashMap<String, u32>>>,
    last_adjustment: Arc<RwLock<HashMap<String, std::time::Instant>>>,
    adjustment_cooldown: Duration,
}

impl DynamicRateLimiter {
    pub fn new(initial_rate: f64, min_rate: f64, max_rate: f64) -> Self {
        let clamped_max = max_rate.min(DEFAULT_MAX_RATE_PER_TARGET);
        let clamped_initial = initial_rate.clamp(min_rate, clamped_max);

        DynamicRateLimiter {
            inner: Arc::new(RwLock::new(TokenBucketRateLimiter::new(clamped_initial))),
            min_rate,
            max_rate: clamped_max,
            failure_threshold: 0.3,
            recovery_factor: 0.1,
            failure_counts: Arc::new(RwLock::new(HashMap::new())),
            success_counts: Arc::new(RwLock::new(HashMap::new())),
            last_adjustment: Arc::new(RwLock::new(HashMap::new())),
            adjustment_cooldown: Duration::from_secs(5),
        }
    }

    /// 记录成功请求，可能提升速率
    pub async fn record_success(&self, target: &str) {
        let mut failures = self.failure_counts.write().await;
        if let Some(count) = failures.get_mut(target) {
            *count = (*count as f64 * (1.0 - self.recovery_factor)) as u32;
            if *count == 0 {
                failures.remove(target);
            }
        }

        let mut successes = self.success_counts.write().await;
        *successes.entry(target.to_string()).or_default() += 1;

        // 如果连续成功足够多，考虑提升速率
        let success_count = successes.get(target).copied().unwrap_or(0);
        if success_count >= 10 {
            self.try_increase_rate(target).await;
            successes.insert(target.to_string(), 0);
        }
    }

    /// 记录失败请求，动态降低速率
    pub async fn record_failure(&self, target: &str) {
        let mut failures = self.failure_counts.write().await;
        *failures.entry(target.to_string()).or_default() += 1;

        let failure_count = failures.get(target).copied().unwrap_or(0);
        let mut successes = self.success_counts.write().await;
        successes.insert(target.to_string(), 0);

        // 如果失败次数超过阈值，降低速率
        if failure_count >= 3 {
            drop(failures);
            drop(successes);
            self.try_decrease_rate(target).await;
        }
    }

    /// 尝试提升速率
    async fn try_increase_rate(&self, target: &str) {
        if !self.can_adjust(target).await {
            return;
        }

        let mut inner = self.inner.write().await;
        let current_rate = inner.get_rate_limit();
        if current_rate < self.max_rate {
            let new_rate = (current_rate * 1.1).min(self.max_rate);
            inner.set_rate_limit(new_rate);
            info!(
                target = %target,
                old_rate = current_rate,
                new_rate = new_rate,
                "Rate limit increased due to consistent success"
            );
        }

        let mut last_adj = self.last_adjustment.write().await;
        last_adj.insert(target.to_string(), std::time::Instant::now());
    }

    /// 尝试降低速率
    async fn try_decrease_rate(&self, target: &str) {
        if !self.can_adjust(target).await {
            return;
        }

        let mut inner = self.inner.write().await;
        let current_rate = inner.get_rate_limit();
        if current_rate > self.min_rate {
            let new_rate = (current_rate * 0.9).max(self.min_rate);
            inner.set_rate_limit(new_rate);
            warn!(
                target = %target,
                old_rate = current_rate,
                new_rate = new_rate,
                "Rate limit decreased due to repeated failures"
            );
        }

        let mut last_adj = self.last_adjustment.write().await;
        last_adj.insert(target.to_string(), std::time::Instant::now());
    }

    /// 检查是否可以通过冷却期进行调整
    async fn can_adjust(&self, target: &str) -> bool {
        let last_adj = self.last_adjustment.read().await;
        match last_adj.get(target) {
            Some(last) => last.elapsed() >= self.adjustment_cooldown,
            None => true,
        }
    }

    /// 获取目标的失败率
    pub async fn get_failure_rate(&self, target: &str) -> f64 {
        let failures = self.failure_counts.read().await;
        let successes = self.success_counts.read().await;

        let f = failures.get(target).copied().unwrap_or(0) as f64;
        let s = successes.get(target).copied().unwrap_or(0) as f64;
        let total = f + s;

        if total > 0.0 {
            f / total
        } else {
            0.0
        }
    }

    /// 获取当前配置参数
    pub fn get_config(&self) -> DynamicRateLimiterConfig {
        DynamicRateLimiterConfig {
            min_rate: self.min_rate,
            max_rate: self.max_rate,
            failure_threshold: self.failure_threshold,
            recovery_factor: self.recovery_factor,
        }
    }

    /// 重置目标的所有统计信息
    pub async fn reset_target_stats(&self, target: &str) {
        let mut failures = self.failure_counts.write().await;
        failures.remove(target);
        let mut successes = self.success_counts.write().await;
        successes.remove(target);
        let mut last_adj = self.last_adjustment.write().await;
        last_adj.remove(target);
    }
}

#[derive(Debug, Clone)]
pub struct DynamicRateLimiterConfig {
    pub min_rate: f64,
    pub max_rate: f64,
    pub failure_threshold: f64,
    pub recovery_factor: f64,
}

#[async_trait]
impl RateLimiter for DynamicRateLimiter {
    async fn acquire(&self, target: &str) -> Result<()> {
        self.inner.read().await.acquire(target).await
    }

    fn set_rate_limit(&mut self, requests_per_second: f64) {
        let clamped = requests_per_second.clamp(self.min_rate, self.max_rate);
        let mut inner = self.inner.blocking_write();
        inner.set_rate_limit(clamped);
    }

    fn get_rate_limit(&self) -> f64 {
        let inner = self.inner.blocking_read();
        inner.get_rate_limit()
    }

    fn reset(&self, target: &str) {
        let inner = self.inner.blocking_write();
        inner.reset(target);
        let mut failures = self.failure_counts.blocking_write();
        failures.remove(target);
        let mut successes = self.success_counts.blocking_write();
        successes.remove(target);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_token_bucket_acquire() {
        let limiter = TokenBucketRateLimiter::new(10.0);

        for _ in 0..5 {
            assert!(limiter.acquire("test").await.is_ok());
        }
    }

    #[tokio::test]
    async fn test_token_bucket_rate_limit() {
        let limiter = TokenBucketRateLimiter::new(1.0);

        for _ in 0..3 {
            let _ = limiter.acquire("test").await;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    #[tokio::test]
    async fn test_token_bucket_max_rate_enforced() {
        let mut limiter = TokenBucketRateLimiter::new(15.0);
        // 即使请求 15 req/s，也应该被限制到 10 req/s
        assert_eq!(limiter.get_rate_limit(), 10.0);

        limiter.set_max_rate_per_target(8.0);
        limiter.set_rate_limit(20.0);
        assert_eq!(limiter.get_rate_limit(), 8.0);
    }

    #[tokio::test]
    async fn test_dynamic_rate_limiter() {
        let limiter = DynamicRateLimiter::new(10.0, 1.0, 20.0);

        assert_eq!(limiter.get_rate_limit(), 10.0);

        for _ in 0..10 {
            limiter.record_failure("test").await;
        }

        assert!(limiter.get_rate_limit() < 10.0);
    }

    #[tokio::test]
    async fn test_dynamic_rate_increase() {
        let limiter = DynamicRateLimiter::new(5.0, 1.0, 10.0);
        assert_eq!(limiter.get_rate_limit(), 5.0);

        // 模拟连续成功
        for _ in 0..15 {
            limiter.record_success("test").await;
        }

        // 速率应该提升
        assert!(limiter.get_rate_limit() > 5.0);
    }

    #[tokio::test]
    async fn test_dynamic_rate_failure_rate() {
        let limiter = DynamicRateLimiter::new(10.0, 1.0, 10.0);

        limiter.record_success("test").await;
        limiter.record_success("test").await;
        limiter.record_failure("test").await;

        let rate = limiter.get_failure_rate("test").await;
        assert!(rate > 0.0);
        assert!(rate < 1.0);
    }

    #[tokio::test]
    async fn test_dynamic_rate_cooldown() {
        let limiter = DynamicRateLimiter::new(10.0, 1.0, 10.0);

        // 第一次应该可以调整
        assert!(limiter.can_adjust("test").await);

        // 记录调整时间
        {
            let mut last_adj = limiter.last_adjustment.write().await;
            last_adj.insert("test".to_string(), std::time::Instant::now());
        }

        // 冷却期内不应调整
        assert!(!limiter.can_adjust("test").await);
    }

    #[tokio::test]
    async fn test_rate_limiter_reset() {
        let limiter = DynamicRateLimiter::new(10.0, 1.0, 10.0);

        limiter.record_failure("test").await;
        limiter.record_failure("test").await;
        limiter.record_failure("test").await;

        limiter.reset("test");

        let rate = limiter.get_failure_rate("test").await;
        assert_eq!(rate, 0.0);
    }

    #[tokio::test]
    async fn test_acquire_multiple_targets() {
        let limiter = TokenBucketRateLimiter::new(10.0);

        // 不同目标应该独立计数
        for i in 0..20 {
            let target = format!("target-{}", i % 5);
            assert!(limiter.acquire(&target).await.is_ok());
        }
    }
}
