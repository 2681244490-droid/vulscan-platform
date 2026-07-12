use async_trait::async_trait;
use std::fmt::Debug;

use crate::error::Result;
use crate::target::Target;
use crate::result::Vulnerability;

#[async_trait]
pub trait Detector: Send + Sync + Debug + 'static {
    fn name(&self) -> &str;
    
    fn severity(&self) -> VulnerabilitySeverity;
    
    fn description(&self) -> &str;
    
    async fn scan(&self, target: &Target) -> Result<Vec<Vulnerability>>;
    
    fn enabled(&self) -> bool {
        true
    }
    
    fn priority(&self) -> u32 {
        100
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VulnerabilitySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl VulnerabilitySeverity {
    pub fn to_string(&self) -> &str {
        match self {
            VulnerabilitySeverity::Critical => "critical",
            VulnerabilitySeverity::High => "high",
            VulnerabilitySeverity::Medium => "medium",
            VulnerabilitySeverity::Low => "low",
            VulnerabilitySeverity::Info => "info",
        }
    }
    
    pub fn from_string(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "critical" => Some(VulnerabilitySeverity::Critical),
            "high" => Some(VulnerabilitySeverity::High),
            "medium" => Some(VulnerabilitySeverity::Medium),
            "low" => Some(VulnerabilitySeverity::Low),
            "info" => Some(VulnerabilitySeverity::Info),
            _ => None,
        }
    }
    
    pub fn cvss_range(&self) -> (f32, f32) {
        match self {
            VulnerabilitySeverity::Critical => (9.0, 10.0),
            VulnerabilitySeverity::High => (7.0, 8.9),
            VulnerabilitySeverity::Medium => (4.0, 6.9),
            VulnerabilitySeverity::Low => (0.1, 3.9),
            VulnerabilitySeverity::Info => (0.0, 0.0),
        }
    }
}

#[async_trait]
pub trait RateLimiter: Send + Sync + Debug {
    async fn acquire(&self, target: &str) -> Result<()>;
    
    fn set_rate_limit(&mut self, requests_per_second: f64);
    
    fn get_rate_limit(&self) -> f64;
    
    fn reset(&self, target: &str);
}

#[async_trait]
pub trait TargetValidator: Send + Sync + Debug {
    async fn validate(&self, target: &str) -> Result<Target>;
    
    async fn is_reachable(&self, target: &Target) -> Result<bool>;
    
    async fn is_authorized(&self, target: &Target) -> Result<bool>;
}

#[async_trait]
pub trait ResultExporter: Send + Sync + Debug {
    async fn export_json(&self, vulnerabilities: &[Vulnerability]) -> Result<Vec<u8>>;
    
    async fn export_csv(&self, vulnerabilities: &[Vulnerability]) -> Result<Vec<u8>>;
    
    async fn export_html(&self, vulnerabilities: &[Vulnerability]) -> Result<Vec<u8>>;
}

pub trait ScannerConfig: Send + Sync + Debug {
    fn get_concurrent_targets(&self) -> usize;
    
    fn get_requests_per_second(&self) -> f64;
    
    fn get_connection_timeout(&self) -> u64;
    
    fn get_response_timeout(&self) -> u64;
    
    fn get_max_retries(&self) -> u32;
    
    fn get_retry_delay_ms(&self) -> u64;
    
    fn get_rules_directory(&self) -> Option<&str>;
}
