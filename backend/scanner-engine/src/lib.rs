pub mod engine;
pub mod worker;
pub mod resource_control;
pub mod error;
pub mod traits;
pub mod target;
pub mod rate_limiter;
pub mod result;
pub mod detectors;
pub mod rules;

pub use crate::engine::{ScanStatus, ScanProgress, ScannerEngine};
pub use crate::error::{Result, ScannerError};
pub use crate::traits::{Detector, RateLimiter, TargetValidator, ResultExporter, ScannerConfig, VulnerabilitySeverity};
pub use crate::target::{Target, TargetType, TargetManager, DefaultTargetValidator};
pub use crate::rate_limiter::{TokenBucketRateLimiter, DynamicRateLimiter, DynamicRateLimiterConfig};
pub use crate::result::{Vulnerability, VulnerabilityResult, ResultCollector, ScanSummary, DefaultResultExporter};
pub use crate::detectors::{SqlInjectionDetector, XssDetector, SensitiveFileDetector, PortScanner, HttpClient, RequestAuditLog, TechFingerprint, FalsePositiveFilter};
pub use crate::rules::{ScanRule, RuleConfig, DetectorConfig, RuleManager};
