use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use shared_lib::models::{Vulnerability, VulnerabilitySeverity};
use shared_lib::errors::AppError;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanContext {
    pub target_url: Url,
    pub task_id: String,
    pub target_id: String,
    pub timeout: u64,
    pub max_requests: usize,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub vulnerabilities: Vec<Vulnerability>,
    pub scanned_urls: Vec<String>,
    pub errors: Vec<String>,
}

#[async_trait]
pub trait ScanPlugin: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn severity(&self) -> VulnerabilitySeverity;
    fn supported_scan_types(&self) -> Vec<&str>;

    async fn scan(&self, context: &ScanContext) -> Result<ScanResult, AppError>;

    fn default_enabled(&self) -> bool {
        true
    }

    fn version(&self) -> &str {
        "1.0.0"
    }
}

pub struct PluginMetadata {
    pub name: String,
    pub description: String,
    pub severity: VulnerabilitySeverity,
    pub version: String,
    pub default_enabled: bool,
    pub supported_scan_types: Vec<String>,
}

impl<T: ScanPlugin> From<&T> for PluginMetadata {
    fn from(plugin: &T) -> Self {
        PluginMetadata {
            name: plugin.name().to_string(),
            description: plugin.description().to_string(),
            severity: plugin.severity(),
            version: plugin.version().to_string(),
            default_enabled: plugin.default_enabled(),
            supported_scan_types: plugin.supported_scan_types().iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl From<&dyn ScanPlugin> for PluginMetadata {
    fn from(plugin: &dyn ScanPlugin) -> Self {
        PluginMetadata {
            name: plugin.name().to_string(),
            description: plugin.description().to_string(),
            severity: plugin.severity(),
            version: plugin.version().to_string(),
            default_enabled: plugin.default_enabled(),
            supported_scan_types: plugin.supported_scan_types().iter().map(|s| s.to_string()).collect(),
        }
    }
}
