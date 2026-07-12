use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use shared_lib::models::VulnerabilitySeverity;
use shared_lib::errors::AppError;

use crate::base::{PluginMetadata, ScanPlugin, ScanContext, ScanResult};

pub struct PluginRegistry {
    plugins: RwLock<HashMap<String, Arc<dyn ScanPlugin>>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        PluginRegistry {
            plugins: RwLock::new(HashMap::new()),
        }
    }

    pub fn register(&self, plugin: Box<dyn ScanPlugin>) {
        let name = plugin.name().to_string();
        self.plugins.write().unwrap().insert(name, Arc::from(plugin));
    }

    pub fn unregister(&self, name: &str) -> bool {
        self.plugins.write().unwrap().remove(name).is_some()
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn ScanPlugin>> {
        self.plugins.read().unwrap().get(name).cloned()
    }

    pub fn list(&self) -> Vec<PluginMetadata> {
        self.plugins.read().unwrap()
            .values()
            .map(|p| PluginMetadata::from(p.as_ref()))
            .collect()
    }

    pub fn list_by_severity(&self, severity: VulnerabilitySeverity) -> Vec<PluginMetadata> {
        self.plugins.read().unwrap()
            .values()
            .filter(|p| p.severity() == severity)
            .map(|p| PluginMetadata::from(p.as_ref()))
            .collect()
    }

    pub fn get_enabled(&self, scan_type: &str) -> Vec<Arc<dyn ScanPlugin>> {
        self.plugins.read().unwrap()
            .values()
            .filter(|p| p.default_enabled() && p.supported_scan_types().contains(&scan_type))
            .cloned()
            .collect()
    }

    pub async fn scan_with_plugins(
        &self,
        context: &ScanContext,
        plugin_names: Option<&[String]>,
    ) -> Result<Vec<ScanResult>, AppError> {
        let plugins = match plugin_names {
            Some(names) => names.iter()
                .filter_map(|name| self.get(name))
                .collect::<Vec<_>>(),
            None => self.get_enabled(&context.task_id.to_string()),
        };

        let mut results = Vec::new();
        for plugin in plugins {
            let result = plugin.scan(context).await?;
            results.push(result);
        }

        Ok(results)
    }

    pub fn count(&self) -> usize {
        self.plugins.read().unwrap().len()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::ScanPlugin;
    use shared_lib::models::VulnerabilitySeverity;
    use url::Url;
    use uuid::Uuid;

    struct TestPlugin;

    #[async_trait::async_trait]
    impl ScanPlugin for TestPlugin {
        fn name(&self) -> &str { "test-plugin" }
        fn description(&self) -> &str { "Test plugin" }
        fn severity(&self) -> VulnerabilitySeverity { VulnerabilitySeverity::Medium }
        fn supported_scan_types(&self) -> Vec<&str> { vec!["full", "quick"] }
        
        async fn scan(&self, _context: &ScanContext) -> Result<ScanResult, AppError> {
            Ok(ScanResult {
                vulnerabilities: Vec::new(),
                scanned_urls: Vec::new(),
                errors: Vec::new(),
            })
        }
    }

    #[test]
    fn test_register_and_list() {
        let registry = PluginRegistry::new();
        registry.register(Box::new(TestPlugin));
        
        assert_eq!(registry.count(), 1);
        
        let plugins = registry.list();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "test-plugin");
    }

    #[test]
    fn test_unregister() {
        let registry = PluginRegistry::new();
        registry.register(Box::new(TestPlugin));
        
        assert!(registry.unregister("test-plugin"));
        assert_eq!(registry.count(), 0);
    }
}
