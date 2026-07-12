use async_trait::async_trait;
use reqwest::{Client, Url, StatusCode};
use shared_lib::models::{Vulnerability, VulnerabilitySeverity};
use shared_lib::errors::AppError;

use crate::base::{ScanContext, ScanPlugin, ScanResult};

pub struct DirectoryScanner {
    client: Client,
    directories: Vec<String>,
    files: Vec<String>,
}

impl DirectoryScanner {
    pub fn new() -> Self {
        DirectoryScanner {
            client: Client::new(),
            directories: vec![
                "/admin/".to_string(),
                "/admin/login/".to_string(),
                "/manager/".to_string(),
                "/manager/html/".to_string(),
                "/wp-admin/".to_string(),
                "/wp-login/".to_string(),
                "/phpmyadmin/".to_string(),
                "/phpMyAdmin/".to_string(),
                "/mysql/".to_string(),
                "/webmin/".to_string(),
                "/cpanel/".to_string(),
                "/.git/".to_string(),
                "/.svn/".to_string(),
                "/backup/".to_string(),
                "/backups/".to_string(),
                "/config/".to_string(),
                "/etc/".to_string(),
                "/logs/".to_string(),
                "/tmp/".to_string(),
                "/uploads/".to_string(),
                "/download/".to_string(),
                "/downloads/".to_string(),
                "/private/".to_string(),
                "/secret/".to_string(),
                "/data/".to_string(),
                "/dump/".to_string(),
                "/sql/".to_string(),
                "/database/".to_string(),
                "/db/".to_string(),
            ],
            files: vec![
                "/.env".to_string(),
                "/.git/config".to_string(),
                "/.svn/entries".to_string(),
                "/config.php".to_string(),
                "/database.php".to_string(),
                "/wp-config.php".to_string(),
                "/.htaccess".to_string(),
                "/robots.txt".to_string(),
                "/sitemap.xml".to_string(),
                "/admin/config.php".to_string(),
                "/config/database.php".to_string(),
                "/backup.sql".to_string(),
                "/dump.sql".to_string(),
                "/db.sql".to_string(),
                "/data.sql".to_string(),
                "/passwords.txt".to_string(),
                "/secrets.txt".to_string(),
                "/credentials.txt".to_string(),
                "/keys.txt".to_string(),
            ],
        }
    }

    async fn test_path(&self, base_url: &Url, path: &str) -> Result<bool, AppError> {
        let test_url = base_url.join(path).map_err(|e| AppError::InvalidRequest(e.to_string()))?;
        
        let response = self.client.get(test_url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| AppError::ScanEngineError(format!("Request failed: {}", e)))?;
        
        Ok(response.status() == StatusCode::OK || response.status() == StatusCode::FORBIDDEN)
    }
}

#[async_trait]
impl ScanPlugin for DirectoryScanner {
    fn name(&self) -> &str { "directory-scanner" }
    
    fn description(&self) -> &str { "Detects sensitive directories and files" }
    
    fn severity(&self) -> VulnerabilitySeverity { VulnerabilitySeverity::Medium }
    
    fn supported_scan_types(&self) -> Vec<&str> { vec!["full", "quick", "custom"] }
    
    async fn scan(&self, context: &ScanContext) -> Result<ScanResult, AppError> {
        let mut vulnerabilities = Vec::new();
        let mut scanned_urls = Vec::new();
        let mut errors = Vec::new();

        for directory in &self.directories {
            match self.test_path(&context.target_url, directory).await {
                Ok(true) => {
                    let vuln = Vulnerability {
                        id: uuid::Uuid::new_v4().to_string(),
                        task_id: context.task_id.clone(),
                        target_id: context.target_id.clone(),
                        plugin_name: self.name().to_string(),
                        severity: self.severity(),
                        title: "Sensitive Directory Found".to_string(),
                        description: format!("Potentially sensitive directory exposed: {}", directory),
                        payload: None,
                        proof: Some(format!("URL: {}{}", context.target_url, directory)),
                        remediation: "Restrict access to sensitive directories using proper authentication or .htaccess rules.".to_string(),
                        cve: None,
                        cvss_score: Some(5.0),
                        created_at: chrono::Utc::now(),
                    };
                    vulnerabilities.push(vuln);
                }
                Ok(false) => {}
                Err(e) => {
                    errors.push(format!("Failed to test directory '{}': {}", directory, e));
                }
            }
            scanned_urls.push(format!("{}{}", context.target_url, directory));
        }

        for file in &self.files {
            match self.test_path(&context.target_url, file).await {
                Ok(true) => {
                    let vuln = Vulnerability {
                        id: uuid::Uuid::new_v4().to_string(),
                        task_id: context.task_id.clone(),
                        target_id: context.target_id.clone(),
                        plugin_name: self.name().to_string(),
                        severity: VulnerabilitySeverity::High,
                        title: "Sensitive File Found".to_string(),
                        description: format!("Potentially sensitive file exposed: {}", file),
                        payload: None,
                        proof: Some(format!("URL: {}{}", context.target_url, file)),
                        remediation: "Remove or restrict access to sensitive configuration files.".to_string(),
                        cve: None,
                        cvss_score: Some(7.5),
                        created_at: chrono::Utc::now(),
                    };
                    vulnerabilities.push(vuln);
                }
                Ok(false) => {}
                Err(e) => {
                    errors.push(format!("Failed to test file '{}': {}", file, e));
                }
            }
            scanned_urls.push(format!("{}{}", context.target_url, file));
        }

        Ok(ScanResult {
            vulnerabilities,
            scanned_urls,
            errors,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::ScanContext;
    use url::Url;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_directory_scanner() {
        let scanner = DirectoryScanner::new();
        let context = ScanContext {
            target_url: Url::parse("http://example.com").unwrap(),
            task_id: Uuid::new_v4().to_string(),
            target_id: Uuid::new_v4().to_string(),
            timeout: 10,
            max_requests: 100,
            headers: Vec::new(),
        };

        let result = scanner.scan(&context).await;
        assert!(result.is_ok());
    }
}
