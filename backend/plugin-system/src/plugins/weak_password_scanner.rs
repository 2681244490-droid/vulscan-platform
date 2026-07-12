use async_trait::async_trait;
use reqwest::{Client, Url, StatusCode};
use shared_lib::models::{Vulnerability, VulnerabilitySeverity};
use shared_lib::errors::AppError;

use crate::base::{ScanContext, ScanPlugin, ScanResult};

pub struct WeakPasswordScanner {
    client: Client,
    common_usernames: Vec<String>,
    common_passwords: Vec<String>,
    login_endpoints: Vec<String>,
}

impl WeakPasswordScanner {
    pub fn new() -> Self {
        WeakPasswordScanner {
            client: Client::new(),
            common_usernames: vec![
                "admin".to_string(), "root".to_string(), "user".to_string(), "test".to_string(), "guest".to_string(), "admin1".to_string(), "admin2".to_string(),
                "administrator".to_string(), "superuser".to_string(), "manager".to_string(), "owner".to_string(), "admin@admin.com".to_string(),
                "test@test.com".to_string(), "user@user.com".to_string(), "root@localhost".to_string(),
            ],
            common_passwords: vec![
                "password".to_string(), "123456".to_string(), "12345678".to_string(), "qwerty".to_string(), "abc123".to_string(), "monkey".to_string(),
                "1234567".to_string(), "letmein".to_string(), "trustno1".to_string(), "dragon".to_string(), "baseball".to_string(), "iloveyou".to_string(),
                "master".to_string(), "sunshine".to_string(), "ashley".to_string(), "bailey".to_string(), "shadow".to_string(), "123123".to_string(),
                "654321".to_string(), "superman".to_string(), "qazwsx".to_string(), "michael".to_string(), "football".to_string(), "password1".to_string(),
                "admin".to_string(), "welcome".to_string(), "welcome1".to_string(), "welcome123".to_string(), "admin123".to_string(), "root".to_string(),
                "toor".to_string(), "password123".to_string(), "123456789".to_string(), "1234567890".to_string(), "000000".to_string(),
            ],
            login_endpoints: vec![
                "/login".to_string(), "/signin".to_string(), "/auth/login".to_string(), "/account/login".to_string(),
                "/admin/login".to_string(), "/user/login".to_string(), "/api/login".to_string(), "/api/auth/login".to_string(),
            ],
        }
    }

    async fn test_login(&self, url: &Url, username: &str, password: &str) -> Result<bool, AppError> {
        let response = self.client.post(url.clone())
            .form(&[("username", username), ("password", password)])
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| AppError::ScanEngineError(format!("Request failed: {}", e)))?;

        Ok(response.status() == StatusCode::OK || response.status() == StatusCode::FOUND)
    }
}

#[async_trait]
impl ScanPlugin for WeakPasswordScanner {
    fn name(&self) -> &str { "weak-password-scanner" }
    
    fn description(&self) -> &str { "Detects weak password authentication" }
    
    fn severity(&self) -> VulnerabilitySeverity { VulnerabilitySeverity::Critical }
    
    fn supported_scan_types(&self) -> Vec<&str> { vec!["full", "custom"] }
    
    async fn scan(&self, context: &ScanContext) -> Result<ScanResult, AppError> {
        let mut vulnerabilities = Vec::new();
        let mut scanned_urls = Vec::new();
        let mut errors = Vec::new();

        for endpoint in &self.login_endpoints {
            if let Ok(login_url) = context.target_url.join(endpoint) {
                for username in &self.common_usernames {
                    for password in &self.common_passwords {
                        match self.test_login(&login_url, username, password).await {
                            Ok(true) => {
                                let vuln = Vulnerability {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    task_id: context.task_id.clone(),
                                    target_id: context.target_id.clone(),
                                    plugin_name: self.name().to_string(),
                                    severity: self.severity(),
                                    title: "Weak Password Found".to_string(),
                                    description: format!("Weak credentials found: username='{}', password='{}'", username, password),
                                    payload: Some(format!("username={}&password={}", username, password)),
                                    proof: Some(format!("URL: {}", login_url)),
                                    remediation: "Enforce strong password policies. Implement account lockout after failed attempts.".to_string(),
                                    cve: None,
                                    cvss_score: Some(9.8),
                                    created_at: chrono::Utc::now(),
                                };
                                vulnerabilities.push(vuln);
                            }
                            Ok(false) => {}
                            Err(e) => {
                                errors.push(format!("Failed to test login '{}:{}' at {}: {}", username, password, endpoint, e));
                            }
                        }
                        scanned_urls.push(login_url.to_string());
                        
                        if vulnerabilities.len() >= 5 {
                            break;
                        }
                    }
                    if vulnerabilities.len() >= 5 {
                        break;
                    }
                }
            }
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
    async fn test_weak_password_scanner() {
        let scanner = WeakPasswordScanner::new();
        let context = ScanContext {
            target_url: Url::parse("http://example.com").unwrap(),
            task_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            timeout: 10,
            max_requests: 100,
            headers: Vec::new(),
        };

        let result = scanner.scan(&context).await;
        assert!(result.is_ok());
    }
}
