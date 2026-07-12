use async_trait::async_trait;
use reqwest::{Client, Url};
use shared_lib::models::{Vulnerability, VulnerabilitySeverity};
use shared_lib::errors::AppError;

use crate::base::{ScanContext, ScanPlugin, ScanResult};

pub struct SqlInjectionScanner {
    client: Client,
    payloads: Vec<String>,
    error_patterns: Vec<regex::Regex>,
}

impl SqlInjectionScanner {
    pub fn new() -> Self {
        SqlInjectionScanner {
            client: Client::new(),
            payloads: vec![
                "' OR '1'='1".to_string(),
                "' OR 1=1--".to_string(),
                "' UNION SELECT 1,2,3--".to_string(),
                "' AND SLEEP(5)--".to_string(),
                "\" OR \"1\"=\"1".to_string(),
                "') OR ('1'='1".to_string(),
                "1'; DROP TABLE users--".to_string(),
                "'; INSERT INTO users VALUES(1,'test','test')--".to_string(),
            ],
            error_patterns: vec![
                regex::Regex::new(r"SQL syntax").unwrap(),
                regex::Regex::new(r"MySQL syntax").unwrap(),
                regex::Regex::new(r"PostgreSQL").unwrap(),
                regex::Regex::new(r"Oracle error").unwrap(),
                regex::Regex::new(r"Microsoft SQL Server").unwrap(),
                regex::Regex::new(r"database error").unwrap(),
                regex::Regex::new(r"ODBC").unwrap(),
                regex::Regex::new(r"SQLException").unwrap(),
            ],
        }
    }

    async fn test_payload(&self, url: &Url, payload: &str) -> Result<bool, AppError> {
        let test_url = url.join(&format!("?id={}", urlencoding::encode(payload))).map_err(|e| AppError::InvalidRequest(e.to_string()))?;
        
        let response = self.client.get(test_url)
            .timeout(std::time::Duration::from_secs(15))
            .send()
            .await
            .map_err(|e| AppError::ScanEngineError(format!("Request failed: {}", e)))?;
        
        let status = response.status();
        let body = response.text()
            .await
            .map_err(|e| AppError::ScanEngineError(format!("Failed to read response: {}", e)))?;
        
        let has_error = self.error_patterns.iter().any(|pattern| pattern.is_match(&body));
        let has_unexpected_response = status.is_server_error();
        
        Ok(has_error || has_unexpected_response)
    }
}

#[async_trait]
impl ScanPlugin for SqlInjectionScanner {
    fn name(&self) -> &str { "sql-injection-scanner" }
    
    fn description(&self) -> &str { "Detects SQL Injection vulnerabilities" }
    
    fn severity(&self) -> VulnerabilitySeverity { VulnerabilitySeverity::Critical }
    
    fn supported_scan_types(&self) -> Vec<&str> { vec!["full", "quick", "custom"] }
    
    async fn scan(&self, context: &ScanContext) -> Result<ScanResult, AppError> {
        let mut vulnerabilities = Vec::new();
        let mut scanned_urls = Vec::new();
        let mut errors = Vec::new();

        for payload in &self.payloads {
            match self.test_payload(&context.target_url, payload).await {
                Ok(true) => {
                    let vuln = Vulnerability {
                        id: uuid::Uuid::new_v4().to_string(),
                        task_id: context.task_id.clone(),
                        target_id: context.target_id.clone(),
                        plugin_name: self.name().to_string(),
                        severity: self.severity(),
                        title: "SQL Injection".to_string(),
                        description: format!("SQL Injection vulnerability detected with payload: {}", payload),
                        payload: Some(payload.clone()),
                        proof: None,
                        remediation: "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.".to_string(),
                        cve: None,
                        cvss_score: Some(8.8),
                        created_at: chrono::Utc::now(),
                    };
                    vulnerabilities.push(vuln);
                }
                Ok(false) => {}
                Err(e) => {
                    errors.push(format!("Failed to test payload '{}': {}", payload, e));
                }
            }
            scanned_urls.push(context.target_url.to_string());
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
    async fn test_sql_injection_scanner() {
        let scanner = SqlInjectionScanner::new();
        let context = ScanContext {
            target_url: Url::parse("http://example.com").unwrap(),
            task_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
            timeout: 15,
            max_requests: 100,
            headers: Vec::new(),
        };

        let result = scanner.scan(&context).await;
        assert!(result.is_ok());
    }
}
