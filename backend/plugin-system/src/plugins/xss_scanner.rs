use async_trait::async_trait;
use reqwest::{Client, Url};
use shared_lib::models::{Vulnerability, VulnerabilitySeverity};
use shared_lib::errors::AppError;

use crate::base::{ScanContext, ScanPlugin, ScanResult};

pub struct XssScanner {
    client: Client,
    payloads: Vec<String>,
}

impl XssScanner {
    pub fn new() -> Self {
        XssScanner {
            client: Client::new(),
            payloads: vec![
                "<script>alert(1)</script>".to_string(),
                "<img src=x onerror=alert(1)>".to_string(),
                "'><script>alert(1)</script>".to_string(),
                "<svg/onload=alert(1)>".to_string(),
                "\";alert(1);//".to_string(),
                "<body onload=alert(1)>".to_string(),
                "<iframe onload=alert(1)>".to_string(),
                "<input onfocus=alert(1) autofocus>".to_string(),
                "<marquee onstart=alert(1)>".to_string(),
                "<details/open/ontoggle=alert(1)>".to_string(),
            ],
        }
    }

    async fn test_payload(&self, url: &Url, payload: &str) -> Result<bool, AppError> {
        let test_url = url.join(&format!("?test={}", urlencoding::encode(payload))).map_err(|e| AppError::InvalidRequest(e.to_string()))?;
        
        let response = self.client.get(test_url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| AppError::ScanEngineError(format!("Request failed: {}", e)))?;
        
        let body = response.text()
            .await
            .map_err(|e| AppError::ScanEngineError(format!("Failed to read response: {}", e)))?;
        
        Ok(body.contains(payload))
    }
}

#[async_trait]
impl ScanPlugin for XssScanner {
    fn name(&self) -> &str { "xss-scanner" }
    
    fn description(&self) -> &str { "Detects Cross-Site Scripting (XSS) vulnerabilities" }
    
    fn severity(&self) -> VulnerabilitySeverity { VulnerabilitySeverity::High }
    
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
                        title: "Cross-Site Scripting (XSS)".to_string(),
                        description: format!("XSS vulnerability detected with payload: {}", payload),
                        payload: Some(payload.clone()),
                        proof: None,
                        remediation: "Sanitize all user input before rendering in HTML context. Use proper output encoding.".to_string(),
                        cve: None,
                        cvss_score: Some(8.0),
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
    async fn test_xss_scanner() {
        let scanner = XssScanner::new();
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
