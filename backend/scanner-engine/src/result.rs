use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::error::{Result, ScannerError};
use crate::traits::{ResultExporter, VulnerabilitySeverity};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub target_id: String,
    pub detector_name: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub payload: Option<String>,
    pub proof: Option<String>,
    pub remediation: String,
    pub cve: Option<String>,
    pub cvss_score: Option<f32>,
    pub cvss_vector: Option<String>,
    pub timestamp: String,
    pub request: Option<String>,
    pub response: Option<String>,
}

impl Vulnerability {
    pub fn new(
        detector_name: &str,
        severity: VulnerabilitySeverity,
        title: &str,
        description: &str,
        remediation: &str,
    ) -> Self {
        Vulnerability {
            id: uuid::Uuid::new_v4().to_string(),
            target_id: String::new(),
            detector_name: detector_name.to_string(),
            severity: severity.to_string().to_string(),
            title: title.to_string(),
            description: description.to_string(),
            payload: None,
            proof: None,
            remediation: remediation.to_string(),
            cve: None,
            cvss_score: None,
            cvss_vector: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            request: None,
            response: None,
        }
    }
    
    pub fn with_target_id(mut self, target_id: &str) -> Self {
        self.target_id = target_id.to_string();
        self
    }
    
    pub fn with_payload(mut self, payload: &str) -> Self {
        self.payload = Some(payload.to_string());
        self
    }
    
    pub fn with_proof(mut self, proof: &str) -> Self {
        self.proof = Some(proof.to_string());
        self
    }
    
    pub fn with_cve(mut self, cve: &str) -> Self {
        self.cve = Some(cve.to_string());
        self
    }
    
    pub fn with_cvss(mut self, score: f32, vector: &str) -> Self {
        self.cvss_score = Some(score);
        self.cvss_vector = Some(vector.to_string());
        self
    }
    
    pub fn with_request(mut self, request: &str) -> Self {
        self.request = Some(request.to_string());
        self
    }
    
    pub fn with_response(mut self, response: &str) -> Self {
        self.response = Some(response.to_string());
        self
    }
    
    pub fn calculate_cvss_score(&mut self) -> f32 {
        if let Some(vector) = &self.cvss_vector {
            match self.parse_cvss_vector(vector) {
                Ok(score) => {
                    self.cvss_score = Some(score);
                    score
                }
                Err(e) => {
                    tracing::warn!("Failed to parse CVSS vector {}: {}", vector, e);
                    self.default_cvss_score()
                }
            }
        } else {
            self.default_cvss_score()
        }
    }
    
    fn default_cvss_score(&self) -> f32 {
        match VulnerabilitySeverity::from_string(&self.severity) {
            Some(VulnerabilitySeverity::Critical) => 9.5,
            Some(VulnerabilitySeverity::High) => 7.5,
            Some(VulnerabilitySeverity::Medium) => 5.0,
            Some(VulnerabilitySeverity::Low) => 2.5,
            Some(VulnerabilitySeverity::Info) => 0.0,
            None => 5.0,
        }
    }
    
    fn parse_cvss_vector(&self, vector: &str) -> Result<f32> {
        let parts: Vec<&str> = vector.split('/').collect();
        
        let mut exploitability: f64 = 0.0;
        let mut impact: f64 = 0.0;
        
        for part in parts {
            if part.starts_with("AV:") {
                match part.split(':').nth(1) {
                    Some("N") => exploitability += 0.85,
                    Some("A") => exploitability += 0.62,
                    Some("L") => exploitability += 0.55,
                    Some("P") => exploitability += 0.20,
                    _ => {}
                }
            } else if part.starts_with("AC:") {
                match part.split(':').nth(1) {
                    Some("L") => exploitability += 0.77,
                    Some("H") => exploitability += 0.44,
                    _ => {}
                }
            } else if part.starts_with("PR:") {
                match part.split(':').nth(1) {
                    Some("N") => exploitability += 0.85,
                    Some("L") => exploitability += 0.62,
                    Some("H") => exploitability += 0.27,
                    _ => {}
                }
            } else if part.starts_with("UI:") {
                match part.split(':').nth(1) {
                    Some("N") => exploitability += 0.85,
                    Some("R") => exploitability += 0.62,
                    _ => {}
                }
            } else if part.starts_with("S:") {
                match part.split(':').nth(1) {
                    Some("C") => impact += 1.0,
                    Some("U") => impact += 0.5,
                    _ => {}
                }
            }
        }
        
        exploitability = (exploitability / 4.0).powf(0.85);
        impact = (impact / 3.0).powf(0.666);
        
        let base_score = 7.52 * (exploitability - 0.029) - 3.25 * (exploitability - 0.02).powf(15.0);
        let base_score = (base_score.max(0.0) * impact).min(10.0);
        
        Ok((base_score.round() / 10.0 * 10.0) as f32)
    }
    
    pub fn fingerprint(&self) -> String {
        format!(
            "{}_{}_{}_{}",
            self.target_id,
            self.detector_name,
            self.title,
            self.payload.as_deref().unwrap_or("")
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityResult {
    pub target_id: String,
    pub vulnerabilities: Vec<Vulnerability>,
    pub scan_started: String,
    pub scan_completed: String,
}

impl VulnerabilityResult {
    pub fn new(target_id: String) -> Self {
        VulnerabilityResult {
            target_id,
            vulnerabilities: Vec::new(),
            scan_started: chrono::Utc::now().to_rfc3339(),
            scan_completed: String::new(),
        }
    }
    
    pub fn add_vulnerability(&mut self, vulnerability: Vulnerability) {
        self.vulnerabilities.push(vulnerability);
    }
    
    pub fn complete(&mut self) {
        self.scan_completed = chrono::Utc::now().to_rfc3339();
    }
    
    pub fn count_by_severity(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for vuln in &self.vulnerabilities {
            *counts.entry(vuln.severity.clone()).or_default() += 1;
        }
        counts
    }
    
    pub fn has_critical(&self) -> bool {
        self.vulnerabilities.iter().any(|v| v.severity == "critical")
    }
}

pub struct ResultCollector {
    results: Arc<tokio::sync::RwLock<Vec<VulnerabilityResult>>>,
    seen_fingerprints: Arc<tokio::sync::RwLock<HashSet<String>>>,
}

impl Default for ResultCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ResultCollector {
    pub fn new() -> Self {
        ResultCollector {
            results: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            seen_fingerprints: Arc::new(tokio::sync::RwLock::new(HashSet::new())),
        }
    }
    
    pub async fn add_result(&self, result: VulnerabilityResult) {
        let mut results = self.results.write().await;
        results.push(result);
    }
    
    pub async fn add_results(&self, results: Vec<VulnerabilityResult>) {
        let mut results_lock = self.results.write().await;
        results_lock.extend(results);
    }
    
    pub async fn get_results(&self) -> Vec<VulnerabilityResult> {
        let results = self.results.read().await;
        results.clone()
    }
    
    pub async fn get_all_vulnerabilities(&self) -> Vec<Vulnerability> {
        let results = self.results.read().await;
        results.iter()
            .flat_map(|r| r.vulnerabilities.clone())
            .collect()
    }
    
    pub async fn deduplicate(&self) -> usize {
        let mut results = self.results.write().await;
        let mut seen = self.seen_fingerprints.write().await;
        
        let mut removed = 0;
        
        for result in results.iter_mut() {
            let original_len = result.vulnerabilities.len();
            result.vulnerabilities.retain(|v| {
                let fp = v.fingerprint();
                if seen.contains(&fp) {
                    true
                } else {
                    seen.insert(fp);
                    false
                }
            });
            removed += original_len - result.vulnerabilities.len();
        }
        
        removed
    }
    
    pub async fn filter_by_severity(&self, severity: &str) -> Vec<Vulnerability> {
        let results = self.results.read().await;
        results.iter()
            .flat_map(|r| r.vulnerabilities.clone())
            .filter(|v| v.severity.to_lowercase() == severity.to_lowercase())
            .collect()
    }
    
    pub async fn filter_by_detector(&self, detector_name: &str) -> Vec<Vulnerability> {
        let results = self.results.read().await;
        results.iter()
            .flat_map(|r| r.vulnerabilities.clone())
            .filter(|v| v.detector_name == detector_name)
            .collect()
    }
    
    pub async fn get_summary(&self) -> ScanSummary {
        let results = self.results.read().await;
        let all_vulnerabilities: Vec<&Vulnerability> = results.iter()
            .flat_map(|r| r.vulnerabilities.iter())
            .collect();
        
        let mut severity_counts = HashMap::new();
        let mut detector_counts = HashMap::new();
        let mut total_cvss = 0.0;
        let mut cvss_count = 0;
        
        for vuln in &all_vulnerabilities {
            *severity_counts.entry(vuln.severity.clone()).or_default() += 1;
            *detector_counts.entry(vuln.detector_name.clone()).or_default() += 1;
            
            if let Some(score) = vuln.cvss_score {
                total_cvss += score;
                cvss_count += 1;
            }
        }
        
        ScanSummary {
            total_targets: results.len(),
            total_vulnerabilities: all_vulnerabilities.len(),
            severity_counts,
            detector_counts,
            avg_cvss_score: if cvss_count > 0 { (total_cvss / cvss_count as f32) as f64 } else { 0.0 },
            has_critical: all_vulnerabilities.iter().any(|v| v.severity == "critical"),
        }
    }
    
    pub async fn clear(&self) {
        let mut results = self.results.write().await;
        results.clear();
        
        let mut seen = self.seen_fingerprints.write().await;
        seen.clear();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub total_targets: usize,
    pub total_vulnerabilities: usize,
    pub severity_counts: HashMap<String, usize>,
    pub detector_counts: HashMap<String, usize>,
    pub avg_cvss_score: f64,
    pub has_critical: bool,
}

#[derive(Debug, Clone)]
pub struct DefaultResultExporter;

#[async_trait]
impl ResultExporter for DefaultResultExporter {
    async fn export_json(&self, vulnerabilities: &[Vulnerability]) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(vulnerabilities)
            .map_err(|e| ScannerError::Export(format!("Failed to export JSON: {}", e)))
    }
    
    async fn export_csv(&self, vulnerabilities: &[Vulnerability]) -> Result<Vec<u8>> {
        let mut wtr = csv::Writer::from_writer(Vec::new());
        
        wtr.write_record([
            "ID", "Target ID", "Detector", "Severity", "Title", 
            "Description", "Payload", "Proof", "Remediation", 
            "CVE", "CVSS Score", "Timestamp"
        ]).map_err(|e| ScannerError::Export(format!("Failed to write CSV header: {}", e)))?;
        
        for vuln in vulnerabilities {
            wtr.write_record([
                &vuln.id,
                &vuln.target_id,
                &vuln.detector_name,
                &vuln.severity,
                &vuln.title,
                &vuln.description,
                vuln.payload.as_deref().unwrap_or(""),
                vuln.proof.as_deref().unwrap_or(""),
                &vuln.remediation,
                vuln.cve.as_deref().unwrap_or(""),
                vuln.cvss_score.map(|s| s.to_string()).as_deref().unwrap_or(""),
                &vuln.timestamp,
            ]).map_err(|e| ScannerError::Export(format!("Failed to write CSV record: {}", e)))?;
        }
        
        wtr.into_inner()
            .map_err(|e| ScannerError::Export(format!("Failed to finish CSV: {}", e)))
    }
    
    async fn export_html(&self, vulnerabilities: &[Vulnerability]) -> Result<Vec<u8>> {
        let html = format!(
            r#"<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .critical {{ background-color: #ffebee; }}
        .high {{ background-color: #fff3e0; }}
        .medium {{ background-color: #fffde7; }}
        .low {{ background-color: #e3f2fd; }}
        .info {{ background-color: #f5f5f5; }}
    </style>
</head>
<body>
    <h1>Vulnerability Scan Report</h1>
    <p>Generated: {}</p>
    <p>Total vulnerabilities: {}</p>
    <table>
        <tr>
            <th>ID</th>
            <th>Target</th>
            <th>Detector</th>
            <th>Severity</th>
            <th>Title</th>
            <th>Description</th>
            <th>Remediation</th>
            <th>CVSS</th>
        </tr>
        {}
    </table>
</body>
</html>"#,
            chrono::Utc::now().to_rfc3339(),
            vulnerabilities.len(),
            vulnerabilities.iter()
                .map(|v| format!(
                    r#"<tr class="{}">
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                        <td>{}</td>
                    </tr>"#,
                    v.severity.to_lowercase(),
                    v.id,
                    v.target_id,
                    v.detector_name,
                    v.severity,
                    v.title,
                    v.description,
                    v.remediation,
                    v.cvss_score.map(|s| s.to_string()).unwrap_or_default()
                ))
                .collect::<Vec<_>>()
                .join("\n")
        );
        
        Ok(html.into_bytes())
    }
}
