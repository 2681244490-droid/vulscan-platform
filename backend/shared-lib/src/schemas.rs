use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub user: UserResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(length(min = 3, max = 64))]
    pub username: String,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8, max = 128))]
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub role: String,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CreateTargetRequest {
    #[validate(length(min = 1, max = 256))]
    pub name: String,
    #[validate(url)]
    pub url: String,
    pub description: Option<String>,
    pub scan_frequency: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportVulnerabilitiesRequest {
    pub format: String,
    pub ids: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateTargetRequest {
    pub name: Option<String>,
    pub url: Option<String>,
    pub description: Option<String>,
    pub status: Option<String>,
    pub scan_frequency: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetResponse {
    pub id: String,
    pub name: String,
    pub url: String,
    pub description: Option<String>,
    pub status: String,
    pub scan_frequency: Option<String>,
    pub last_scan_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct CreateScanTaskRequest {
    pub target_id: String,
    pub scan_type: Option<String>,
    pub priority: Option<String>,
    pub plugins: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateScanTaskRequest {
    pub status: Option<String>,
    pub priority: Option<String>,
    pub progress: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanTaskResponse {
    pub id: String,
    pub name: String,
    pub target_id: String,
    pub target_ids: Vec<String>,
    pub target_name: String,
    pub target_count: i32,
    pub status: String,
    pub scan_type: String,
    pub priority: String,
    pub progress: i32,
    pub concurrency: i32,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityResponse {
    pub id: String,
    pub task_id: String,
    pub task_name: Option<String>,
    pub target_id: String,
    pub target_url: Option<String>,
    pub plugin_name: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub payload: Option<String>,
    pub proof: Option<String>,
    pub remediation: String,
    pub cve: Option<String>,
    pub cvss_score: Option<f64>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportResponse {
    pub id: String,
    pub task_id: String,
    pub task_name: String,
    pub status: String,
    pub summary: serde_json::Value,
    pub template: Option<String>,
    pub generated_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub page: i32,
    pub page_size: i32,
    pub total: i64,
    pub total_pages: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResultMessage {
    pub task_id: String,
    pub vulnerabilities: Vec<VulnerabilityResponse>,
    pub progress: i32,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateReportRequest {
    pub task_id: String,
    pub template: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateReportRequest {
    pub status: Option<String>,
    pub summary: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateVulnerabilityStatusRequest {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchCreateTargetRequest {
    pub targets: Vec<CreateTargetRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityFilter {
    pub severity: Option<String>,
    pub plugin_name: Option<String>,
    pub task_id: Option<String>,
    pub target_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    #[validate(length(min = 8, max = 128))]
    pub old_password: String,
    #[validate(length(min = 8, max = 128))]
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserListQuery {
    pub page: Option<i32>,
    pub page_size: Option<i32>,
    pub role: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardStatsResponse {
    pub today_scans: i64,
    pub high_risk_count: i64,
    pub pending_fix_count: i64,
    pub total_targets: i64,
    pub scan_trend: Vec<TrendDataPoint>,
    pub vulnerability_distribution: Vec<DistributionItem>,
    pub severity_distribution: Vec<DistributionItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendDataPoint {
    pub date: String,
    pub count: i64,
    pub high_risk: i64,
    pub medium_risk: i64,
    pub low_risk: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionItem {
    pub name: String,
    pub value: i64,
}
