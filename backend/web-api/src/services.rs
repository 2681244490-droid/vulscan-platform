use auth_service::rbac::RbacService;
use auth_service::service::AuthService;
use shared_lib::errors::AppError;
use shared_lib::models::Target;
use shared_lib::schemas::{
    CreateReportRequest, CreateScanTaskRequest, CreateTargetRequest, DashboardStatsResponse,
    DistributionItem, PaginatedResponse, ReportResponse, ScanTaskResponse, TargetResponse,
    TrendDataPoint, UpdateReportRequest, UpdateScanTaskRequest, UpdateTargetRequest,
    VulnerabilityFilter, VulnerabilityResponse,
};
use sqlx::PgPool;
use uuid::Uuid;

/// 轻量行映射结构体，用于接收 reports + scan_tasks JOIN 查询结果
#[derive(sqlx::FromRow)]
struct ReportJoinRow {
    id: String,
    task_id: String,
    status: String,
    summary: serde_json::Value,
    generated_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    task_name: String,
    template: Option<String>,
}

impl ReportJoinRow {
    fn into_response(self) -> ReportResponse {
        ReportResponse {
            id: self.id,
            task_id: self.task_id,
            task_name: self.task_name,
            status: self.status,
            summary: self.summary,
            template: self.template,
            generated_at: self.generated_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

/// 轻量行映射结构体，用于接收 scan_tasks + targets JOIN 查询结果
#[derive(sqlx::FromRow)]
struct ScanTaskJoinRow {
    id: String,
    target_id: String,
    status: String,
    scan_type: String,
    priority: String,
    progress: i32,
    started_at: Option<chrono::DateTime<chrono::Utc>>,
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    target_name: String,
}

impl ScanTaskJoinRow {
    fn into_response(self) -> ScanTaskResponse {
        ScanTaskResponse {
            id: self.id.clone(),
            name: format!("Scan-{}", &self.id[..8.min(self.id.len())]),
            target_id: self.target_id.clone(),
            target_ids: vec![self.target_id.clone()],
            target_name: self.target_name.clone(),
            target_count: 1,
            status: self.status,
            scan_type: self.scan_type,
            priority: self.priority,
            progress: self.progress,
            concurrency: 1,
            started_at: self.started_at,
            completed_at: self.completed_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Clone)]
pub struct AuthServices {
    pub auth_service: AuthService,
    pub rbac_service: RbacService,
}

/// 轻量行映射结构体，用于接收 targets 查询结果
#[derive(sqlx::FromRow)]
struct TargetRow {
    id: String,
    name: String,
    url: String,
    description: Option<String>,
    status: String,
    scan_frequency: Option<String>,
    last_scan_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl TargetRow {
    fn into_response(self) -> TargetResponse {
        TargetResponse {
            id: self.id,
            name: self.name,
            url: self.url,
            description: self.description,
            status: self.status,
            scan_frequency: self.scan_frequency,
            last_scan_at: self.last_scan_at,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Clone)]
pub struct TargetServices {
    pub target_store: TargetStore,
}

#[derive(Clone)]
pub struct ScanServices {
    pub scan_store: ScanStore,
}

/// 轻量行映射结构体，用于接收 vulnerabilities 查询结果
#[derive(sqlx::FromRow)]
struct VulnerabilityRow {
    id: String,
    task_id: String,
    target_id: String,
    plugin_name: String,
    severity: String,
    title: String,
    description: String,
    payload: Option<String>,
    proof: Option<String>,
    remediation: String,
    cve: Option<String>,
    cvss_score: Option<f64>,
    status: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    #[sqlx(default)]
    task_name: Option<String>,
    #[sqlx(default)]
    target_url: Option<String>,
}

impl VulnerabilityRow {
    fn into_response(self) -> VulnerabilityResponse {
        VulnerabilityResponse {
            id: self.id,
            task_id: self.task_id,
            task_name: self.task_name,
            target_id: self.target_id,
            target_url: self.target_url,
            plugin_name: self.plugin_name,
            severity: self.severity,
            title: self.title,
            description: self.description,
            payload: self.payload,
            proof: self.proof,
            remediation: self.remediation,
            cve: self.cve,
            cvss_score: self.cvss_score,
            status: self.status.unwrap_or_else(|| "open".to_string()),
            created_at: self.created_at,
            updated_at: self.created_at,
        }
    }
}

#[derive(Clone)]
pub struct VulnerabilityServices {
    pub vuln_store: VulnerabilityStore,
}

#[derive(Clone)]
pub struct ReportServices {
    pub report_store: ReportStore,
}

#[derive(Clone)]
pub struct TargetStore {
    pool: PgPool,
}

impl TargetStore {
    pub fn new(pool: PgPool) -> Self {
        TargetStore { pool }
    }

    pub async fn list_targets(
        &self,
        page: i32,
        page_size: i32,
    ) -> Result<PaginatedResponse<TargetResponse>, AppError> {
        let offset = (page - 1) * page_size;

        let targets: Vec<TargetRow> = sqlx::query_as(
            r#"SELECT id, name, url, description, status, scan_frequency, last_scan_at, created_at, updated_at 
               FROM targets 
               ORDER BY created_at DESC 
               LIMIT $1 OFFSET $2"#,
        )
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to list targets: {e}")))?;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM targets")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to count targets: {e}")))?;

        let total_pages = ((total + i64::from(page_size) - 1) / i64::from(page_size)) as i32;

        let data = targets.into_iter().map(|r| r.into_response()).collect();

        Ok(PaginatedResponse {
            data,
            page,
            page_size,
            total,
            total_pages,
        })
    }

    pub async fn get_target(&self, id: String) -> Result<TargetResponse, AppError> {
        let target: TargetRow = sqlx::query_as(
            r#"SELECT id, name, url, description, status, scan_frequency, last_scan_at, created_at, updated_at 
               FROM targets 
               WHERE id = $1"#,
        )
        .bind(&id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::NotFound("Target not found".to_string()),
            _ => AppError::DatabaseError(format!("Failed to get target: {e}")),
        })?;

        Ok(target.into_response())
    }

    pub async fn create_target(
        &self,
        user_id: String,
        request: CreateTargetRequest,
    ) -> Result<TargetResponse, AppError> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        sqlx::query(
            r#"INSERT INTO targets (id, user_id, name, url, description, status, scan_frequency, created_at, updated_at) 
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(&id)
        .bind(&user_id)
        .bind(request.name)
        .bind(request.url)
        .bind(request.description)
        .bind("active")
        .bind(request.scan_frequency)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to create target: {e}")))?;

        self.get_target(id).await
    }

    pub async fn update_target(
        &self,
        id: String,
        request: UpdateTargetRequest,
    ) -> Result<TargetResponse, AppError> {
        let now = chrono::Utc::now();

        sqlx::query(
            r#"UPDATE targets 
               SET name = COALESCE($1, name), 
                   url = COALESCE($2, url), 
                   description = COALESCE($3, description), 
                   status = COALESCE($4, status),
                   scan_frequency = COALESCE($5, scan_frequency),
                   updated_at = $6 
               WHERE id = $7"#,
        )
        .bind(request.name)
        .bind(request.url)
        .bind(request.description)
        .bind(request.status.as_ref().and_then(|s| match s.as_str() {
            "active" | "inactive" | "scanning" => Some(s.clone()),
            _ => None,
        }))
        .bind(request.scan_frequency)
        .bind(now)
        .bind(&id)
        .execute(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::NotFound("Target not found".to_string()),
            _ => AppError::DatabaseError(format!("Failed to update target: {e}")),
        })?;

        self.get_target(id).await
    }

    pub async fn delete_target(&self, id: String) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM targets WHERE id = $1")
            .bind(&id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete target: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Target not found".to_string()));
        }

        Ok(())
    }

    #[allow(dead_code)]
    fn map_to_response(&self, target: &Target) -> TargetResponse {
        TargetResponse {
            id: target.id.clone(),
            name: target.name.clone(),
            url: target.url.clone(),
            description: target.description.clone(),
            status: target.status.to_string(),
            scan_frequency: None,
            last_scan_at: None,
            created_at: target.created_at,
            updated_at: target.updated_at,
        }
    }
}

#[derive(Clone)]
pub struct ScanStore {
    pool: PgPool,
}

impl ScanStore {
    pub fn new(pool: PgPool) -> Self {
        ScanStore { pool }
    }

    pub async fn list_scan_tasks(
        &self,
        page: i32,
        page_size: i32,
    ) -> Result<PaginatedResponse<ScanTaskResponse>, AppError> {
        let offset = (page - 1) * page_size;

        let rows: Vec<ScanTaskJoinRow> = sqlx::query_as(
            r#"SELECT st.id, st.target_id, st.status, st.scan_type, st.priority,
                      st.progress, st.started_at, st.completed_at, st.created_at,
                      st.updated_at, t.name as "target_name"
               FROM scan_tasks st
               JOIN targets t ON st.target_id = t.id
               ORDER BY st.created_at DESC
               LIMIT $1 OFFSET $2"#,
        )
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to list scan tasks: {e}")))?;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scan_tasks")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to count scan tasks: {e}")))?;

        let total_pages = ((total + i64::from(page_size) - 1) / i64::from(page_size)) as i32;

        let data = rows
            .into_iter()
            .map(|r| r.into_response())
            .collect();

        Ok(PaginatedResponse {
            data,
            page,
            page_size,
            total,
            total_pages,
        })
    }

    pub async fn get_scan_task(&self, id: String) -> Result<ScanTaskResponse, AppError> {
        let row: ScanTaskJoinRow = sqlx::query_as(
            r#"SELECT st.id, st.target_id, st.status, st.scan_type, st.priority,
                      st.progress, st.started_at, st.completed_at, st.created_at,
                      st.updated_at, t.name as "target_name"
               FROM scan_tasks st
               JOIN targets t ON st.target_id = t.id
               WHERE st.id = $1"#,
        )
        .bind(&id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::NotFound("Scan task not found".to_string()),
            _ => AppError::DatabaseError(format!("Failed to get scan task: {e}")),
        })?;

        Ok(row.into_response())
    }

    pub async fn create_scan_task(
        &self,
        user_id: String,
        request: CreateScanTaskRequest,
    ) -> Result<ScanTaskResponse, AppError> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();

        let scan_type = match request.scan_type.as_deref() {
            Some("quick") => "quick",
            Some("custom") => "custom",
            _ => "full",
        };

        let priority = match request.priority.as_deref() {
            Some("low") => "low",
            Some("high") => "high",
            Some("critical") => "critical",
            _ => "medium",
        };

        let plugins = serde_json::json!(request.plugins.unwrap_or_default());

        sqlx::query(
            r#"INSERT INTO scan_tasks (id, user_id, target_id, status, scan_type, priority, plugins, progress, created_at, updated_at) 
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"#,
        )
        .bind(&id)
        .bind(&user_id)
        .bind(&request.target_id)
        .bind("pending")
        .bind(scan_type)
        .bind(priority)
        .bind(&plugins)
        .bind(0)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to create scan task: {e}")))?;

        self.get_scan_task_response_by_id(id).await
    }

    pub async fn update_scan_task(
        &self,
        id: String,
        request: UpdateScanTaskRequest,
    ) -> Result<ScanTaskResponse, AppError> {
        let now = chrono::Utc::now();

        let status = request.status.as_ref().and_then(|s| match s.as_str() {
            "pending" | "running" | "completed" | "failed" | "cancelled" => Some(s.clone()),
            _ => None,
        });

        let priority = request.priority.as_ref().and_then(|s| match s.as_str() {
            "low" | "medium" | "high" | "critical" => Some(s.clone()),
            _ => None,
        });

        let result = sqlx::query(
            r#"UPDATE scan_tasks 
               SET status = COALESCE($1, status), 
                   priority = COALESCE($2, priority), 
                   progress = COALESCE($3, progress),
                   updated_at = $4 
               WHERE id = $5"#,
        )
        .bind(status)
        .bind(priority)
        .bind(request.progress)
        .bind(now)
        .bind(&id)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update scan task: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Scan task not found".to_string()));
        }

        self.get_scan_task_response_by_id(id).await
    }

    pub async fn cancel_scan_task(&self, id: String) -> Result<ScanTaskResponse, AppError> {
        let now = chrono::Utc::now();

        let result = sqlx::query(
            r#"UPDATE scan_tasks 
               SET status = $1, updated_at = $2 
               WHERE id = $3"#,
        )
        .bind("cancelled")
        .bind(now)
        .bind(&id)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to cancel scan task: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Scan task not found".to_string()));
        }

        self.get_scan_task_response_by_id(id).await
    }

    pub async fn update_scan_task_status(&self, task_id: String, status: &str) -> Result<ScanTaskResponse, AppError> {
        let now = chrono::Utc::now();
        sqlx::query("UPDATE scan_tasks SET status = $1, updated_at = $2 WHERE id = $3")
            .bind(status)
            .bind(now)
            .bind(&task_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to update task status: {e}")))?;

        self.get_scan_task_response_by_id(task_id).await
    }

    pub async fn delete_scan_task(&self, id: String) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM scan_tasks WHERE id = $1")
            .bind(&id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete scan task: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Scan task not found".to_string()));
        }

        Ok(())
    }

    async fn get_scan_task_response_by_id(&self, id: String) -> Result<ScanTaskResponse, AppError> {
        let row: ScanTaskJoinRow = sqlx::query_as(
            r#"SELECT st.id, st.target_id, st.status, st.scan_type, st.priority,
                      st.progress, st.started_at, st.completed_at, st.created_at,
                      st.updated_at, t.name as "target_name"
               FROM scan_tasks st
               JOIN targets t ON st.target_id = t.id
               WHERE st.id = $1"#,
        )
        .bind(&id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::NotFound("Scan task not found".to_string()),
            _ => AppError::DatabaseError(format!("Failed to get scan task: {e}")),
        })?;

        Ok(row.into_response())
    }
}

#[derive(Clone)]
pub struct DashboardServices {
    pub dashboard_store: DashboardStore,
}

#[derive(Clone)]
pub struct DashboardStore {
    pool: PgPool,
}

impl DashboardStore {
    pub fn new(pool: PgPool) -> Self {
        DashboardStore { pool }
    }

    pub async fn get_stats(&self) -> Result<DashboardStatsResponse, AppError> {
        let today_scans: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM scan_tasks WHERE DATE(created_at) = CURRENT_DATE",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to count today scans: {e}")))?;

        let high_risk_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM vulnerabilities WHERE severity IN ('critical', 'high')",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to count high risk: {e}")))?;

        let pending_fix_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM vulnerabilities")
                .fetch_one(&self.pool)
                .await
                .map_err(|e| AppError::DatabaseError(format!("Failed to count vulnerabilities: {e}")))?;

        let total_targets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM targets")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to count targets: {e}")))?;

        #[derive(sqlx::FromRow)]
        struct ScanTrendRow {
            date: chrono::NaiveDate,
            count: i64,
        }
        let scan_rows: Vec<ScanTrendRow> = sqlx::query_as(
            r#"SELECT DATE(created_at) as date, COUNT(*) as count
               FROM scan_tasks
               WHERE created_at >= CURRENT_DATE - INTERVAL '6 DAY'
               GROUP BY DATE(created_at)
               ORDER BY date"#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to get scan trend: {e}")))?;

        #[derive(sqlx::FromRow)]
        struct VulnTrendRow {
            date: chrono::NaiveDate,
            severity: String,
            count: i64,
        }
        let vuln_rows: Vec<VulnTrendRow> = sqlx::query_as(
            r#"SELECT DATE(created_at) as date, severity, COUNT(*) as count
               FROM vulnerabilities
               WHERE created_at >= CURRENT_DATE - INTERVAL '6 DAY'
               GROUP BY DATE(created_at), severity
               ORDER BY date"#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to get vuln trend: {e}")))?;

        let mut vuln_by_date: std::collections::BTreeMap<chrono::NaiveDate, (i64, i64, i64)> =
            std::collections::BTreeMap::new();
        for row in vuln_rows {
            let entry = vuln_by_date.entry(row.date).or_insert((0, 0, 0));
            match row.severity.as_str() {
                "critical" | "high" => entry.0 += row.count,
                "medium" => entry.1 += row.count,
                "low" => entry.2 += row.count,
                _ => {}
            }
        }

        let mut scan_by_date: std::collections::BTreeMap<chrono::NaiveDate, i64> =
            std::collections::BTreeMap::new();
        for row in scan_rows {
            *scan_by_date.entry(row.date).or_insert(0) += row.count;
        }

        let mut scan_trend = Vec::new();
        let today = chrono::Utc::now().date_naive();
        for i in (0..7i64).rev() {
            let day = today - chrono::Duration::days(i);
            let count = scan_by_date.get(&day).copied().unwrap_or(0);
            let (high_risk, medium_risk, low_risk) =
                vuln_by_date.get(&day).copied().unwrap_or((0, 0, 0));
            scan_trend.push(TrendDataPoint {
                date: day.format("%Y-%m-%d").to_string(),
                count,
                high_risk,
                medium_risk,
                low_risk,
            });
        }

        #[derive(sqlx::FromRow)]
        struct DistRow {
            name: String,
            value: i64,
        }
        let vuln_dist: Vec<DistRow> = sqlx::query_as(
            r#"SELECT plugin_name as name, COUNT(*) as value
               FROM vulnerabilities
               GROUP BY plugin_name
               ORDER BY value DESC
               LIMIT 10"#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to get vuln distribution: {e}")))?;

        let sev_dist: Vec<DistRow> = sqlx::query_as(
            r#"SELECT severity as name, COUNT(*) as value
               FROM vulnerabilities
               GROUP BY severity
               ORDER BY value DESC"#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to get severity distribution: {e}")))?;

        Ok(DashboardStatsResponse {
            today_scans,
            high_risk_count,
            pending_fix_count,
            total_targets,
            scan_trend,
            vulnerability_distribution: vuln_dist
                .into_iter()
                .map(|r| DistributionItem {
                    name: r.name,
                    value: r.value,
                })
                .collect(),
            severity_distribution: sev_dist
                .into_iter()
                .map(|r| DistributionItem {
                    name: r.name,
                    value: r.value,
                })
                .collect(),
        })
    }
}

#[derive(Clone)]
pub struct VulnerabilityStore {
    pool: PgPool,
}

impl VulnerabilityStore {
    pub fn new(pool: PgPool) -> Self {
        VulnerabilityStore { pool }
    }

    pub async fn list_vulnerabilities(
        &self,
        page: i32,
        page_size: i32,
        filter: Option<VulnerabilityFilter>,
    ) -> Result<PaginatedResponse<VulnerabilityResponse>, AppError> {
        let offset = (page - 1) * page_size;

        let severity_filter = filter.as_ref().and_then(|f| f.severity.clone());

        let vulnerabilities: Vec<VulnerabilityRow> = if let Some(severity) = severity_filter {
            sqlx::query_as(
                r#"SELECT v.id, v.task_id, v.target_id, v.plugin_name, v.severity, v.title, v.description,
                          v.payload, v.proof, v.remediation, v.cve, v.cvss_score, v.status, v.created_at,
                          tgt.url as target_url
                   FROM vulnerabilities v
                   LEFT JOIN targets tgt ON v.target_id = tgt.id
                   WHERE v.severity = $1
                   ORDER BY v.created_at DESC
                   LIMIT $2 OFFSET $3"#,
            )
            .bind(severity)
            .bind(page_size)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
        } else {
            sqlx::query_as(
                r#"SELECT v.id, v.task_id, v.target_id, v.plugin_name, v.severity, v.title, v.description,
                          v.payload, v.proof, v.remediation, v.cve, v.cvss_score, v.status, v.created_at,
                          tgt.url as target_url
                   FROM vulnerabilities v
                   LEFT JOIN targets tgt ON v.target_id = tgt.id
                   ORDER BY v.created_at DESC
                   LIMIT $1 OFFSET $2"#,
            )
            .bind(page_size)
            .bind(offset)
            .fetch_all(&self.pool)
            .await
        }
        .map_err(|e| AppError::DatabaseError(format!("Failed to list vulnerabilities: {e}")))?;

        let total: i64 = if let Some(filter) = &filter {
            if let Some(severity) = &filter.severity {
                sqlx::query_scalar("SELECT COUNT(*) FROM vulnerabilities WHERE severity = $1")
                    .bind(severity)
                    .fetch_one(&self.pool)
                    .await
            } else {
                sqlx::query_scalar("SELECT COUNT(*) FROM vulnerabilities")
                    .fetch_one(&self.pool)
                    .await
            }
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM vulnerabilities")
                .fetch_one(&self.pool)
                .await
        }
        .map_err(|e| AppError::DatabaseError(format!("Failed to count vulnerabilities: {e}")))?;

        let total_pages = ((total + i64::from(page_size) - 1) / i64::from(page_size)) as i32;

        let data = vulnerabilities
            .into_iter()
            .map(|v| v.into_response())
            .collect();

        Ok(PaginatedResponse {
            data,
            page,
            page_size,
            total,
            total_pages,
        })
    }

    pub async fn get_vulnerability(&self, id: String) -> Result<VulnerabilityResponse, AppError> {
        let vulnerability: VulnerabilityRow = sqlx::query_as(
            r#"SELECT v.id, v.task_id, v.target_id, v.plugin_name, v.severity, v.title, v.description,
               v.payload, v.proof, v.remediation, v.cve, v.cvss_score, v.status, v.created_at,
               tgt.url as target_url
               FROM vulnerabilities v
               LEFT JOIN targets tgt ON v.target_id = tgt.id
               WHERE v.id = $1"#,
        )
        .bind(&id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::NotFound("Vulnerability not found".to_string()),
            _ => AppError::DatabaseError(format!("Failed to get vulnerability: {e}")),
        })?;

        Ok(vulnerability.into_response())
    }

    pub async fn delete_vulnerability(&self, id: String) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM vulnerabilities WHERE id = $1")
            .bind(&id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete vulnerability: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Vulnerability not found".to_string()));
        }

        Ok(())
    }

    pub async fn update_status(&self, id: String, status: String) -> Result<VulnerabilityResponse, AppError> {
        let now = chrono::Utc::now();
        let result = sqlx::query("UPDATE vulnerabilities SET status = $1, updated_at = $2 WHERE id = $3")
            .bind(&status)
            .bind(now)
            .bind(&id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to update vulnerability status: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Vulnerability not found".to_string()));
        }

        self.get_vulnerability(id).await
    }

    pub async fn list_all(&self) -> Result<Vec<VulnerabilityResponse>, AppError> {
        let vulnerabilities: Vec<VulnerabilityRow> = sqlx::query_as(
            r#"SELECT v.id, v.task_id, v.target_id, v.plugin_name, v.severity, v.title, v.description,
               v.payload, v.proof, v.remediation, v.cve, v.cvss_score, v.status, v.created_at,
               tgt.url as target_url
               FROM vulnerabilities v
               LEFT JOIN targets tgt ON v.target_id = tgt.id
               ORDER BY v.created_at DESC"#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to list all vulnerabilities: {e}")))?;

        Ok(vulnerabilities.into_iter().map(|v| v.into_response()).collect())
    }

    pub async fn list_by_ids(&self, ids: &[String]) -> Result<Vec<VulnerabilityResponse>, AppError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        // 动态构建 IN 查询
        let placeholders = (1..=ids.len()).map(|i| format!("${}", i)).collect::<Vec<_>>().join(",");
        let sql = format!(
            r#"SELECT v.id, v.task_id, v.target_id, v.plugin_name, v.severity, v.title, v.description,
               v.payload, v.proof, v.remediation, v.cve, v.cvss_score, v.status, v.created_at,
               tgt.url as target_url
               FROM vulnerabilities v
               LEFT JOIN targets tgt ON v.target_id = tgt.id
               WHERE v.id IN ({})
               ORDER BY v.created_at DESC"#,
            placeholders
        );

        let mut query = sqlx::query_as::<_, VulnerabilityRow>(&sql);
        for id in ids {
            query = query.bind(id);
        }

        let vulnerabilities: Vec<VulnerabilityRow> = query
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to list vulnerabilities by ids: {e}")))?;

        Ok(vulnerabilities.into_iter().map(|v| v.into_response()).collect())
    }
}

#[derive(Clone)]
pub struct ReportStore {
    pool: PgPool,
}

impl ReportStore {
    pub fn new(pool: PgPool) -> Self {
        ReportStore { pool }
    }

    pub async fn list_reports(
        &self,
        page: i32,
        page_size: i32,
    ) -> Result<PaginatedResponse<ReportResponse>, AppError> {
        let offset = (page - 1) * page_size;

        let rows: Vec<ReportJoinRow> = sqlx::query_as(
            r#"SELECT r.id, r.task_id, r.status, r.summary, r.generated_at, r.created_at, 
                      r.updated_at, st.scan_type as "task_name", r.template 
               FROM reports r 
               JOIN scan_tasks st ON r.task_id = st.id 
               ORDER BY r.created_at DESC 
               LIMIT $1 OFFSET $2"#,
        )
        .bind(page_size)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to list reports: {e}")))?;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reports")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to count reports: {e}")))?;

        let total_pages = ((total + i64::from(page_size) - 1) / i64::from(page_size)) as i32;

        let data = rows
            .into_iter()
            .map(|r| r.into_response())
            .collect();

        Ok(PaginatedResponse {
            data,
            page,
            page_size,
            total,
            total_pages,
        })
    }

    pub async fn get_report(&self, id: String) -> Result<ReportResponse, AppError> {
        let row: ReportJoinRow = sqlx::query_as(
            r#"SELECT r.id, r.task_id, r.status, r.summary, r.generated_at, r.created_at, 
                      r.updated_at, st.scan_type as "task_name", r.template 
               FROM reports r 
               JOIN scan_tasks st ON r.task_id = st.id 
               WHERE r.id = $1"#,
        )
        .bind(&id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::NotFound("Report not found".to_string()),
            _ => AppError::DatabaseError(format!("Failed to get report: {e}")),
        })?;

        Ok(row.into_response())
    }

    pub async fn create_report(
        &self,
        user_id: String,
        request: CreateReportRequest,
    ) -> Result<ReportResponse, AppError> {
        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now();
        let template = request.template.unwrap_or_else(|| "technical".to_string());

        // 1. 查询扫描任务信息（JOIN targets 获取 target_name 和 target_url）
        let task_row = sqlx::query_as::<_, ScanTaskJoinRow>(
            r#"SELECT st.id, st.target_id, st.status, st.scan_type, st.priority,
                      st.progress, st.started_at, st.completed_at, st.created_at,
                      st.updated_at, t.name as "target_name"
               FROM scan_tasks st
               JOIN targets t ON st.target_id = t.id
               WHERE st.id = $1"#,
        )
        .bind(&request.task_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to get scan task: {e}")))?;

        let task = task_row.ok_or_else(|| AppError::NotFound(format!("Scan task {} not found", request.task_id)))?;

        // 2. 单独查询 target 的 url（ScanTaskJoinRow 没有 target_url）
        #[derive(sqlx::FromRow)]
        struct TargetInfoRow {
            name: String,
            url: String,
        }
        let target_info: TargetInfoRow = sqlx::query_as(
            "SELECT name, url FROM targets WHERE id = $1",
        )
        .bind(&task.target_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to get target info: {e}")))?;

        // 3. 查询该任务的所有漏洞
        let vuln_rows: Vec<VulnerabilityRow> = sqlx::query_as(
            r#"SELECT v.id, v.task_id, v.target_id, v.plugin_name, v.severity, v.title, v.description,
               v.payload, v.proof, v.remediation, v.cve, v.cvss_score, v.status, v.created_at,
               tgt.url as target_url
               FROM vulnerabilities v
               LEFT JOIN targets tgt ON v.target_id = tgt.id
               WHERE v.task_id = $1
               ORDER BY v.severity DESC, v.created_at DESC"#,
        )
        .bind(&request.task_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to get vulnerabilities: {e}")))?;

        let vulnerabilities: Vec<_> = vuln_rows.into_iter().map(|v| v.into_response()).collect();

        // 4. 统计
        let total = vulnerabilities.len();
        let critical = vulnerabilities.iter().filter(|v| v.severity == "critical").count();
        let high = vulnerabilities.iter().filter(|v| v.severity == "high").count();
        let medium = vulnerabilities.iter().filter(|v| v.severity == "medium").count();
        let low = vulnerabilities.iter().filter(|v| v.severity == "low").count();
        let info = vulnerabilities.iter().filter(|v| v.severity == "info").count();

        // 5. 生成报告内容
        let summary = serde_json::json!({
            "template": template,
            "generated_at": now.to_rfc3339(),
            "target": {
                "id": task.target_id,
                "name": target_info.name,
                "url": target_info.url,
            },
            "scan_task": {
                "id": request.task_id,
                "status": task.status,
                "scan_type": task.scan_type,
                "started_at": task.started_at.map(|t| t.to_rfc3339()),
                "completed_at": task.completed_at.map(|t| t.to_rfc3339()),
            },
            "statistics": {
                "total": total,
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "info": info,
            },
            "risk_level": if critical > 0 { "critical".to_string() }
                         else if high > 0 { "high".to_string() }
                         else if medium > 0 { "medium".to_string() }
                         else if total > 0 { "low".to_string() }
                         else { "none".to_string() },
            "vulnerabilities": vulnerabilities.iter().map(|v| serde_json::json!({
                "id": v.id,
                "title": v.title,
                "severity": v.severity,
                "plugin_name": v.plugin_name,
                "description": v.description,
                "remediation": v.remediation,
                "cve": v.cve,
                "cvss_score": v.cvss_score,
            })).collect::<Vec<_>>(),
        });

        // 6. 写入数据库
        sqlx::query(
            r#"INSERT INTO reports (id, task_id, user_id, status, summary, template, generated_at, created_at, updated_at)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
        )
        .bind(&id)
        .bind(&request.task_id)
        .bind(&user_id)
        .bind("completed")
        .bind(&summary)
        .bind(&template)
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to create report: {e}")))?;

        self.get_report_response_by_id(id).await
    }

    pub async fn update_report(
        &self,
        id: String,
        request: UpdateReportRequest,
    ) -> Result<ReportResponse, AppError> {
        let now = chrono::Utc::now();

        let status = request.status.as_ref().and_then(|s| match s.as_str() {
            "generating" | "ready" | "completed" | "failed" => Some(s.clone()),
            _ => None,
        });

        let result = sqlx::query(
            r#"UPDATE reports 
               SET status = COALESCE($1, status), 
                   summary = COALESCE($2, summary), 
                   generated_at = CASE WHEN $3 IN ('ready', 'completed') THEN $4 ELSE generated_at END,
                   updated_at = $5 
               WHERE id = $6"#,
        )
        .bind(status.clone())
        .bind(request.summary)
        .bind(status.clone())
        .bind(now)
        .bind(now)
        .bind(&id)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update report: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Report not found".to_string()));
        }

        self.get_report_response_by_id(id).await
    }

    pub async fn delete_report(&self, id: String) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM reports WHERE id = $1")
            .bind(&id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete report: {e}")))?;

        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("Report not found".to_string()));
        }

        Ok(())
    }

    async fn get_report_response_by_id(&self, id: String) -> Result<ReportResponse, AppError> {
        let row: ReportJoinRow = sqlx::query_as(
            r#"SELECT r.id, r.task_id, r.status, r.summary, r.generated_at, r.created_at, 
                      r.updated_at, st.scan_type as "task_name", r.template 
               FROM reports r 
               JOIN scan_tasks st ON r.task_id = st.id 
               WHERE r.id = $1"#,
        )
        .bind(&id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => AppError::NotFound("Report not found".to_string()),
            _ => AppError::DatabaseError(format!("Failed to get report: {e}")),
        })?;

        Ok(row.into_response())
    }
}
