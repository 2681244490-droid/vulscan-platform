use actix_web::{delete, get, post, put, web, HttpRequest, HttpResponse, HttpMessage};
use auth_service::jwt::Claims;
use shared_lib::errors::AppError;
use shared_lib::schemas::{
    BatchCreateTargetRequest, CreateReportRequest, CreateScanTaskRequest, CreateTargetRequest,
    ExportVulnerabilitiesRequest, LoginRequest, LoginResponse, RefreshTokenRequest,
    RegisterRequest, UpdateReportRequest, UpdateScanTaskRequest, UpdateTargetRequest,
    UpdateVulnerabilityStatusRequest, UserResponse, VulnerabilityFilter,
};
use shared_lib::models::UserRole;
use validator::Validate;

use crate::services::{
    AuthServices, DashboardServices, ReportServices, ScanServices, TargetServices,
    VulnerabilityServices,
};

#[derive(serde::Deserialize)]
pub struct PageQuery {
    pub page: Option<i32>,
    pub page_size: Option<i32>,
}

impl PageQuery {
    pub fn page(&self) -> i32 {
        self.page.unwrap_or(1).max(1)
    }

    pub fn page_size(&self) -> i32 {
        self.page_size.unwrap_or(20).clamp(1, 100)
    }
}

#[derive(serde::Deserialize)]
pub struct VulnerabilityListQuery {
    pub page: Option<i32>,
    pub page_size: Option<i32>,
    pub severity: Option<String>,
    pub plugin_name: Option<String>,
    pub task_id: Option<String>,
    pub target_id: Option<String>,
}

// Auth routes
#[post("/api/auth/login")]
async fn login(
    req: web::Json<LoginRequest>,
    services: web::Data<AuthServices>,
) -> Result<HttpResponse, AppError> {
    let req_data = req.into_inner();
    req_data.validate().map_err(|e| AppError::ValidationError(e.to_string()))?;
    let response: LoginResponse = services.auth_service.login(req_data).await?;
    Ok(HttpResponse::Ok().json(response))
}

#[post("/api/auth/register")]
async fn register(
    req: web::Json<RegisterRequest>,
    services: web::Data<AuthServices>,
) -> Result<HttpResponse, AppError> {
    let req_data = req.into_inner();
    req_data.validate().map_err(|e| AppError::ValidationError(e.to_string()))?;
    let user: UserResponse = services.auth_service.register(req_data).await?;
    Ok(HttpResponse::Created().json(user))
}

#[post("/api/auth/refresh")]
async fn refresh_token(
    req: web::Json<RefreshTokenRequest>,
    services: web::Data<AuthServices>,
) -> Result<HttpResponse, AppError> {
    let response: LoginResponse = services.auth_service.refresh_token(req.into_inner()).await?;
    Ok(HttpResponse::Ok().json(response))
}

#[post("/api/auth/logout")]
async fn logout(
    req: web::Json<RefreshTokenRequest>,
    services: web::Data<AuthServices>,
) -> Result<HttpResponse, AppError> {
    services.auth_service.logout(&req.refresh_token).await?;
    Ok(HttpResponse::NoContent().finish())
}

#[get("/api/auth/me")]
async fn get_me(req: HttpRequest) -> Result<HttpResponse, AppError> {
    let ext = req.extensions();
    let claims = match ext.get::<Claims>() {
        Some(c) => c.clone(),
        None => return Err(AppError::AuthError("未提供有效的认证凭据".to_string())),
    };

    let role = match claims.role.as_str() {
        "admin" => UserRole::Admin,
        "scanner" => UserRole::Scanner,
        _ => UserRole::User,
    };

    Ok(HttpResponse::Ok().json(UserResponse {
        id: claims.sub.clone(),
        username: claims.sub.clone(),
        email: claims.email.clone(),
        role: role.to_string(),
        is_active: true,
        created_at: chrono::Utc::now(),
    }))
}

// Target routes
#[get("/api/targets")]
async fn list_targets(
    services: web::Data<TargetServices>,
    page: web::Query<PageQuery>,
) -> Result<HttpResponse, AppError> {
    let response = services
        .target_store
        .list_targets(page.page(), page.page_size())
        .await?;
    Ok(HttpResponse::Ok().json(response))
}

#[get("/api/targets/{id}")]
async fn get_target(
    path: web::Path<String>,
    services: web::Data<TargetServices>,
) -> Result<HttpResponse, AppError> {
    let target = services.target_store.get_target(path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(target))
}

#[post("/api/targets")]
async fn create_target(
    http_req: HttpRequest,
    req: web::Json<CreateTargetRequest>,
    services: web::Data<TargetServices>,
) -> Result<HttpResponse, AppError> {
    let req_data = req.into_inner();
    req_data.validate().map_err(|e| AppError::ValidationError(e.to_string()))?;
    
    let user_id = http_req.extensions().get::<Claims>().map(|c| {
        tracing::info!("Found claims, sub={}", c.sub);
        c.sub.clone()
    }).unwrap_or_else(|| {
        tracing::warn!("No claims found in extensions!");
        String::default()
    });
    
    let target = services
        .target_store
        .create_target(user_id, req_data)
        .await?;
    Ok(HttpResponse::Created().json(target))
}

#[put("/api/targets/{id}")]
async fn update_target(
    path: web::Path<String>,
    req: web::Json<UpdateTargetRequest>,
    services: web::Data<TargetServices>,
) -> Result<HttpResponse, AppError> {
    let target = services
        .target_store
        .update_target(path.into_inner(), req.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(target))
}

#[delete("/api/targets/{id}")]
async fn delete_target(
    path: web::Path<String>,
    services: web::Data<TargetServices>,
) -> Result<HttpResponse, AppError> {
    services.target_store.delete_target(path.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}

#[post("/api/targets/batch")]
async fn batch_create_targets(
    http_req: HttpRequest,
    req: web::Json<BatchCreateTargetRequest>,
    services: web::Data<TargetServices>,
) -> Result<HttpResponse, AppError> {
    let user_id = http_req.extensions().get::<Claims>().map(|c| c.sub.clone()).unwrap_or_default();
    let mut created = Vec::new();
    for target_req in req.targets.iter() {
        match services
            .target_store
            .create_target(user_id.clone(), CreateTargetRequest {
                name: target_req.name.clone(),
                url: target_req.url.clone(),
                description: target_req.description.clone(),
                scan_frequency: target_req.scan_frequency.clone(),
            })
            .await
        {
            Ok(target) => created.push(target),
            Err(_) => continue,
        }
    }
    Ok(HttpResponse::Created().json(created))
}

// Scan task routes
#[get("/api/scan-tasks")]
async fn list_scan_tasks(
    services: web::Data<ScanServices>,
    page: web::Query<PageQuery>,
) -> Result<HttpResponse, AppError> {
    let response = services
        .scan_store
        .list_scan_tasks(page.page(), page.page_size())
        .await?;
    Ok(HttpResponse::Ok().json(response))
}

#[get("/api/scan-tasks/{id}")]
async fn get_scan_task(
    path: web::Path<String>,
    services: web::Data<ScanServices>,
) -> Result<HttpResponse, AppError> {
    let task = services.scan_store.get_scan_task(path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(task))
}

#[post("/api/scan-tasks")]
async fn create_scan_task(
    http_req: HttpRequest,
    req: web::Json<CreateScanTaskRequest>,
    services: web::Data<ScanServices>,
) -> Result<HttpResponse, AppError> {
    let user_id = http_req.extensions().get::<Claims>().map(|c| c.sub.clone()).unwrap_or_default();
    let task = services
        .scan_store
        .create_scan_task(user_id, req.into_inner())
        .await?;
    Ok(HttpResponse::Created().json(task))
}

#[put("/api/scan-tasks/{id}")]
async fn update_scan_task(
    path: web::Path<String>,
    req: web::Json<UpdateScanTaskRequest>,
    services: web::Data<ScanServices>,
) -> Result<HttpResponse, AppError> {
    let task = services
        .scan_store
        .update_scan_task(path.into_inner(), req.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(task))
}

#[put("/api/scan-tasks/{id}/cancel")]
async fn cancel_scan_task(
    path: web::Path<String>,
    services: web::Data<ScanServices>,
) -> Result<HttpResponse, AppError> {
    let task = services.scan_store.cancel_scan_task(path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(task))
}

#[delete("/api/scan-tasks/{id}")]
async fn delete_scan_task(
    path: web::Path<String>,
    services: web::Data<ScanServices>,
) -> Result<HttpResponse, AppError> {
    services.scan_store.delete_scan_task(path.into_inner()).await?;
    Ok(HttpResponse::NoContent().finish())
}

#[put("/api/scan-tasks/{id}/pause")]
async fn pause_scan_task(
    path: web::Path<String>,
    services: web::Data<ScanServices>,
) -> Result<HttpResponse, AppError> {
    let task = services.scan_store.update_scan_task_status(path.into_inner(), "paused").await?;
    Ok(HttpResponse::Ok().json(task))
}

#[put("/api/scan-tasks/{id}/resume")]
async fn resume_scan_task(
    path: web::Path<String>,
    services: web::Data<ScanServices>,
) -> Result<HttpResponse, AppError> {
    let task = services.scan_store.update_scan_task_status(path.into_inner(), "running").await?;
    Ok(HttpResponse::Ok().json(task))
}

// Vulnerability routes
#[get("/api/vulnerabilities")]
async fn list_vulnerabilities(
    services: web::Data<VulnerabilityServices>,
    query: web::Query<VulnerabilityListQuery>,
) -> Result<HttpResponse, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query.page_size.unwrap_or(20).clamp(1, 100);
    let filter = VulnerabilityFilter {
        severity: query.severity.clone(),
        plugin_name: query.plugin_name.clone(),
        task_id: query.task_id.clone(),
        target_id: query.target_id.clone(),
    };
    let response = services
        .vuln_store
        .list_vulnerabilities(page, page_size, Some(filter))
        .await?;
    Ok(HttpResponse::Ok().json(response))
}

#[get("/api/vulnerabilities/{id}")]
async fn get_vulnerability(
    path: web::Path<String>,
    services: web::Data<VulnerabilityServices>,
) -> Result<HttpResponse, AppError> {
    let vuln = services
        .vuln_store
        .get_vulnerability(path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(vuln))
}

#[delete("/api/vulnerabilities/{id}")]
async fn delete_vulnerability(
    path: web::Path<String>,
    services: web::Data<VulnerabilityServices>,
) -> Result<HttpResponse, AppError> {
    services
        .vuln_store
        .delete_vulnerability(path.into_inner())
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

#[put("/api/vulnerabilities/{id}/status")]
async fn update_vulnerability_status(
    path: web::Path<String>,
    req: web::Json<UpdateVulnerabilityStatusRequest>,
    services: web::Data<VulnerabilityServices>,
) -> Result<HttpResponse, AppError> {
    let vuln = services
        .vuln_store
        .update_status(path.into_inner(), req.status.clone())
        .await?;
    Ok(HttpResponse::Ok().json(vuln))
}

#[post("/api/vulnerabilities/export")]
async fn export_vulnerabilities(
    req: web::Json<ExportVulnerabilitiesRequest>,
    services: web::Data<VulnerabilityServices>,
) -> Result<HttpResponse, AppError> {
    let ids = req.ids.as_deref().unwrap_or_default();
    let vulnerabilities = if ids.is_empty() {
        services.vuln_store.list_all().await?
    } else {
        services.vuln_store.list_by_ids(ids).await?
    };

    match req.format.as_str() {
        "json" => {
            Ok(HttpResponse::Ok().json(vulnerabilities))
        }
        "csv" => {
            let mut csv = String::from("id,title,severity,status,target_id,plugin_name,created_at\n");
            for v in &vulnerabilities {
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{}\n",
                    v.id,
                    v.title.replace(',', ";"),
                    v.severity,
                    v.status,
                    v.target_id,
                    v.plugin_name.replace(',', ";"),
                    v.created_at,
                ));
            }
            Ok(HttpResponse::Ok()
                .content_type("text/csv")
                .insert_header(("Content-Disposition", "attachment; filename=\"vulnerabilities.csv\""))
                .body(csv))
        }
        _ => Err(AppError::ValidationError(
            "Unsupported format. Use 'json' or 'csv'.".to_string(),
        )),
    }
}

// Report routes
#[get("/api/reports")]
async fn list_reports(
    services: web::Data<ReportServices>,
    page: web::Query<PageQuery>,
) -> Result<HttpResponse, AppError> {
    let response = services
        .report_store
        .list_reports(page.page(), page.page_size())
        .await?;
    Ok(HttpResponse::Ok().json(response))
}

#[get("/api/reports/{id}")]
async fn get_report(
    path: web::Path<String>,
    services: web::Data<ReportServices>,
) -> Result<HttpResponse, AppError> {
    let report = services.report_store.get_report(path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(report))
}

#[post("/api/reports")]
async fn create_report(
    http_req: HttpRequest,
    req: web::Json<CreateReportRequest>,
    services: web::Data<ReportServices>,
) -> Result<HttpResponse, AppError> {
    let user_id = http_req.extensions().get::<Claims>().map(|c| c.sub.clone()).unwrap_or_default();
    let report = services
        .report_store
        .create_report(user_id, req.into_inner())
        .await?;
    Ok(HttpResponse::Created().json(report))
}

#[put("/api/reports/{id}")]
async fn update_report(
    path: web::Path<String>,
    req: web::Json<UpdateReportRequest>,
    services: web::Data<ReportServices>,
) -> Result<HttpResponse, AppError> {
    let report = services
        .report_store
        .update_report(path.into_inner(), req.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(report))
}

#[delete("/api/reports/{id}")]
async fn delete_report(
    path: web::Path<String>,
    services: web::Data<ReportServices>,
) -> Result<HttpResponse, AppError> {
    services
        .report_store
        .delete_report(path.into_inner())
        .await?;
    Ok(HttpResponse::NoContent().finish())
}

#[get("/api/reports/{id}/download")]
async fn download_report(
    path: web::Path<String>,
    services: web::Data<ReportServices>,
) -> Result<HttpResponse, AppError> {
    let report = services.report_store.get_report(path.into_inner()).await?;

    let report_data = serde_json::to_string_pretty(&report)
        .map_err(|e| AppError::InvalidRequest(format!("Failed to serialize report: {}", e)))?;

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .insert_header(("Content-Disposition", "attachment; filename=\"report.json\""))
        .body(report_data))
}

// Dashboard routes
#[get("/api/dashboard/stats")]
async fn get_dashboard_stats(
    services: web::Data<DashboardServices>,
) -> Result<HttpResponse, AppError> {
    let stats = services.dashboard_store.get_stats().await?;
    Ok(HttpResponse::Ok().json(stats))
}

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(login);
    cfg.service(register);
    cfg.service(refresh_token);
    cfg.service(logout);
    cfg.service(get_me);
    cfg.service(list_targets);
    cfg.service(get_target);
    cfg.service(create_target);
    cfg.service(batch_create_targets);
    cfg.service(update_target);
    cfg.service(delete_target);
    cfg.service(list_scan_tasks);
    cfg.service(get_scan_task);
    cfg.service(create_scan_task);
    cfg.service(update_scan_task);
    cfg.service(cancel_scan_task);
    cfg.service(pause_scan_task);
    cfg.service(resume_scan_task);
    cfg.service(delete_scan_task);
    cfg.service(list_vulnerabilities);
    cfg.service(get_vulnerability);
    cfg.service(update_vulnerability_status);
    cfg.service(delete_vulnerability);
    cfg.service(export_vulnerabilities);
    cfg.service(list_reports);
    cfg.service(get_report);
    cfg.service(create_report);
    cfg.service(update_report);
    cfg.service(delete_report);
    cfg.service(download_report);
    cfg.service(get_dashboard_stats);
}
