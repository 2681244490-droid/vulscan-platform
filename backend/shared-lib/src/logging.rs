use std::time::Duration;

use tracing::{debug, error, info, warn};
use tracing_subscriber::{
    fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

pub fn init_logging() {
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("vulscan=info,tracing=info"));

    tracing_subscriber::registry()
        .with(env_filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_span_events(FmtSpan::ENTER | FmtSpan::EXIT),
        )
        .init();

    info!("Logging initialized");
}

pub fn log_request(request_id: &str, method: &str, path: &str) {
    info!(%request_id, %method, %path, "Incoming request");
}

pub fn log_response(request_id: &str, status: u16, duration: Duration) {
    info!(%request_id, %status, duration = ?duration, "Response sent");
}

pub fn log_error(request_id: &str, error: &str) {
    error!(%request_id, %error, "Request error");
}

pub fn log_scan_task_start(task_id: &str, target: &str) {
    info!(%task_id, %target, "Scan task started");
}

pub fn log_scan_task_progress(task_id: &str, progress: u32) {
    debug!(%task_id, %progress, "Scan task progress");
}

pub fn log_scan_task_complete(task_id: &str, vulnerabilities: usize) {
    info!(%task_id, %vulnerabilities, "Scan task completed");
}

pub fn log_scan_task_failed(task_id: &str, error: &str) {
    error!(%task_id, %error, "Scan task failed");
}

pub fn log_vulnerability_found(task_id: &str, severity: &str, title: &str) {
    warn!(%task_id, %severity, %title, "Vulnerability found");
}

pub fn log_auth_success(email: &str) {
    info!(%email, "Authentication successful");
}

pub fn log_auth_failure(email: &str, reason: &str) {
    warn!(%email, %reason, "Authentication failed");
}

pub fn log_rate_limit(ip: &str, path: &str) {
    warn!(%ip, %path, "Rate limit exceeded");
}

pub fn log_permission_denied(user_id: &str, action: &str) {
    warn!(%user_id, %action, "Permission denied");
}
