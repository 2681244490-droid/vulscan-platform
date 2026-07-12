use prometheus::{
    register_counter, register_counter_vec, register_histogram, register_histogram_vec,
    register_gauge, Counter, CounterVec, Histogram, HistogramVec, Gauge,
};

pub struct Metrics {
    pub http_requests_total: CounterVec,
    pub http_request_duration_seconds: HistogramVec,
    pub http_request_errors_total: CounterVec,
    pub active_scan_tasks: Gauge,
    pub scan_tasks_total: CounterVec,
    pub vulnerabilities_found_total: CounterVec,
    pub scan_duration_seconds: Histogram,
    pub api_requests_total: CounterVec,
    pub api_request_rate_limit_total: Counter,
    pub auth_success_total: Counter,
    pub auth_failure_total: Counter,
    pub database_connections: Gauge,
    pub redis_connections: Gauge,
}

impl Metrics {
    pub fn new() -> Self {
        let http_requests_total = register_counter_vec!(
            "http_requests_total",
            "Total number of HTTP requests",
            &["method", "endpoint", "status_code"]
        ).unwrap();

        let http_request_duration_seconds = register_histogram_vec!(
            "http_request_duration_seconds",
            "HTTP request duration in seconds",
            &["method", "endpoint"],
            vec![0.001, 0.01, 0.1, 0.5, 1.0, 5.0, 10.0]
        ).unwrap();

        let http_request_errors_total = register_counter_vec!(
            "http_request_errors_total",
            "Total number of HTTP request errors",
            &["method", "endpoint", "error_type"]
        ).unwrap();

        let active_scan_tasks = register_gauge!(
            "active_scan_tasks",
            "Number of active scan tasks"
        ).unwrap();

        let scan_tasks_total = register_counter_vec!(
            "scan_tasks_total",
            "Total number of scan tasks",
            &["status"]
        ).unwrap();

        let vulnerabilities_found_total = register_counter_vec!(
            "vulnerabilities_found_total",
            "Total number of vulnerabilities found",
            &["severity", "plugin"]
        ).unwrap();

        let scan_duration_seconds = register_histogram!(
            "scan_duration_seconds",
            "Scan duration in seconds",
            vec![1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0]
        ).unwrap();

        let api_requests_total = register_counter_vec!(
            "api_requests_total",
            "Total number of API requests",
            &["endpoint", "method"]
        ).unwrap();

        let api_request_rate_limit_total = register_counter!(
            "api_request_rate_limit_total",
            "Total number of rate limited API requests"
        ).unwrap();

        let auth_success_total = register_counter!(
            "auth_success_total",
            "Total number of successful authentications"
        ).unwrap();

        let auth_failure_total = register_counter!(
            "auth_failure_total",
            "Total number of failed authentications"
        ).unwrap();

        let database_connections = register_gauge!(
            "database_connections",
            "Number of active database connections"
        ).unwrap();

        let redis_connections = register_gauge!(
            "redis_connections",
            "Number of active Redis connections"
        ).unwrap();

        Metrics {
            http_requests_total,
            http_request_duration_seconds,
            http_request_errors_total,
            active_scan_tasks,
            scan_tasks_total,
            vulnerabilities_found_total,
            scan_duration_seconds,
            api_requests_total,
            api_request_rate_limit_total,
            auth_success_total,
            auth_failure_total,
            database_connections,
            redis_connections,
        }
    }
}

lazy_static::lazy_static! {
    pub static ref METRICS: Metrics = Metrics::new();
}

pub fn record_http_request(method: &str, endpoint: &str, status_code: u16, duration: f64) {
    METRICS.http_requests_total
        .with_label_values(&[method, endpoint, &status_code.to_string()])
        .inc();
    
    METRICS.http_request_duration_seconds
        .with_label_values(&[method, endpoint])
        .observe(duration);
}

pub fn record_http_request_error(method: &str, endpoint: &str, error_type: &str) {
    METRICS.http_request_errors_total
        .with_label_values(&[method, endpoint, error_type])
        .inc();
}

pub fn increment_scan_task(status: &str) {
    METRICS.scan_tasks_total.with_label_values(&[status]).inc();
}

pub fn set_active_scan_tasks(count: i64) {
    METRICS.active_scan_tasks.set(count as f64);
}

pub fn increment_active_scan_tasks() {
    METRICS.active_scan_tasks.inc();
}

pub fn decrement_active_scan_tasks() {
    METRICS.active_scan_tasks.dec();
}

pub fn record_vulnerability(severity: &str, plugin: &str) {
    METRICS.vulnerabilities_found_total
        .with_label_values(&[severity, plugin])
        .inc();
}

pub fn record_scan_duration(duration: f64) {
    METRICS.scan_duration_seconds.observe(duration);
}

pub fn record_api_request(endpoint: &str, method: &str) {
    METRICS.api_requests_total.with_label_values(&[endpoint, method]).inc();
}

pub fn increment_rate_limit() {
    METRICS.api_request_rate_limit_total.inc();
}

pub fn increment_auth_success() {
    METRICS.auth_success_total.inc();
}

pub fn increment_auth_failure() {
    METRICS.auth_failure_total.inc();
}

pub fn set_database_connections(count: i64) {
    METRICS.database_connections.set(count as f64);
}

pub fn set_redis_connections(count: i64) {
    METRICS.redis_connections.set(count as f64);
}
