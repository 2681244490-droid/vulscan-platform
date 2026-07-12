use config::{Config, Environment, File};
use serde::Deserialize;
use std::env;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    pub jwt_expire_minutes: i64,
    pub jwt_refresh_expire_days: i64,
    pub api_host: String,
    pub api_port: u16,
    pub worker_count: usize,
    pub max_scan_threads: usize,
    pub cors_allowed_origins: Vec<String>,
    pub cors_allowed_methods: Vec<String>,
    pub cors_allowed_headers: Vec<String>,
    pub rate_limit_ip_max_requests: usize,
    pub rate_limit_user_max_requests: usize,
    pub rate_limit_window_seconds: u64,
    pub log_level: String,
    pub metrics_enabled: bool,
    pub scan_engine: ScanEngineConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ScanEngineConfig {
    pub timeout_seconds: u64,
    pub max_concurrent_scans: usize,
    pub retry_attempts: u32,
    pub retry_delay_seconds: u64,
    pub default_plugins: Vec<String>,
}

impl Default for ScanEngineConfig {
    fn default() -> Self {
        ScanEngineConfig {
            timeout_seconds: 300,
            max_concurrent_scans: 10,
            retry_attempts: 3,
            retry_delay_seconds: 5,
            default_plugins: vec![
                "directory_scanner".to_string(),
                "sql_injection_scanner".to_string(),
                "xss_scanner".to_string(),
                "weak_password_scanner".to_string(),
            ],
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, anyhow::Error> {
        let run_mode = env::var("RUN_MODE").unwrap_or_else(|_| "development".to_string());

        let config = Config::builder()
            .add_source(File::with_name("config/default").required(false))
            .add_source(File::with_name(&format!("config/{run_mode}")).required(false))
            .add_source(Environment::default().prefix("APP").separator("__"))
            .set_default("database_url", env::var("POSTGRES_URL").unwrap_or_else(|_| "postgres://admin:postgres@localhost:5432/vulscan".to_string()))?
            .set_default("redis_url", env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379/0".to_string()))?
            .set_default("jwt_secret", env::var("JWT_SECRET").unwrap_or_else(|_| "dev-secret-key-change-in-production".to_string()))?
            .set_default("jwt_expire_minutes", 60)?
            .set_default("jwt_refresh_expire_days", 7)?
            .set_default("api_host", "0.0.0.0")?
            .set_default("api_port", 8080)?
            .set_default("worker_count", 4)?
            .set_default("max_scan_threads", 8)?
            .set_default("cors_allowed_origins", vec!["http://localhost:3000", "http://localhost:3001", "http://localhost:5173"])?
            .set_default("cors_allowed_methods", vec!["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])?
            .set_default("cors_allowed_headers", vec!["Authorization", "Content-Type", "X-Request-ID"])?
            .set_default("rate_limit_ip_max_requests", 100)?
            .set_default("rate_limit_user_max_requests", 1000)?
            .set_default("rate_limit_window_seconds", 60)?
            .set_default("log_level", "info")?
            .set_default("metrics_enabled", true)?
            .set_default("scan_engine.timeout_seconds", 300)?
            .set_default("scan_engine.max_concurrent_scans", 10)?
            .set_default("scan_engine.retry_attempts", 3)?
            .set_default("scan_engine.retry_delay_seconds", 5)?
            .set_default("scan_engine.default_plugins", vec!["directory_scanner", "sql_injection_scanner", "xss_scanner", "weak_password_scanner"])?
            .build()?;

        let app_config: AppConfig = config.try_deserialize().map_err(|e| anyhow::anyhow!("Config error: {}", e))?;
        Ok(app_config)
    }

    pub fn database_pool_size(&self) -> u32 {
        (self.worker_count as u32) * 2 + 1
    }

    pub fn redis_pool_size(&self) -> u32 {
        (self.worker_count as u32) * 2
    }
}
