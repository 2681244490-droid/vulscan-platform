use actix_web::{web, App, HttpServer, middleware::Logger};
use sqlx::postgres::PgPoolOptions;
use tracing::info;

use auth_service::{AuthService, AuthStore, JwtService, RbacService};
use web_api::{
    config::AppConfig,
    middleware::{configure_cors, ErrorHandler, RateLimiter},
    routes::configure_routes,
    services::{
        AuthServices, DashboardServices, DashboardStore, ReportServices, ReportStore, ScanServices,
        ScanStore, TargetServices, TargetStore, VulnerabilityServices, VulnerabilityStore,
    },
};

#[actix_web::main]
async fn main() -> Result<(), anyhow::Error> {
    dotenvy::dotenv().ok();
    let config = AppConfig::load()?;

    shared_lib::logging::init_logging();

    info!("Starting Vulnerability Scanning Platform API");
    info!("Loading configuration from environment");

    let pool = PgPoolOptions::new()
        .max_connections(config.database_pool_size())
        .connect(&config.database_url)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to database: {e}"))?;

    let auth_store = AuthStore::new(pool.clone());
    let jwt_service = JwtService::new(
        config.jwt_secret.clone(),
        config.jwt_expire_minutes,
        config.jwt_refresh_expire_days,
    );
    let auth_service = AuthService::new(auth_store, jwt_service.clone());
    let rbac_service = RbacService::new(pool.clone());

    rbac_service.init_default_permissions().await?;

    let auth_services = AuthServices {
        auth_service,
        rbac_service,
    };

    let target_store = TargetStore::new(pool.clone());
    let target_services = TargetServices { target_store };

    let scan_store = ScanStore::new(pool.clone());
    let scan_services = ScanServices { scan_store };

    let vuln_store = VulnerabilityStore::new(pool.clone());
    let vuln_services = VulnerabilityServices { vuln_store };

    let dashboard_store = DashboardStore::new(pool.clone());
    let dashboard_services = DashboardServices { dashboard_store };

    let report_store = ReportStore::new(pool);
    let report_services = ReportServices { report_store };

    let rate_limiter = RateLimiter::new(
        config.rate_limit_ip_max_requests,
        config.rate_limit_user_max_requests,
        config.rate_limit_window_seconds,
    );

    let allowed_origins = config.cors_allowed_origins.clone();
    let allowed_methods = config.cors_allowed_methods.clone();
    let allowed_headers = config.cors_allowed_headers.clone();

    let server = HttpServer::new(move || {
        let cors = configure_cors(allowed_origins.clone(), allowed_methods.clone(), allowed_headers.clone());
        App::new()
            .wrap(cors)
            .wrap(rate_limiter.clone())
            .wrap(Logger::default())
            .wrap(web_api::middleware::JwtAuth::new(jwt_service.clone()))
            .wrap(ErrorHandler)
            .app_data(web::Data::new(auth_services.clone()))
            .app_data(web::Data::new(target_services.clone()))
            .app_data(web::Data::new(scan_services.clone()))
            .app_data(web::Data::new(vuln_services.clone()))
            .app_data(web::Data::new(report_services.clone()))
            .app_data(web::Data::new(dashboard_services.clone()))
            .configure(configure_routes)
    })
    .bind((config.api_host.clone(), config.api_port))?
    .run();

    info!("Server running on http://{}:{}", config.api_host, config.api_port);

    server.await?;

    Ok(())
}
