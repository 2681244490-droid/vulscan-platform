use actix_cors::Cors;
use actix_web::{
    body::MessageBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    http::{header, Method},
    Error as ActixError, HttpMessage,
};
use auth_service::jwt::JwtService;
use shared_lib::errors::{AppError, ErrorResponse};
use shared_lib::logging::log_rate_limit;
use shared_lib::metrics;
use std::{
    collections::HashMap,
    future::{ready, Future, Ready},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

pub fn configure_cors(allowed_origins: Vec<String>, allowed_methods: Vec<String>, allowed_headers: Vec<String>) -> Cors {
    let mut cors = Cors::default();

    if allowed_origins.contains(&"*".to_string()) {
        cors = cors.allow_any_origin();
    } else {
        for origin in allowed_origins {
            cors = cors.allowed_origin(&origin);
        }
    }

    let methods: Vec<Method> = allowed_methods
        .iter()
        .filter_map(|m| Method::try_from(m.as_str()).ok())
        .collect();
    if !methods.is_empty() {
        cors = cors.allowed_methods(methods);
    }

    for header in allowed_headers {
        if let Ok(h) = header::HeaderName::try_from(header.as_str()) {
            cors = cors.allowed_header(h);
        }
    }

    cors.supports_credentials()
        .max_age(3600)
}

#[derive(Clone)]
pub struct JwtAuth {
    jwt_service: Arc<JwtService>,
}

impl JwtAuth {
    pub fn new(jwt_service: JwtService) -> Self {
        JwtAuth {
            jwt_service: Arc::new(jwt_service),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for JwtAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Transform = JwtAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtAuthMiddleware {
            service,
            jwt_service: self.jwt_service.clone(),
        }))
    }
}

pub struct JwtAuthMiddleware<S> {
    service: S,
    jwt_service: Arc<JwtService>,
}

impl<S, B> Service<ServiceRequest> for JwtAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        ctx: &mut core::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let jwt_service = self.jwt_service.clone();

        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string());

        // 在传递给下游 service 之前就设置 Claims
        if let Some(header_value) = auth_header {
            if header_value.starts_with("Bearer ") {
                let token = header_value.trim_start_matches("Bearer ").trim();
                if let Ok(claims) = jwt_service.validate_token(token) {
                    req.extensions_mut().insert(claims);
                }
            }
        }

        Box::pin(self.service.call(req))
    }
}

#[derive(Clone)]
pub struct Rbac {
    required_permission: String,
}

impl Rbac {
    pub fn new(permission: impl Into<String>) -> Self {
        Rbac {
            required_permission: permission.into(),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for Rbac
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Transform = RbacMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RbacMiddleware {
            service,
            required_permission: self.required_permission.clone(),
        }))
    }
}

pub struct RbacMiddleware<S> {
    service: S,
    required_permission: String,
}

impl<S, B> Service<ServiceRequest> for RbacMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        ctx: &mut core::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let permission = self.required_permission.clone();
        let fut = self.service.call(req);

        Box::pin(async move {
            let req = fut.await?;
            let has_permission = req
                .request()
                .extensions()
                .get::<auth_service::jwt::Claims>()
                .map(|claims| {
                    claims.role == "admin" || claims.role == "scanner"
                })
                .unwrap_or(false);

            if !has_permission && permission != "public" {
                return Err(AppError::PermissionDenied.into());
            }

            Ok(req)
        })
    }
}

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<RateLimiterInner>,
}

struct RateLimiterInner {
    ip_limits: Mutex<HashMap<String, (usize, Instant)>>,
    user_limits: Mutex<HashMap<String, (usize, Instant)>>,
    ip_max_requests: usize,
    user_max_requests: usize,
    window_seconds: u64,
}

impl RateLimiter {
    pub fn new(ip_max_requests: usize, user_max_requests: usize, window_seconds: u64) -> Self {
        RateLimiter {
            inner: Arc::new(RateLimiterInner {
                ip_limits: Mutex::new(HashMap::new()),
                user_limits: Mutex::new(HashMap::new()),
                ip_max_requests,
                user_max_requests,
                window_seconds,
            }),
        }
    }

    fn check_ip(&self, ip: &str) -> bool {
        let mut limits = match self.inner.ip_limits.lock() {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        let now = Instant::now();
        let window = Duration::from_secs(self.inner.window_seconds);

        let (count, start) = limits.entry(ip.to_string()).or_insert((0, now));

        if now.duration_since(*start) > window {
            *count = 1;
            *start = now;
            true
        } else if *count >= self.inner.ip_max_requests {
            false
        } else {
            *count += 1;
            true
        }
    }

    fn check_user(&self, user_id: &str) -> bool {
        let mut limits = match self.inner.user_limits.lock() {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        let now = Instant::now();
        let window = Duration::from_secs(self.inner.window_seconds);

        let (count, start) = limits.entry(user_id.to_string()).or_insert((0, now));

        if now.duration_since(*start) > window {
            *count = 1;
            *start = now;
            true
        } else if *count >= self.inner.user_max_requests {
            false
        } else {
            *count += 1;
            true
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Transform = RateLimitMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RateLimitMiddleware {
            service,
            limiter: self.clone(),
        }))
    }
}

pub struct RateLimitMiddleware<S> {
    service: S,
    limiter: RateLimiter,
}

impl<S, B> Service<ServiceRequest> for RateLimitMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<B>;
    type Error = ActixError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        ctx: &mut core::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let ip = req
            .connection_info()
            .realip_remote_addr()
            .unwrap_or("unknown")
            .to_string();
        let user_id = req
            .headers()
            .get("X-User-ID")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("anonymous")
            .to_string();

        let path = req.path().to_string();
        let limiter = self.limiter.clone();
        let fut = self.service.call(req);

        Box::pin(async move {
            if !limiter.check_ip(&ip) {
                log_rate_limit(&ip, &path);
                metrics::increment_rate_limit();
                return Err(AppError::RateLimitExceeded.into());
            }

            if !limiter.check_user(&user_id) {
                log_rate_limit(&user_id, &path);
                metrics::increment_rate_limit();
                return Err(AppError::RateLimitExceeded.into());
            }

            fut.await
        })
    }
}

#[derive(Clone)]
pub struct ErrorHandler;

impl<S, B> Transform<S, ServiceRequest> for ErrorHandler
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = ActixError;
    type Transform = ErrorHandlerMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(ErrorHandlerMiddleware { service }))
    }
}

pub struct ErrorHandlerMiddleware<S> {
    service: S,
}

type BoxBody = actix_web::body::BoxBody;

impl<S, B> Service<ServiceRequest> for ErrorHandlerMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = ActixError>,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<BoxBody>;
    type Error = ActixError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        ctx: &mut core::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fut = self.service.call(req);

        Box::pin(async move {
            match fut.await {
                Ok(res) => Ok(res.map_into_boxed_body()),
                Err(err) => {
                    let error_response = if let Some(app_error) = err.as_error::<AppError>() {
                        ErrorResponse::from_error(app_error)
                    } else {
                        ErrorResponse {
                            error: "error".to_string(),
                            message: "Internal server error".to_string(),
                            code: 500,
                            timestamp: chrono::Utc::now().to_rfc3339(),
                        }
                    };
                    Err(actix_web::error::ErrorInternalServerError(error_response))
                }
            }
        })
    }
}

pub fn logger_middleware() -> actix_web::middleware::Logger {
    actix_web::middleware::Logger::default()
}
