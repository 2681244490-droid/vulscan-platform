use crate::jwt::JwtService;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};

#[test]
fn test_generate_access_token() {
    let jwt_service = JwtService::new(
        "test-secret-key-very-long-to-be-secure".to_string(),
        Duration::minutes(15),
        Duration::hours(24),
    );

    let token = jwt_service.generate_access_token("user123", "admin", "test@example.com");
    assert!(token.is_ok());

    let token_str = token.unwrap();
    assert!(!token_str.is_empty());
}

#[test]
fn test_generate_refresh_token() {
    let jwt_service = JwtService::new(
        "test-secret-key-very-long-to-be-secure".to_string(),
        Duration::minutes(15),
        Duration::hours(24),
    );

    let token = jwt_service.generate_refresh_token("user123");
    assert!(token.is_ok());

    let token_str = token.unwrap();
    assert!(!token_str.is_empty());
}

#[test]
fn test_validate_token_valid() {
    let jwt_service = JwtService::new(
        "test-secret-key-very-long-to-be-secure".to_string(),
        Duration::minutes(15),
        Duration::hours(24),
    );

    let token = jwt_service.generate_access_token("user123", "admin", "test@example.com").unwrap();
    let claims = jwt_service.validate_token(&token);

    assert!(claims.is_ok());
    let claims = claims.unwrap();
    assert_eq!(claims.sub, "user123");
    assert_eq!(claims.role, "admin");
    assert_eq!(claims.email, "test@example.com");
}

#[test]
fn test_validate_token_invalid_signature() {
    let jwt_service = JwtService::new(
        "test-secret-key-very-long-to-be-secure".to_string(),
        Duration::minutes(15),
        Duration::hours(24),
    );

    let invalid_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let claims = jwt_service.validate_token(invalid_token);

    assert!(claims.is_err());
}

#[test]
fn test_validate_token_expired() {
    let jwt_service = JwtService::new(
        "test-secret-key-very-long-to-be-secure".to_string(),
        Duration::seconds(-1),
        Duration::hours(24),
    );

    let token = jwt_service.generate_access_token("user123", "admin", "test@example.com").unwrap();
    std::thread::sleep(std::time::Duration::from_secs(1));

    let claims = jwt_service.validate_token(&token);
    assert!(claims.is_err());
}

#[test]
fn test_validate_refresh_token() {
    let jwt_service = JwtService::new(
        "test-secret-key-very-long-to-be-secure".to_string(),
        Duration::minutes(15),
        Duration::hours(24),
    );

    let token = jwt_service.generate_refresh_token("user123").unwrap();
    let user_id = jwt_service.validate_refresh_token(&token);

    assert!(user_id.is_ok());
    assert_eq!(user_id.unwrap(), "user123");
}
