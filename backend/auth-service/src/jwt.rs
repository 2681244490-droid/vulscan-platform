use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use shared_lib::errors::AppError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    pub role: String,
    pub email: String,
}

#[derive(Clone)]
pub struct JwtService {
    secret: String,
    access_expire_minutes: i64,
    refresh_expire_days: i64,
}

impl JwtService {
    pub fn new(secret: String, access_expire_minutes: i64, refresh_expire_days: i64) -> Self {
        JwtService {
            secret,
            access_expire_minutes,
            refresh_expire_days,
        }
    }

    pub fn generate_access_token(&self, user_id: String, role: &str, email: &str) -> Result<String, AppError> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id,
            exp: (now + Duration::minutes(self.access_expire_minutes)).timestamp(),
            iat: now.timestamp(),
            role: role.to_string(),
            email: email.to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        )
        .map_err(|e| AppError::AuthError(format!("Failed to generate token: {e}")))
    }

    pub fn generate_refresh_token(&self, user_id: String, role: &str, email: &str) -> Result<String, AppError> {
        let now = Utc::now();
        let claims = Claims {
            sub: user_id,
            exp: (now + Duration::days(self.refresh_expire_days)).timestamp(),
            iat: now.timestamp(),
            role: role.to_string(),
            email: email.to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_ref()),
        )
        .map_err(|e| AppError::AuthError(format!("Failed to generate refresh token: {e}")))
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, AppError> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_ref()),
            &Validation::new(Algorithm::HS256),
        )
        .map(|data| data.claims)
        .map_err(|e| AppError::AuthError(format!("Invalid token: {e}")))
    }

    pub fn decode_token(&self, token: &str) -> Result<Claims, AppError> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;

        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_ref()),
            &validation,
        )
        .map(|data| data.claims)
        .map_err(|e| AppError::AuthError(format!("Failed to decode token: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn test_generate_and_validate_token() {
        let jwt_service = JwtService::new("test-secret-key".to_string(), 15, 7);
        let user_id = Uuid::new_v4().to_string();

        let token = jwt_service.generate_access_token(user_id.clone(), "admin", "test@example.com").unwrap();
        let claims = jwt_service.validate_token(&token).unwrap();

        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.email, "test@example.com");
    }

    #[test]
    fn test_invalid_token() {
        let jwt_service = JwtService::new("test-secret-key".to_string(), 15, 7);

        let result = jwt_service.validate_token("invalid-token");
        assert!(matches!(result, Err(AppError::AuthError(_))));
    }
}
