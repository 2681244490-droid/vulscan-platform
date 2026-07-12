use chrono::{Duration, Utc};
use shared_lib::errors::AppError;
use shared_lib::models::User;
use shared_lib::schemas::{LoginRequest, LoginResponse, RegisterRequest, RefreshTokenRequest, UserResponse};
use shared_lib::utils::{hash_password, verify_password};

use crate::jwt::JwtService;
use crate::store::AuthStore;

#[derive(Clone)]
pub struct AuthService {
    store: AuthStore,
    jwt_service: JwtService,
}

impl AuthService {
    pub fn new(store: AuthStore, jwt_service: JwtService) -> Self {
        AuthService { store, jwt_service }
    }

    pub async fn login(&self, request: LoginRequest) -> Result<LoginResponse, AppError> {
        let user = self.store.get_user_by_email(&request.email).await?
            .ok_or_else(|| AppError::AuthError("Invalid email or password".to_string()))?;

        if !user.is_active {
            return Err(AppError::AuthError("User account is not active".to_string()));
        }

        let is_valid = verify_password(&request.password, &user.password_hash)
            .map_err(|e| AppError::AuthError(format!("Failed to verify password: {e}")))?;

        if !is_valid {
            return Err(AppError::AuthError("Invalid email or password".to_string()));
        }

        let access_token = self.jwt_service.generate_access_token(user.id.clone(), &user.role.to_string(), &user.email)?;
        let refresh_token = self.jwt_service.generate_refresh_token(user.id.clone(), &user.role.to_string(), &user.email)?;

        let refresh_expire_at = Utc::now() + Duration::days(7);
        self.store.save_refresh_token(user.id.clone(), &refresh_token, refresh_expire_at).await?;

        Ok(LoginResponse {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: 60 * 60,
            user: self.map_user_to_response(&user),
        })
    }

    pub async fn register(&self, request: RegisterRequest) -> Result<UserResponse, AppError> {
        let password_hash = hash_password(&request.password)
            .map_err(|e| AppError::ValidationError(format!("Failed to hash password: {e}")))?;

        let user = self.store.create_user(&request.username, &request.email, &password_hash).await?;

        Ok(self.map_user_to_response(&user))
    }

    pub async fn refresh_token(&self, request: RefreshTokenRequest) -> Result<LoginResponse, AppError> {
        let refresh_token = self.store.get_refresh_token(&request.refresh_token).await?
            .ok_or_else(|| AppError::AuthError("Invalid or expired refresh token".to_string()))?;

        let user = self.store.get_user_by_id(refresh_token.user_id).await?
            .ok_or_else(|| AppError::AuthError("User not found".to_string()))?;

        if !user.is_active {
            return Err(AppError::AuthError("User account is not active".to_string()));
        }

        let access_token = self.jwt_service.generate_access_token(user.id.clone(), &user.role.to_string(), &user.email)?;
        let new_refresh_token = self.jwt_service.generate_refresh_token(user.id.clone(), &user.role.to_string(), &user.email)?;

        self.store.revoke_refresh_token(&request.refresh_token).await?;

        let refresh_expire_at = Utc::now() + Duration::days(7);
        self.store.save_refresh_token(user.id.clone(), &new_refresh_token, refresh_expire_at).await?;

        Ok(LoginResponse {
            access_token,
            refresh_token: new_refresh_token,
            token_type: "Bearer".to_string(),
            expires_in: 60 * 60,
            user: self.map_user_to_response(&user),
        })
    }

    pub async fn logout(&self, refresh_token: &str) -> Result<(), AppError> {
        self.store.revoke_refresh_token(refresh_token).await
    }

    pub async fn logout_all(&self, user_id: String) -> Result<(), AppError> {
        self.store.revoke_all_user_tokens(user_id).await
    }

    fn map_user_to_response(&self, user: &User) -> UserResponse {
        UserResponse {
            id: user.id.clone(),
            username: user.username.clone(),
            email: user.email.clone(),
            role: user.role.to_string(),
            is_active: user.is_active,
            created_at: user.created_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_login_success() {
        let pool = sqlx::MySqlPool::connect("mysql://admin:password@localhost:3306/vulscan_test")
            .await
            .unwrap();

        let store = AuthStore::new(pool);
        let jwt_service = JwtService::new("test-secret".to_string(), 15, 7);
        let auth_service = AuthService::new(store, jwt_service);

        let request = LoginRequest {
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        };

        let result = auth_service.login(request).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_login_invalid_password() {
        let pool = sqlx::MySqlPool::connect("mysql://admin:password@localhost:3306/vulscan_test")
            .await
            .unwrap();

        let store = AuthStore::new(pool);
        let jwt_service = JwtService::new("test-secret".to_string(), 15, 7);
        let auth_service = AuthService::new(store, jwt_service);

        let request = LoginRequest {
            email: "test@example.com".to_string(),
            password: "wrongpassword".to_string(),
        };

        let result = auth_service.login(request).await;
        assert!(matches!(result, Err(AppError::AuthError(_))));
    }
}
