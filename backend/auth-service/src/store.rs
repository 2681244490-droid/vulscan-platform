use chrono::{DateTime, Utc};
use shared_lib::errors::AppError;
use shared_lib::models::{RefreshToken, User, UserRole};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct UserRow {
    id: String,
    username: String,
    email: String,
    password_hash: String,
    role: String,
    is_active: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl UserRow {
    fn into_user(self) -> User {
        User {
            id: self.id,
            username: self.username,
            email: self.email,
            password_hash: self.password_hash,
            role: match self.role.as_str() {
                "admin" => UserRole::Admin,
                "scanner" => UserRole::Scanner,
                _ => UserRole::User,
            },
            is_active: self.is_active,
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

#[derive(Clone)]
pub struct AuthStore {
    pool: PgPool,
}

impl AuthStore {
    pub fn new(pool: PgPool) -> Self {
        AuthStore { pool }
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        let row: Option<UserRow> = sqlx::query_as(
            r#"
            SELECT id, username, email, password_hash, role, is_active, created_at, updated_at
            FROM sys_user
            WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to get user by email: {e}")))?;

        Ok(row.map(|r| r.into_user()))
    }

    pub async fn get_user_by_id(&self, user_id: String) -> Result<Option<User>, AppError> {
        let row: Option<UserRow> = sqlx::query_as(
            r#"
            SELECT id, username, email, password_hash, role, is_active, created_at, updated_at
            FROM sys_user
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to get user by id: {e}")))?;

        Ok(row.map(|r| r.into_user()))
    }

    pub async fn create_user(&self, username: &str, email: &str, password_hash: &str) -> Result<User, AppError> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let exists: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM sys_user WHERE email = $1 OR username = $2")
            .bind(email)
            .bind(username)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to check user existence: {e}")))?;

        if exists.is_some() {
            return Err(AppError::Conflict("User already exists".to_string()));
        }

        sqlx::query(
            r#"
            INSERT INTO sys_user (id, username, email, password_hash, role, is_active, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(&id)
        .bind(username)
        .bind(email)
        .bind(password_hash)
        .bind("user")
        .bind(true)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to create user: {e}")))?;

        let row: UserRow = sqlx::query_as(
            r#"
            SELECT id, username, email, password_hash, role, is_active, created_at, updated_at
            FROM sys_user
            WHERE id = $1
            "#,
        )
        .bind(&id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to fetch created user: {e}")))?;

        Ok(row.into_user())
    }

    pub async fn save_refresh_token(&self, user_id: String, token: &str, expires_at: DateTime<Utc>) -> Result<(), AppError> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO refresh_tokens (id, user_id, token, expires_at, created_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (token) DO UPDATE SET expires_at = EXCLUDED.expires_at, created_at = EXCLUDED.created_at
            "#,
        )
        .bind(&id)
        .bind(&user_id)
        .bind(token)
        .bind(expires_at)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to save refresh token: {e}")))?;

        Ok(())
    }

    pub async fn get_refresh_token(&self, token: &str) -> Result<Option<RefreshToken>, AppError> {
        let refresh_token: Option<RefreshToken> = sqlx::query_as(
            r#"
            SELECT id, user_id, token, expires_at, created_at
            FROM refresh_tokens
            WHERE token = $1 AND expires_at > NOW()
            "#,
        )
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to get refresh token: {e}")))?;

        Ok(refresh_token)
    }

    pub async fn revoke_refresh_token(&self, token: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM refresh_tokens WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to revoke refresh token: {e}")))?;

        Ok(())
    }

    pub async fn revoke_all_user_tokens(&self, user_id: String) -> Result<(), AppError> {
        sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
            .bind(&user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to revoke user tokens: {e}")))?;

        Ok(())
    }
}
