use shared_lib::errors::AppError;
use shared_lib::models::UserRole;
use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

#[derive(Clone)]
pub struct RbacService {
    pool: PgPool,
}

impl RbacService {
    pub fn new(pool: PgPool) -> Self {
        RbacService { pool }
    }

    pub async fn get_user_permissions(&self, role: &UserRole) -> Result<HashSet<String>, AppError> {
        let role_str = role.to_string();

        let permissions: Vec<(String,)> = sqlx::query_as(
            r#"
            SELECT p.name FROM permissions p
            JOIN role_permissions rp ON p.id = rp.permission_id
            WHERE rp.role = $1
            "#,
        )
        .bind(role_str)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to get permissions: {e}")))?;

        Ok(permissions.into_iter().map(|p| p.0).collect())
    }

    pub async fn has_permission(&self, role: &UserRole, permission: &str) -> Result<bool, AppError> {
        let permissions = self.get_user_permissions(role).await?;
        Ok(permissions.contains(permission))
    }

    pub async fn require_permission(&self, role: &UserRole, permission: &str) -> Result<(), AppError> {
        if !self.has_permission(role, permission).await? {
            return Err(AppError::PermissionDenied);
        }
        Ok(())
    }

    pub async fn init_default_permissions(&self) -> Result<(), AppError> {
        let permissions = vec![
            ("scan:create", "Create scan tasks"),
            ("scan:read", "Read scan tasks"),
            ("scan:update", "Update scan tasks"),
            ("scan:delete", "Delete scan tasks"),
            ("target:create", "Create targets"),
            ("target:read", "Read targets"),
            ("target:update", "Update targets"),
            ("target:delete", "Delete targets"),
            ("vulnerability:read", "Read vulnerabilities"),
            ("vulnerability:delete", "Delete vulnerabilities"),
            ("report:read", "Read reports"),
            ("report:delete", "Delete reports"),
            ("user:manage", "Manage users"),
            ("system:admin", "System administration"),
        ];

        for (name, description) in permissions {
            let exists: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM permissions WHERE name = $1")
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| AppError::DatabaseError(format!("Failed to check permission: {e}")))?;

            if exists.is_none() {
                let id = Uuid::new_v4();
                sqlx::query(
                    "INSERT INTO permissions (id, name, description, created_at) VALUES ($1, $2, $3, NOW())",
                )
                .bind(id.to_string())
                .bind(name)
                .bind(description)
                .execute(&self.pool)
                .await
                .map_err(|e| AppError::DatabaseError(format!("Failed to insert permission: {e}")))?;
            }
        }

        self.init_role_permissions().await?;

        Ok(())
    }

    async fn init_role_permissions(&self) -> Result<(), AppError> {
        let admin_permissions = vec![
            "scan:create", "scan:read", "scan:update", "scan:delete",
            "target:create", "target:read", "target:update", "target:delete",
            "vulnerability:read", "vulnerability:delete",
            "report:read", "report:delete",
            "user:manage", "system:admin",
        ];

        let user_permissions = vec![
            "scan:create", "scan:read", "scan:update", "scan:delete",
            "target:create", "target:read", "target:update", "target:delete",
            "vulnerability:read",
            "report:read",
        ];

        let scanner_permissions = vec![
            "scan:read",
            "vulnerability:read",
        ];

        self.assign_role_permissions("admin", &admin_permissions).await?;
        self.assign_role_permissions("user", &user_permissions).await?;
        self.assign_role_permissions("scanner", &scanner_permissions).await?;

        Ok(())
    }

    async fn assign_role_permissions(&self, role: &str, permissions: &[&str]) -> Result<(), AppError> {
        for permission_name in permissions {
            let permission_id: Option<(String,)> = sqlx::query_as("SELECT id FROM permissions WHERE name = $1")
                .bind(*permission_name)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| AppError::DatabaseError(format!("Failed to get permission id: {e}")))?;

            if let Some((permission_id,)) = permission_id {
                let exists: Option<(i32,)> = sqlx::query_as(
                    "SELECT 1 FROM role_permissions WHERE role = $1 AND permission_id = $2",
                )
                .bind(role)
                .bind(&permission_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| AppError::DatabaseError(format!("Failed to check role permission: {e}")))?;

                if exists.is_none() {
                    sqlx::query(
                        "INSERT INTO role_permissions (role, permission_id) VALUES ($1, $2)",
                    )
                    .bind(role)
                    .bind(&permission_id)
                    .execute(&self.pool)
                    .await
                    .map_err(|e| AppError::DatabaseError(format!("Failed to insert role permission: {e}")))?;
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_has_permission() {
        let pool = sqlx::PgPool::connect("postgres://admin:postgres@localhost:5432/vulscan_test")
            .await
            .unwrap();

        let rbac = RbacService::new(pool);

        let result = rbac.has_permission(&UserRole::Admin, "scan:create").await;
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
