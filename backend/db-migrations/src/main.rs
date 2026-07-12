use anyhow::{Context, Result};
use sqlx::postgres::PgPoolOptions;
use std::env;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    let database_url = env::var("POSTGRES_URL")
        .context("POSTGRES_URL environment variable not set")?;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .context("Failed to connect to PostgreSQL database")?;

    run_migrations(&pool).await?;
    println!("PostgreSQL migrations completed successfully");
    Ok(())
}

async fn run_migrations(pool: &sqlx::PgPool) -> Result<()> {
    sqlx::query("DROP TABLE IF EXISTS refresh_tokens CASCADE").execute(pool).await?;
    sqlx::query("DROP TABLE IF EXISTS reports CASCADE").execute(pool).await?;
    sqlx::query("DROP TABLE IF EXISTS vulnerabilities CASCADE").execute(pool).await?;
    sqlx::query("DROP TABLE IF EXISTS scan_tasks CASCADE").execute(pool).await?;
    sqlx::query("DROP TABLE IF EXISTS targets CASCADE").execute(pool).await?;
    sqlx::query("DROP TABLE IF EXISTS role_permissions CASCADE").execute(pool).await?;
    sqlx::query("DROP TABLE IF EXISTS permissions CASCADE").execute(pool).await?;
    sqlx::query("DROP TABLE IF EXISTS sys_user CASCADE").execute(pool).await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS sys_user (
            id VARCHAR(36) NOT NULL PRIMARY KEY,
            username VARCHAR(64) NOT NULL UNIQUE,
            email VARCHAR(255) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(32) NOT NULL DEFAULT 'user',
            is_active BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await
    .context("Failed to create sys_user table")?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS permissions (
            id VARCHAR(36) NOT NULL PRIMARY KEY,
            name VARCHAR(128) NOT NULL UNIQUE,
            description TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(pool)
    .await
    .context("Failed to create permissions table")?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS role_permissions (
            role VARCHAR(32) NOT NULL,
            permission_id VARCHAR(36) NOT NULL,
            PRIMARY KEY (role, permission_id),
            CONSTRAINT fk_role_permissions_permission FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .context("Failed to create role_permissions table")?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS targets (
            id VARCHAR(36) NOT NULL PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL,
            name VARCHAR(256) NOT NULL,
            url VARCHAR(1024) NOT NULL,
            description TEXT,
            status VARCHAR(32) NOT NULL DEFAULT 'active',
            scan_frequency VARCHAR(32),
            last_scan_at TIMESTAMPTZ NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_targets_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .context("Failed to create targets table")?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS scan_tasks (
            id VARCHAR(36) NOT NULL PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL,
            target_id VARCHAR(36) NOT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'pending',
            scan_type VARCHAR(32) NOT NULL DEFAULT 'full',
            priority VARCHAR(32) NOT NULL DEFAULT 'medium',
            plugins JSON NOT NULL,
            progress INT NOT NULL DEFAULT 0,
            started_at TIMESTAMPTZ NULL,
            completed_at TIMESTAMPTZ NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_scan_tasks_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE,
            CONSTRAINT fk_scan_tasks_target FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .context("Failed to create scan_tasks table")?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id VARCHAR(36) NOT NULL PRIMARY KEY,
            task_id VARCHAR(36) NOT NULL,
            target_id VARCHAR(36) NOT NULL,
            plugin_name VARCHAR(128) NOT NULL,
            severity VARCHAR(32) NOT NULL,
            title VARCHAR(256) NOT NULL,
            description TEXT NOT NULL,
            payload TEXT,
            proof TEXT,
            remediation TEXT NOT NULL,
            cve VARCHAR(64),
            cvss_score DOUBLE PRECISION,
            status VARCHAR(32) NOT NULL DEFAULT 'open',
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_vuln_task FOREIGN KEY (task_id) REFERENCES scan_tasks(id) ON DELETE CASCADE,
            CONSTRAINT fk_vuln_target FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .context("Failed to create vulnerabilities table")?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS reports (
            id VARCHAR(36) NOT NULL PRIMARY KEY,
            task_id VARCHAR(36) NOT NULL,
            user_id VARCHAR(36) NOT NULL,
            status VARCHAR(32) NOT NULL DEFAULT 'generating',
            summary JSON NOT NULL,
            template VARCHAR(64) DEFAULT 'technical',
            generated_at TIMESTAMPTZ NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_reports_task FOREIGN KEY (task_id) REFERENCES scan_tasks(id) ON DELETE CASCADE,
            CONSTRAINT fk_reports_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .context("Failed to create reports table")?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id VARCHAR(36) NOT NULL PRIMARY KEY,
            user_id VARCHAR(36) NOT NULL,
            token VARCHAR(512) NOT NULL UNIQUE,
            expires_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES sys_user(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(pool)
    .await
    .context("Failed to create refresh_tokens table")?;

    let indexes = [
        ("idx_targets_user_id", "CREATE INDEX IF NOT EXISTS idx_targets_user_id ON targets(user_id)"),
        ("idx_targets_status", "CREATE INDEX IF NOT EXISTS idx_targets_status ON targets(status)"),
        ("idx_scan_tasks_user_id", "CREATE INDEX IF NOT EXISTS idx_scan_tasks_user_id ON scan_tasks(user_id)"),
        ("idx_scan_tasks_target_id", "CREATE INDEX IF NOT EXISTS idx_scan_tasks_target_id ON scan_tasks(target_id)"),
        ("idx_scan_tasks_status", "CREATE INDEX IF NOT EXISTS idx_scan_tasks_status ON scan_tasks(status)"),
        ("idx_vulnerabilities_task_id", "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_task_id ON vulnerabilities(task_id)"),
        ("idx_vulnerabilities_target_id", "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_target_id ON vulnerabilities(target_id)"),
        ("idx_vulnerabilities_severity", "CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities(severity)"),
        ("idx_reports_task_id", "CREATE INDEX IF NOT EXISTS idx_reports_task_id ON reports(task_id)"),
        ("idx_reports_user_id", "CREATE INDEX IF NOT EXISTS idx_reports_user_id ON reports(user_id)"),
        ("idx_refresh_tokens_user_id", "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id)"),
        ("idx_refresh_tokens_token", "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token)"),
    ];
    for (name, idx) in indexes {
        sqlx::query(idx)
            .execute(pool)
            .await
            .context(format!("Failed to create index {}", name))?;
    }

    Ok(())
}
