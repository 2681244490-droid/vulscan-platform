use std::sync::Arc;

use anyhow::Context;
use reqwest::Client;
use sqlx::postgres::PgPool;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use scanner_engine::{
    DefaultTargetValidator, SqlInjectionDetector, SensitiveFileDetector, TargetManager,
    XssDetector, Detector,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().init();

    info!("Starting Scanner Engine (daemon mode)...");

    let database_url = std::env::var("POSTGRES_URL")
        .unwrap_or_else(|_| "postgres://admin:postgres@localhost:5432/vulscan".to_string());
    let pool = PgPool::connect(&database_url)
        .await
        .context("Failed to connect to PostgreSQL")?;
    info!("Connected to PostgreSQL");

    let redis_url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://localhost:6379/0".to_string());
    let redis_client = redis::Client::open(redis_url.as_str())
        .context("Failed to create Redis client")?;
    let redis_conn = redis_client
        .get_connection_manager()
        .await
        .context("Failed to get Redis connection manager")?;
    info!("Connected to Redis");

    let http_client = Arc::new(Client::new());
    let validator = Arc::new(DefaultTargetValidator::new(http_client.clone()));
    let target_manager = Arc::new(TargetManager::new(validator, http_client.clone()));

    let detectors: Vec<Arc<dyn Detector + 'static>> = vec![
        Arc::new(SqlInjectionDetector::new(http_client.clone())?),
        Arc::new(XssDetector::new(http_client.clone())?),
        Arc::new(SensitiveFileDetector::new(http_client.clone())?),
    ];

    info!(
        "Loaded {} detectors: {}",
        detectors.len(),
        detectors
            .iter()
            .map(|d| d.name().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("Received shutdown signal");
        let _ = shutdown_tx.send(()).await;
    });

    let queue_name = "scan_tasks";
    let poll_interval = std::time::Duration::from_secs(3);

    info!(
        "Scanner engine daemon started, polling queue '{}' every {:?}",
        queue_name, poll_interval
    );

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("Scanner engine shutting down...");
                break;
            }
            _ = tokio::time::sleep(poll_interval) => {
                let message: Option<String> = redis::cmd("LPOP")
                    .arg(queue_name)
                    .query_async::<_, Option<String>>(&mut redis_conn.clone())
                    .await
                    .unwrap_or(None);

                if let Some(msg_json) = message {
                    match serde_json::from_str::<ScanTaskMessage>(&msg_json) {
                        Ok(task_msg) => {
                            info!(
                                "Received scan task: {} (target: {}, user: {})",
                                task_msg.task_id, task_msg.target_id, task_msg.user_id
                            );

                            let target_url = match get_target_url(&pool, &task_msg.target_id).await {
                                Ok(url) => url,
                                Err(e) => {
                                    error!("Failed to get target URL for {}: {}", task_msg.target_id, e);
                                    let _ = update_task_status(&pool, &task_msg.task_id, "failed", 0).await;
                                    continue;
                                }
                            };

                            if let Err(e) = update_task_status(&pool, &task_msg.task_id, "scanning", 5).await {
                                error!("Failed to update task status to scanning: {}", e);
                            }

                            match scan_single_url(
                                &target_manager,
                                &detectors,
                                &target_url,
                                &task_msg.target_id,
                                &pool,
                                &task_msg.task_id,
                            )
                            .await
                            {
                                Ok(vulnerabilities) => {
                                    info!(
                                        "Scan completed for task {}, found {} vulnerabilities",
                                        task_msg.task_id,
                                        vulnerabilities.len()
                                    );

                                    for vuln in &vulnerabilities {
                                        if let Err(e) =
                                            save_vulnerability(&pool, &task_msg.task_id, &task_msg.target_id, vuln)
                                                .await
                                        {
                                            error!("Failed to save vulnerability: {}", e);
                                        }
                                    }

                                    if let Err(e) =
                                        update_task_status(&pool, &task_msg.task_id, "completed", 100).await
                                    {
                                        error!("Failed to update task status to completed: {}", e);
                                    }

                                    if let Err(e) =
                                        update_target_last_scan(&pool, &task_msg.target_id).await
                                    {
                                        error!("Failed to update target last_scan_at: {}", e);
                                    }
                                }
                                Err(e) => {
                                    error!("Scan failed for task {}: {}", task_msg.task_id, e);
                                    let _ =
                                        update_task_status(&pool, &task_msg.task_id, "failed", 0).await;
                                }
                            }
                        }
                        Err(e) => {
                            error!("Failed to parse task message '{}': {}", msg_json, e);
                        }
                    }
                }
            }
        }
    }

    info!("Scanner engine stopped");
    Ok(())
}

#[derive(serde::Deserialize)]
struct ScanTaskMessage {
    task_id: String,
    user_id: String,
    target_id: String,
}

async fn get_target_url(pool: &PgPool, target_id: &str) -> anyhow::Result<String> {
    let url: Option<String> =
        sqlx::query_scalar("SELECT url FROM targets WHERE id = $1")
            .bind(target_id)
            .fetch_optional(pool)
            .await?;

    url.ok_or_else(|| anyhow::anyhow!("Target not found: {}", target_id))
}

async fn update_target_last_scan(pool: &PgPool, target_id: &str) -> anyhow::Result<()> {
    let now = chrono::Utc::now();
    sqlx::query("UPDATE targets SET updated_at = $1 WHERE id = $2")
        .bind(now)
        .bind(target_id)
        .execute(pool)
        .await?;
    Ok(())
}

async fn update_task_status(
    pool: &PgPool,
    task_id: &str,
    status: &str,
    progress: i32,
) -> anyhow::Result<()> {
    let now = chrono::Utc::now();
    let completed_at = if status == "completed" || status == "failed" {
        Some(now)
    } else {
        None
    };
    let started_at = if status == "scanning" {
        Some(now)
    } else {
        None
    };

    if completed_at.is_some() {
        sqlx::query("UPDATE scan_tasks SET status = $1, progress = $2, completed_at = $3, updated_at = $4 WHERE id = $5")
            .bind(status)
            .bind(progress)
            .bind(completed_at)
            .bind(now)
            .bind(task_id)
            .execute(pool)
            .await?;
    } else if started_at.is_some() {
        sqlx::query("UPDATE scan_tasks SET status = $1, progress = $2, started_at = $3, updated_at = $4 WHERE id = $5")
            .bind(status)
            .bind(progress)
            .bind(started_at)
            .bind(now)
            .bind(task_id)
            .execute(pool)
            .await?;
    } else {
        sqlx::query("UPDATE scan_tasks SET status = $1, progress = $2, updated_at = $3 WHERE id = $4")
            .bind(status)
            .bind(progress)
            .bind(now)
            .bind(task_id)
            .execute(pool)
            .await?;
    }
    Ok(())
}

async fn scan_single_url(
    target_manager: &Arc<TargetManager>,
    detectors: &[Arc<dyn Detector + 'static>],
    target_url: &str,
    target_id: &str,
    pool: &PgPool,
    task_id: &str,
) -> anyhow::Result<Vec<scanner_engine::Vulnerability>> {
    let target = target_manager
        .add_target(target_url)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to validate target '{}': {}", target_url, e))?;

    info!("Target validated: {} (id={})", target_url, target.id);

    let _ = update_task_status(pool, task_id, "scanning", 10).await;

    let mut all_vulnerabilities = Vec::new();
    let total_detectors = detectors.len();

    for (i, detector) in detectors.iter().enumerate() {
        info!("Running detector '{}' on {}", detector.name(), target_url);

        match detector.scan(&target).await {
            Ok(mut vulns) => {
                for vuln in &mut vulns {
                    if vuln.target_id.is_empty() {
                        vuln.target_id = target_id.to_string();
                    }
                }
                let count = vulns.len();
                all_vulnerabilities.extend(vulns);
                if count > 0 {
                    info!(
                        "Detector '{}' found {} vulnerabilities on {}",
                        detector.name(),
                        count,
                        target_url
                    );
                }
            }
            Err(e) => {
                warn!(
                    "Detector '{}' failed on {}: {}",
                    detector.name(),
                    target_url,
                    e
                );
            }
        }

        let progress = 10 + ((i + 1) as i32 * 85 / total_detectors as i32);
        let _ = update_task_status(pool, task_id, "scanning", progress).await;
    }

    let _ = update_task_status(pool, task_id, "scanning", 95).await;

    Ok(all_vulnerabilities)
}

async fn save_vulnerability(
    pool: &PgPool,
    task_id: &str,
    target_id: &str,
    vuln: &scanner_engine::Vulnerability,
) -> anyhow::Result<()> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now();

    sqlx::query(
        r#"INSERT INTO vulnerabilities (id, task_id, target_id, plugin_name, severity, title, description, payload, proof, remediation, cve, cvss_score, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)"#,
    )
    .bind(&id)
    .bind(task_id)
    .bind(target_id)
    .bind(&vuln.detector_name)
    .bind(&vuln.severity)
    .bind(&vuln.title)
    .bind(&vuln.description)
    .bind(&vuln.payload)
    .bind(&vuln.proof)
    .bind(&vuln.remediation)
    .bind(&vuln.cve)
    .bind(vuln.cvss_score.map(|s| s as f64))
    .bind(now)
    .execute(pool)
    .await?;

    Ok(())
}
