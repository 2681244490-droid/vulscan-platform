use shared_lib::errors::AppError;
use sqlx::MySqlPool;
use tokio::sync::mpsc;
use tracing::{info, error};

use crate::queue::TaskQueue;

/// 轻量行映射结构体，用于接收 scan_tasks 查询结果
#[derive(sqlx::FromRow)]
struct ScanTaskRow {
    id: String,
    user_id: String,
    target_id: String,
}

pub struct TaskScheduler {
    pool: MySqlPool,
    queue: TaskQueue,
    interval_seconds: u64,
    shutdown_rx: mpsc::Receiver<()>,
}

impl TaskScheduler {
    pub fn new(
        pool: MySqlPool,
        queue: TaskQueue,
        interval_seconds: u64,
        shutdown_rx: mpsc::Receiver<()>,
    ) -> Self {
        TaskScheduler {
            pool,
            queue,
            interval_seconds,
            shutdown_rx,
        }
    }

    pub async fn run(mut self) {
        info!("Task scheduler starting with interval {}s", self.interval_seconds);

        loop {
            tokio::select! {
                _ = self.shutdown_rx.recv() => {
                    info!("Task scheduler shutting down");
                    break;
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(self.interval_seconds)) => {
                    if let Err(e) = self.process_pending_tasks().await {
                        error!("Error processing pending tasks: {}", e);
                    }
                }
            }
        }
    }

    async fn process_pending_tasks(&self) -> Result<(), AppError> {
        let pending_tasks: Vec<ScanTaskRow> = sqlx::query_as(
            r#"
            SELECT id, user_id, target_id
            FROM scan_tasks
            WHERE status = 'pending'
            ORDER BY created_at ASC
            LIMIT 10
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to get pending tasks: {}", e)))?;

        info!("Found {} pending tasks", pending_tasks.len());

        for task in pending_tasks {
            self.queue.enqueue(task.id.clone(), task.user_id.clone(), task.target_id.clone()).await?;

            let now = chrono::Utc::now();
            sqlx::query("UPDATE scan_tasks SET status = ?, updated_at = ? WHERE id = ?")
                .bind("queued")
                .bind(now)
                .bind(&task.id)
                .execute(&self.pool)
                .await
                .map_err(|e| AppError::DatabaseError(format!("Failed to update task status: {}", e)))?;

            info!("Task {} queued for processing", task.id);
        }

        Ok(())
    }
}

pub struct SchedulerManager {
    scheduler: TaskScheduler,
}

impl SchedulerManager {
    pub fn new(
        pool: MySqlPool,
        queue: TaskQueue,
        interval_seconds: u64,
    ) -> (Self, mpsc::Sender<()>) {
        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);

        let scheduler = TaskScheduler::new(
            pool,
            queue,
            interval_seconds,
            shutdown_rx,
        );

        (SchedulerManager { scheduler }, shutdown_tx)
    }

    pub async fn start(self) {
        self.scheduler.run().await;
    }
}
