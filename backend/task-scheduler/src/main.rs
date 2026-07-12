use anyhow::Context;
use redis::Client;
use sqlx::postgres::PgPoolOptions;
use tracing::info;

use task_scheduler::queue::TaskQueue;
use task_scheduler::scheduler::SchedulerManager;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Starting Task Scheduler");

    let database_url = std::env::var("POSTGRES_URL")
        .context("POSTGRES_URL environment variable not set")?;

    let redis_url = std::env::var("REDIS_URL")
        .context("REDIS_URL environment variable not set")?;

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .context("Failed to connect to database")?;

    let redis_client = Client::open(redis_url.as_str())
        .context("Failed to connect to Redis")?;

    let queue = TaskQueue::new(redis_client, "scan_tasks");

    let (manager, shutdown_tx) = SchedulerManager::new(pool, queue, 5);

    info!("Task scheduler started with 5s interval");

    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C handler");
    };

    tokio::select! {
        _ = shutdown_signal => {
            info!("Received shutdown signal");
            drop(shutdown_tx);
        }
        _ = manager.start() => {
            info!("Scheduler stopped");
        }
    }

    info!("Task Scheduler shutting down");

    Ok(())
}
