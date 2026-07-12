use redis::{Client, Commands};
use serde::{Deserialize, Serialize};
use shared_lib::errors::AppError;
use tracing::info;

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanTaskMessage {
    pub task_id: String,
    pub user_id: String,
    pub target_id: String,
}

pub struct TaskQueue {
    client: Client,
    queue_name: String,
}

impl TaskQueue {
    pub fn new(client: Client, queue_name: &str) -> Self {
        TaskQueue {
            client,
            queue_name: queue_name.to_string(),
        }
    }

    pub async fn enqueue(&self, task_id: String, user_id: String, target_id: String) -> Result<(), AppError> {
        let message = ScanTaskMessage {
            task_id,
            user_id,
            target_id,
        };

        let message_json = serde_json::to_string(&message)
            .map_err(|e| AppError::ScanEngineError(format!("Failed to serialize task message: {}", e)))?;

        let mut conn = self.client.get_connection()
            .map_err(|e| AppError::RedisError(format!("Failed to get Redis connection: {}", e)))?;

        conn.rpush::<_, _, ()>(&self.queue_name, &message_json)
            .map_err(|e| AppError::RedisError(format!("Failed to enqueue task: {}", e)))?;

        info!("Enqueued task: {}", message.task_id);

        Ok(())
    }

    pub async fn dequeue(&self) -> Result<Option<ScanTaskMessage>, AppError> {
        let mut conn = self.client.get_connection()
            .map_err(|e| AppError::RedisError(format!("Failed to get Redis connection: {}", e)))?;

        let message: Option<String> = conn.lpop(&self.queue_name, None)
            .map_err(|e| AppError::RedisError(format!("Failed to dequeue task: {}", e)))?;

        if let Some(msg) = message {
            let scan_message: ScanTaskMessage = serde_json::from_str(&msg)
                .map_err(|e| AppError::ScanEngineError(format!("Failed to parse task message: {}", e)))?;

            Ok(Some(scan_message))
        } else {
            Ok(None)
        }
    }

    pub async fn queue_length(&self) -> Result<usize, AppError> {
        let mut conn = self.client.get_connection()
            .map_err(|e| AppError::RedisError(format!("Failed to get Redis connection: {}", e)))?;

        conn.llen(&self.queue_name)
            .map_err(|e| AppError::RedisError(format!("Failed to get queue length: {}", e)))
    }

    pub async fn clear_queue(&self) -> Result<(), AppError> {
        let mut conn = self.client.get_connection()
            .map_err(|e| AppError::RedisError(format!("Failed to get Redis connection: {}", e)))?;

        conn.del::<_, ()>(&self.queue_name)
            .map_err(|e| AppError::RedisError(format!("Failed to clear queue: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_enqueue_and_dequeue() {
        let client = Client::open("redis://localhost:6379/0").unwrap();
        let queue = TaskQueue::new(client, "test_queue");

        let task_id = Uuid::new_v4().to_string();
        let user_id = Uuid::new_v4().to_string();
        let target_id = Uuid::new_v4().to_string();

        queue.enqueue(task_id.clone(), user_id, target_id).await.unwrap();

        let length = queue.queue_length().await.unwrap();
        assert_eq!(length, 1);

        let message = queue.dequeue().await.unwrap();
        assert!(message.is_some());
        assert_eq!(message.unwrap().task_id, task_id);

        queue.clear_queue().await.unwrap();
    }
}
