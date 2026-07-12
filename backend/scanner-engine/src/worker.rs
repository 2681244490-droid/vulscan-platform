use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{info, error};
use uuid::Uuid;

use crate::engine::ScannerEngine;

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanTaskMessage {
    pub task_id: Uuid,
    pub user_id: Uuid,
    pub target_id: Uuid,
}

pub struct ScannerWorker {
    worker_id: usize,
    shutdown_rx: watch::Receiver<bool>,
}

impl ScannerWorker {
    pub fn new(
        worker_id: usize,
        _engine: Arc<ScannerEngine>,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Self {
        ScannerWorker {
            worker_id,
            shutdown_rx,
        }
    }

    pub async fn run(mut self) {
        info!("Scanner worker {} starting", self.worker_id);

        loop {
            tokio::select! {
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        info!("Scanner worker {} shutting down", self.worker_id);
                        break;
                    }
                }
                else => {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        }
    }
}

pub struct WorkerManager {
    workers: Vec<ScannerWorker>,
}

impl WorkerManager {
    pub fn new(
        count: usize,
        engine: Arc<ScannerEngine>,
    ) -> (Self, watch::Sender<bool>) {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        
        let mut workers = Vec::with_capacity(count);
        for i in 0..count {
            let worker = ScannerWorker::new(
                i + 1,
                engine.clone(),
                shutdown_rx.clone(),
            );
            workers.push(worker);
        }

        (WorkerManager { workers }, shutdown_tx)
    }

    pub async fn start_all(&mut self) {
        let mut handles = Vec::with_capacity(self.workers.len());
        
        for worker in self.workers.drain(..) {
            let handle = tokio::spawn(async move {
                worker.run().await;
            });
            handles.push(handle);
        }

        for handle in handles {
            if let Err(e) = handle.await {
                error!("Worker task failed: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_task_message_serialization() {
        let msg = ScanTaskMessage {
            task_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            target_id: Uuid::new_v4(),
        };

        let json = serde_json::to_string(&msg).unwrap();
        let deserialized: ScanTaskMessage = serde_json::from_str(&json).unwrap();

        assert_eq!(msg.task_id, deserialized.task_id);
        assert_eq!(msg.user_id, deserialized.user_id);
        assert_eq!(msg.target_id, deserialized.target_id);
    }

    #[tokio::test]
    async fn test_worker_manager_creation() {
        let engine = Arc::new(ScannerEngine::new(
            Arc::new(crate::target::TargetManager::new(
                Arc::new(crate::target::DefaultTargetValidator::new(
                    Arc::new(reqwest::Client::new()),
                )),
                Arc::new(reqwest::Client::new()),
            )),
            vec![],
            50,
            10.0,
        ));

        let (manager, shutdown_tx) = WorkerManager::new(2, engine);
        assert_eq!(manager.workers.len(), 2);
        
        let _ = shutdown_tx.send(true);
    }
}
