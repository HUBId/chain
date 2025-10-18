use std::future::Future;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use tokio::task::JoinHandle;

/// Lightweight task supervisor that keeps track of spawned asynchronous jobs
/// and provides a graceful shutdown hook.
#[derive(Clone, Default, Debug)]
pub struct Supervisor {
    tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Supervisor {
    /// Create a new supervisor without managed tasks.
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawn a supervised task.
    ///
    /// The supplied future should resolve to `Ok(())` on success. Any error is
    /// logged and does not propagate to the caller.
    pub fn spawn<Fut>(&self, name: &'static str, future: Fut)
    where
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        let tasks = Arc::clone(&self.tasks);
        let handle = tokio::spawn(async move {
            if let Err(err) = future.await {
                log::warn!(target: "rpp::runtime::supervisor", %name, ?err, "supervised task terminated with error");
            }
        });
        tasks
            .lock()
            .expect("supervisor task registry lock")
            .push(handle);
    }

    /// Wait for all supervised tasks to finish.
    pub async fn shutdown(&self) {
        let handles = self
            .tasks
            .lock()
            .expect("supervisor task registry lock")
            .drain(..)
            .collect::<Vec<_>>();
        for handle in handles {
            if let Err(err) = handle.await {
                log::warn!(target: "rpp::runtime::supervisor", ?err, "supervised task aborted");
            }
        }
    }
}
