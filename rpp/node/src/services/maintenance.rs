use std::sync::Arc;
use std::time::Duration;

use time::OffsetDateTime;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};
use tracing::{info, warn};

use rpp_chain::config::{MaintenanceConfig, MaintenanceWindow};

use crate::telemetry::maintenance::MaintenanceMetrics;

pub struct MaintenanceWindowTracker {
    shutdown: watch::Sender<bool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl MaintenanceWindowTracker {
    pub fn start(config: MaintenanceConfig) -> Self {
        let (tx, mut rx) = watch::channel(false);
        let metrics = MaintenanceMetrics::global().clone();
        let poll_interval = Duration::from_secs(config.poll_interval_secs.max(5));
        let windows = Arc::new(config.windows);

        let worker = tokio::spawn(async move {
            let mut ticker = time::interval(poll_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let mut active: Vec<MaintenanceWindow> = Vec::new();
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let now = OffsetDateTime::now_utc();
                        let next_active: Vec<MaintenanceWindow> = windows
                            .iter()
                            .filter(|window| window.contains(now))
                            .cloned()
                            .collect();

                        for window in next_active.iter() {
                            if !active.iter().any(|current| current.name == window.name) {
                                metrics.record_window_start(window);
                                info!(
                                    window = window.name,
                                    starts_at = %window.starts_at,
                                    ends_at = %window.ends_at,
                                    scopes = ?window.scopes(),
                                    "maintenance window entered"
                                );
                            }
                        }

                        for window in active.iter() {
                            if !next_active.iter().any(|candidate| candidate.name == window.name) {
                                metrics.record_window_end(window);
                                info!(
                                    window = window.name,
                                    scopes = ?window.scopes(),
                                    "maintenance window completed"
                                );
                            }
                        }

                        if !active.is_empty() && next_active.is_empty() {
                            warn!("all maintenance windows ended; alert suppression lifted");
                        }

                        active = next_active;
                    }
                    changed = rx.changed() => {
                        if changed.is_ok() && *rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });

        Self {
            shutdown: tx,
            worker: Mutex::new(Some(worker)),
        }
    }

    pub async fn shutdown(&self) {
        if self.shutdown.send(true).is_err() {
            return;
        }
        if let Some(handle) = self.worker.lock().await.take() {
            let _ = handle.await;
        }
    }
}
