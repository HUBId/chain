use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use serde_json::json;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};
use tracing::{debug, info, warn};

use rpp_chain::config::NodeConfig;
use rpp_chain::errors::ChainError;
use rpp_chain::node::NodeHandle;
use rpp_chain::runtime::node_runtime::node::GossipTopic;
use rpp_chain::wallet::Wallet;

use crate::telemetry::uptime::{CycleOutcome, CyclePhase, UptimeMetrics};

const DEFAULT_CADENCE_SECS: u64 = 600;

#[derive(Debug)]
struct CycleError {
    stage: CyclePhase,
    error: anyhow::Error,
}

impl CycleError {
    fn node_status(error: ChainError) -> Self {
        Self {
            stage: CyclePhase::NodeStatus,
            error: error.into(),
        }
    }

    fn wallet(error: ChainError) -> Self {
        Self {
            stage: CyclePhase::Wallet,
            error: error.into(),
        }
    }

    fn submission(error: ChainError) -> Self {
        Self {
            stage: CyclePhase::Submission,
            error: error.into(),
        }
    }

    fn gossip(error: anyhow::Error) -> Self {
        Self {
            stage: CyclePhase::Gossip,
            error,
        }
    }
}

#[derive(Debug)]
struct CycleReport {
    outcome: CycleOutcome,
    credited_hours: Option<u64>,
    pending_queue: usize,
}

pub struct UptimeScheduler {
    shutdown: watch::Sender<bool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

impl UptimeScheduler {
    pub fn start(node: NodeHandle, wallet: Arc<Wallet>, cadence: Duration) -> Self {
        let (tx, mut rx) = watch::channel(false);
        let metrics = UptimeMetrics::global().clone();
        let worker = tokio::spawn(async move {
            let mut ticker = time::interval(cadence);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let started = Instant::now();
                        match run_cycle(&node, Arc::clone(&wallet)).await {
                            Ok(report) => {
                                metrics.record_pending_queue(report.pending_queue);
                                metrics.record_cycle(
                                    report.outcome,
                                    started.elapsed(),
                                    report.credited_hours,
                                );
                            }
                            Err(err) => {
                                metrics.record_cycle(CycleOutcome::Error, started.elapsed(), None);
                                metrics.record_failure(err.stage);
                                warn!(
                                    stage = err.stage.as_str(),
                                    error = %err.error,
                                    "uptime scheduler cycle failed"
                                );
                            }
                        }
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
            if let Err(err) = handle.await {
                debug!(?err, "uptime scheduler worker exited with error");
            }
        }
    }
}

async fn run_cycle(node: &NodeHandle, wallet: Arc<Wallet>) -> Result<CycleReport, CycleError> {
    let status = node
        .node_status()
        .map_err(CycleError::node_status)?;
    let mut report = CycleReport {
        outcome: CycleOutcome::Success,
        credited_hours: None,
        pending_queue: status.pending_uptime_proofs,
    };

    if status.pending_uptime_proofs > 0 {
        debug!(
            pending = status.pending_uptime_proofs,
            "skipping uptime proof generation while queue drains"
        );
        report.outcome = CycleOutcome::Skipped;
        return Ok(report);
    }

    let wallet_clone = Arc::clone(&wallet);
    let proof = tokio::task::spawn_blocking(move || wallet_clone.generate_uptime_proof())
        .await
        .map_err(|err| CycleError {
            stage: CyclePhase::Wallet,
            error: anyhow!(err),
        })?
        .map_err(CycleError::wallet)?;
    let credited = node
        .submit_uptime_proof(proof.clone())
        .map_err(CycleError::submission)?;
    report.credited_hours = Some(credited);

    if let Ok(Some(audit)) = node.reputation_audit(&proof.wallet_address) {
        info!(
            validator = %audit.address,
            credited_hours = credited,
            uptime_hours = audit.uptime_hours,
            score = audit.score,
            tier = %audit.tier,
            "submitted uptime proof"
        );
        if let Some(handle) = node.p2p_handle() {
            let peer = handle.local_peer_id().to_base58();
            let payload = json!({
                "peer": peer,
                "event": { "type": "uptime_proof" },
                "reputation": audit.score,
                "tier": audit.tier.to_string(),
                "banned_until": serde_json::Value::Null,
                "label": "uptime_proof",
            });
            let encoded = serde_json::to_vec(&payload)
                .map_err(|err| CycleError::gossip(anyhow!(err)))?;
            handle
                .publish_gossip(GossipTopic::Meta, encoded)
                .await
                .map_err(|err| CycleError::gossip(anyhow!(err)))?;
        } else {
            debug!("p2p handle not yet initialised; skipping uptime gossip");
        }
    } else {
        warn!(
            validator = %proof.wallet_address,
            "reputation audit unavailable after uptime submission"
        );
    }

    Ok(report)
}

pub fn cadence_from_config(config: &NodeConfig) -> Duration {
    let secs = config
        .malachite
        .reputation
        .timetoke
        .sync_interval_secs
        .max(1);
    Duration::from_secs(secs.max(DEFAULT_CADENCE_SECS))
}
