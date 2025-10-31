use std::collections::HashSet;
use std::sync::{Arc, OnceLock};

use rpp_chain::orchestration::{PipelineDashboardSnapshot, PipelineOrchestrator, PipelineStage};
use tokio::sync::{broadcast, watch, RwLock};
use tokio::task::JoinHandle;
use tracing::{info, trace};

const HOOK_BUFFER: usize = 128;
const STAGES_OF_INTEREST: [PipelineStage; 4] = [
    PipelineStage::GossipReceived,
    PipelineStage::MempoolAccepted,
    PipelineStage::BftFinalised,
    PipelineStage::FirewoodCommitted,
];

static EVENT_DISPATCH: OnceLock<broadcast::Sender<PipelineStageEvent>> = OnceLock::new();

fn channel() -> &'static broadcast::Sender<PipelineStageEvent> {
    EVENT_DISPATCH.get_or_init(|| {
        let (tx, _rx) = broadcast::channel(HOOK_BUFFER);
        tx
    })
}

/// Structured payload emitted when the orchestrator completes an observed stage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PipelineStageEvent {
    pub stage: PipelineStage,
    pub hash: String,
    pub observed_ms: u128,
    pub commit_height: Option<u64>,
}

impl PipelineStageEvent {
    fn new(
        stage: PipelineStage,
        hash: String,
        observed_ms: u128,
        commit_height: Option<u64>,
    ) -> Self {
        Self {
            stage,
            hash,
            observed_ms,
            commit_height,
        }
    }
}

#[derive(Debug)]
pub struct PipelineHookGuard {
    shutdown: Option<watch::Sender<bool>>,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for PipelineHookGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(true);
        }
        for handle in &self.tasks {
            handle.abort();
        }
    }
}

pub fn subscribe_stage_events() -> broadcast::Receiver<PipelineStageEvent> {
    channel().subscribe()
}

pub(crate) fn install_hooks(orchestrator: Arc<PipelineOrchestrator>) -> PipelineHookGuard {
    let seen: Arc<RwLock<HashSet<(String, PipelineStage)>>> = Arc::new(RwLock::new(HashSet::new()));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut dashboard_rx = orchestrator.subscribe_dashboard();
    let mut shutdown_rx_dashboard = shutdown_rx.clone();
    let seen_dashboard = Arc::clone(&seen);

    let dashboard_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                changed = shutdown_rx_dashboard.changed() => {
                    if changed.is_err() || *shutdown_rx_dashboard.borrow() {
                        break;
                    }
                }
                update = dashboard_rx.changed() => {
                    if update.is_err() {
                        break;
                    }
                    let snapshot = dashboard_rx.borrow().clone();
                    let events = collect_events(snapshot, &seen_dashboard).await;
                    publish_events(events);
                }
            }
        }
    });

    PipelineHookGuard {
        shutdown: Some(shutdown_tx),
        tasks: vec![dashboard_task],
    }
}

async fn collect_events(
    snapshot: PipelineDashboardSnapshot,
    seen: &Arc<RwLock<HashSet<(String, PipelineStage)>>>,
) -> Vec<PipelineStageEvent> {
    let mut emitted = Vec::new();
    let mut guard = seen.write().await;

    for flow in &snapshot.flows {
        for stage in STAGES_OF_INTEREST {
            if let Some(observed_ms) = flow.stages.get(&stage).copied() {
                let key = (flow.hash.clone(), stage);
                if guard.insert(key.clone()) {
                    let commit_height = if stage == PipelineStage::FirewoodCommitted {
                        flow.commit_height
                    } else {
                        None
                    };
                    emitted.push(PipelineStageEvent::new(
                        stage,
                        key.0,
                        observed_ms,
                        commit_height,
                    ));
                }
            }
        }
    }

    emitted
}

fn publish_events(events: Vec<PipelineStageEvent>) {
    for event in events {
        let stage = event.stage;
        let hash = event.hash.clone();
        let result = channel().send(event.clone());
        match result {
            Ok(_) => {
                info!(
                    target = "pipeline.hooks",
                    stage = stage.as_str(),
                    hash = %hash,
                    observed_ms = event.observed_ms,
                    commit_height = ?event.commit_height,
                    "pipeline stage observed"
                );
            }
            Err(err) => {
                trace!(
                    target = "pipeline.hooks",
                    stage = stage.as_str(),
                    hash = %hash,
                    error = %err,
                    "no active pipeline hook subscribers"
                );
            }
        }
    }
}
