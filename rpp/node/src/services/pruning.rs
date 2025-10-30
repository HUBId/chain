use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex as ParkingMutex, RwLock};
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{self, MissedTickBehavior};
use tracing::{debug, info, warn};

use rpp_chain::config::NodeConfig;
use rpp_chain::node::{NodeHandle, PruningJobStatus, DEFAULT_STATE_SYNC_CHUNK};

const COMMAND_QUEUE_DEPTH: usize = 8;

#[derive(Clone, Copy, Debug)]
pub struct PruningSettings {
    pub chunk_size: usize,
    pub cadence: Duration,
    pub paused: bool,
    pub retention_depth: u64,
}

impl PruningSettings {
    pub fn from_config(config: &NodeConfig) -> Self {
        Self {
            chunk_size: DEFAULT_STATE_SYNC_CHUNK,
            cadence: Duration::from_secs(config.pruning.cadence_secs),
            paused: config.pruning.emergency_pause,
            retention_depth: config.pruning.retention_depth,
        }
    }
}

#[derive(Debug)]
pub enum PruningCommandError {
    ServiceUnavailable,
    InvalidCadence,
    InvalidRetention,
}

impl std::fmt::Display for PruningCommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PruningCommandError::ServiceUnavailable => {
                write!(f, "pruning service is no longer running")
            }
            PruningCommandError::InvalidCadence => {
                write!(f, "pruning cadence must be greater than zero")
            }
            PruningCommandError::InvalidRetention => {
                write!(f, "pruning retention depth must be greater than zero")
            }
        }
    }
}

impl std::error::Error for PruningCommandError {}

pub struct PruningService {
    inner: Arc<PruningServiceInner>,
    shutdown: watch::Sender<bool>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Clone)]
pub struct PruningServiceHandle {
    inner: Arc<PruningServiceInner>,
}

struct PruningServiceInner {
    commands: mpsc::Sender<Command>,
    status_tx: watch::Sender<Option<PruningJobStatus>>,
    status_rx: ParkingMutex<watch::Receiver<Option<PruningJobStatus>>>,
    state: Arc<PruningState>,
}

struct PruningState {
    cadence: RwLock<Duration>,
    retention_depth: RwLock<u64>,
    paused: AtomicBool,
}

enum Command {
    Trigger,
    UpdateCadence(Duration),
    UpdateRetention(u64),
    SetPaused(bool),
}

enum RunReason {
    Manual,
    Scheduled,
}

impl PruningService {
    pub fn start(node: NodeHandle, config: &NodeConfig) -> Self {
        Self::with_settings(node, PruningSettings::from_config(config))
    }

    pub fn with_settings(node: NodeHandle, settings: PruningSettings) -> Self {
        let state = Arc::new(PruningState {
            cadence: RwLock::new(settings.cadence),
            retention_depth: RwLock::new(settings.retention_depth),
            paused: AtomicBool::new(settings.paused),
        });
        let (command_tx, command_rx) = mpsc::channel(COMMAND_QUEUE_DEPTH);
        let (status_tx, status_rx) = watch::channel(None);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let inner = Arc::new(PruningServiceInner {
            commands: command_tx.clone(),
            status_tx: status_tx.clone(),
            status_rx: ParkingMutex::new(status_rx),
            state: Arc::clone(&state),
        });

        let mut worker_shutdown = shutdown_rx;
        let worker_state = Arc::clone(&state);
        let worker_status = status_tx.clone();
        let worker_chunk = settings.chunk_size;
        let worker = tokio::spawn(async move {
            run_worker(
                node,
                worker_chunk,
                command_rx,
                worker_status,
                &mut worker_shutdown,
                worker_state,
                settings.cadence,
            )
            .await;
        });

        info!(
            target = "pruning",
            cadence_secs = settings.cadence.as_secs(),
            chunk_size = settings.chunk_size,
            paused = settings.paused,
            retention_depth = settings.retention_depth,
            "pruning service started"
        );

        PruningService {
            inner,
            shutdown: shutdown_tx,
            worker: Mutex::new(Some(worker)),
        }
    }

    pub fn handle(&self) -> PruningServiceHandle {
        PruningServiceHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    pub fn subscribe_status(&self) -> watch::Receiver<Option<PruningJobStatus>> {
        self.inner.status_rx.lock().clone()
    }

    pub fn cadence(&self) -> Duration {
        *self.inner.state.cadence.read()
    }

    pub fn retention_depth(&self) -> u64 {
        *self.inner.state.retention_depth.read()
    }

    pub fn is_paused(&self) -> bool {
        self.inner.state.paused.load(Ordering::SeqCst)
    }

    pub async fn shutdown(&self) {
        if self.shutdown.send(true).is_ok() {
            if let Some(handle) = self.worker.lock().await.take() {
                if let Err(err) = handle.await {
                    debug!(?err, "pruning worker exited with error");
                }
            }
        }
    }
}

impl Drop for PruningService {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

impl PruningServiceHandle {
    pub fn subscribe_status(&self) -> watch::Receiver<Option<PruningJobStatus>> {
        self.inner.status_rx.lock().clone()
    }

    pub fn cadence(&self) -> Duration {
        *self.inner.state.cadence.read()
    }

    pub fn retention_depth(&self) -> u64 {
        *self.inner.state.retention_depth.read()
    }

    pub fn paused(&self) -> bool {
        self.inner.state.paused.load(Ordering::SeqCst)
    }

    pub async fn queue_job(&self) -> Result<(), PruningCommandError> {
        self.inner
            .commands
            .send(Command::Trigger)
            .await
            .map_err(|_| PruningCommandError::ServiceUnavailable)
    }

    pub async fn set_cadence(&self, cadence: Duration) -> Result<(), PruningCommandError> {
        if cadence.is_zero() {
            return Err(PruningCommandError::InvalidCadence);
        }
        self.inner
            .commands
            .send(Command::UpdateCadence(cadence))
            .await
            .map_err(|_| PruningCommandError::ServiceUnavailable)?;
        *self.inner.state.cadence.write() = cadence;
        Ok(())
    }

    pub async fn set_retention_depth(
        &self,
        retention_depth: u64,
    ) -> Result<(), PruningCommandError> {
        if retention_depth == 0 {
            return Err(PruningCommandError::InvalidRetention);
        }
        self.inner
            .commands
            .send(Command::UpdateRetention(retention_depth))
            .await
            .map_err(|_| PruningCommandError::ServiceUnavailable)?;
        *self.inner.state.retention_depth.write() = retention_depth;
        Ok(())
    }

    pub async fn set_paused(&self, paused: bool) -> Result<(), PruningCommandError> {
        self.inner
            .commands
            .send(Command::SetPaused(paused))
            .await
            .map_err(|_| PruningCommandError::ServiceUnavailable)?;
        self.inner.state.paused.store(paused, Ordering::SeqCst);
        Ok(())
    }
}

async fn run_worker(
    node: NodeHandle,
    chunk_size: usize,
    mut commands: mpsc::Receiver<Command>,
    status_tx: watch::Sender<Option<PruningJobStatus>>,
    shutdown: &mut watch::Receiver<bool>,
    state: Arc<PruningState>,
    initial_cadence: Duration,
) {
    let mut ticker = time::interval(initial_cadence);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut next_run = Some(RunReason::Manual);

    loop {
        let run_reason = if let Some(reason) = next_run.take() {
            Some(reason)
        } else {
            let mut selected: Option<RunReason> = None;
            tokio::select! {
                biased;
                changed = shutdown.changed() => {
                    if changed.is_ok() && *shutdown.borrow() {
                        break;
                    }
                }
                command = commands.recv() => {
                    match command {
                        Some(Command::Trigger) => {
                            selected = Some(RunReason::Manual);
                        }
                        Some(Command::UpdateCadence(duration)) => {
                            *state.cadence.write() = duration;
                            ticker = time::interval(duration);
                            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
                        }
                        Some(Command::UpdateRetention(depth)) => {
                            *state.retention_depth.write() = depth;
                        }
                        Some(Command::SetPaused(paused)) => {
                            state.paused.store(paused, Ordering::SeqCst);
                            if !paused {
                                selected = Some(RunReason::Manual);
                            }
                        }
                        None => break,
                    }
                }
                _ = ticker.tick(), if !state.paused.load(Ordering::SeqCst) => {
                    selected = Some(RunReason::Scheduled);
                }
            }
            selected
        };

        let Some(reason) = run_reason else {
            continue;
        };

        if matches!(reason, RunReason::Scheduled) && state.paused.load(Ordering::SeqCst) {
            continue;
        }

        let retention_depth = *state.retention_depth.read();
        if let Err(err) = run_pruning_cycle(&node, chunk_size, retention_depth, &status_tx) {
            warn!(?err, "pruning cycle failed");
        }
    }

    debug!("pruning worker exiting");
}

fn run_pruning_cycle(
    node: &NodeHandle,
    chunk_size: usize,
    retention_depth: u64,
    status_tx: &watch::Sender<Option<PruningJobStatus>>,
) -> Result<(), rpp_chain::errors::ChainError> {
    let status = node.run_pruning_cycle(chunk_size, retention_depth)?;
    if let Err(err) = status_tx.send(status.clone()) {
        debug!(?err, "pruning status watchers dropped");
    }
    Ok(())
}
