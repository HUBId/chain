use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::{mpsc, watch, Mutex as AsyncMutex};
use tokio::task::JoinHandle;
use tracing::{error, warn};

use crate::engine::WalletEngine;
use crate::indexer::client::IndexerClient;
use crate::indexer::scanner::{
    ScanAbortHandle, ScanAbortToken, ScannerError, SyncStatus, WalletScanner,
};
use crate::node_client::NodeClientError;

#[derive(Clone, Debug, thiserror::Error)]
pub enum WalletSyncError {
    #[error("scanner error: {0}")]
    Scanner(Arc<ScannerError>),
    #[error("sync coordinator stopped")]
    Stopped,
}

impl From<ScannerError> for WalletSyncError {
    fn from(error: ScannerError) -> Self {
        WalletSyncError::Scanner(Arc::new(error))
    }
}

#[derive(Default)]
struct StatusState {
    last_status: Option<SyncStatus>,
    last_error: Option<WalletSyncError>,
    is_syncing: bool,
    pending_resume: bool,
    pending_rescan: Option<u64>,
    node_issue: Option<String>,
    node_hints: Vec<String>,
    abort_handle: Option<ScanAbortHandle>,
}

pub struct WalletSyncCoordinator {
    command_tx: mpsc::UnboundedSender<SyncCommand>,
    shutdown_tx: watch::Sender<bool>,
    task: AsyncMutex<Option<JoinHandle<()>>>,
    state: Arc<Mutex<StatusState>>,
}

enum SyncCommand {
    Resume,
    Rescan,
}

impl WalletSyncCoordinator {
    pub fn start(
        engine: Arc<WalletEngine>,
        indexer_client: Arc<dyn IndexerClient>,
    ) -> Result<Self, WalletSyncError> {
        let scanner = WalletScanner::new(engine, indexer_client)?;
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let state = Arc::new(Mutex::new(StatusState::default()));
        let task_state = Arc::clone(&state);
        let mut task_shutdown_rx = shutdown_rx.clone();
        let task = tokio::spawn(async move {
            run_loop(scanner, command_rx, &mut task_shutdown_rx, task_state).await;
        });
        let coordinator = Self {
            command_tx,
            shutdown_tx,
            task: AsyncMutex::new(Some(task)),
            state,
        };
        // Trigger the initial resume synchronisation.
        let _ = coordinator.request_resume_sync();
        Ok(coordinator)
    }

    pub fn request_resume_sync(&self) -> Result<bool, WalletSyncError> {
        let should_send = {
            let mut state = lock_state(&self.state);
            if state.pending_resume {
                false
            } else {
                state.pending_resume = true;
                true
            }
        };
        if should_send {
            self.command_tx
                .send(SyncCommand::Resume)
                .map_err(|_| WalletSyncError::Stopped)?;
        }
        Ok(should_send)
    }

    pub fn request_rescan(&self, from_height: u64) -> Result<bool, WalletSyncError> {
        let should_send = {
            let mut state = lock_state(&self.state);
            if let Some(pending) = state.pending_rescan.as_mut() {
                *pending = from_height;
                false
            } else {
                state.pending_rescan = Some(from_height);
                true
            }
        };
        if should_send {
            self.command_tx
                .send(SyncCommand::Rescan)
                .map_err(|_| WalletSyncError::Stopped)?;
        }
        Ok(should_send)
    }

    pub fn latest_status(&self) -> Option<SyncStatus> {
        let state = lock_state(&self.state);
        state.last_status.as_ref().map(|status| {
            let mut status = status.clone();
            if let Some(pending) = state.pending_rescan {
                let upper = status
                    .checkpoints
                    .resume_height
                    .unwrap_or(status.current_height)
                    .max(pending);
                status.pending_ranges.push((pending, upper));
                status.target_height = status.target_height.max(upper);
            }
            if let Some(issue) = &state.node_issue {
                status.node_issue = Some(issue.clone());
            }
            if !state.node_hints.is_empty() {
                status.hints.extend(state.node_hints.clone());
            }
            status
        })
    }

    pub fn last_error(&self) -> Option<WalletSyncError> {
        lock_state(&self.state).last_error.clone()
    }

    pub fn is_syncing(&self) -> bool {
        lock_state(&self.state).is_syncing
    }

    pub async fn shutdown(&self) -> Result<(), WalletSyncError> {
        self.abort_active_scan();
        let _ = self.shutdown_tx.send(true);
        let mut task = self.task.lock().await;
        if let Some(handle) = task.take() {
            handle.await.map_err(|_| WalletSyncError::Stopped)?;
        }
        Ok(())
    }

    fn abort_active_scan(&self) {
        let handle = {
            let guard = lock_state(&self.state);
            guard.abort_handle.clone()
        };
        if let Some(handle) = handle {
            handle.abort();
        }
    }

    pub fn record_node_failure(&self, error: &NodeClientError) {
        let message = error.user_message();
        let hints = error.hints();
        warn!(
            code = error.phase2_code(),
            %message,
            ?hints,
            "wallet node interaction failed"
        );
        let mut guard = lock_state(&self.state);
        guard.node_issue = Some(message);
        guard.node_hints = hints;
    }

    pub fn clear_node_failure(&self) {
        let mut guard = lock_state(&self.state);
        guard.node_issue = None;
        guard.node_hints.clear();
    }
}

fn lock_state<'a>(state: &'a Arc<Mutex<StatusState>>) -> MutexGuard<'a, StatusState> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

async fn run_loop(
    mut scanner: WalletScanner,
    mut commands: mpsc::UnboundedReceiver<SyncCommand>,
    shutdown_rx: &mut watch::Receiver<bool>,
    state: Arc<Mutex<StatusState>>,
) {
    loop {
        let command = tokio::select! {
            biased;
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
                continue;
            }
            cmd = commands.recv() => match cmd {
                Some(command) => command,
                None => break,
            },
        };

        match command {
            SyncCommand::Resume => {
                let (abort_handle, abort_token) = ScanAbortToken::new_pair();
                {
                    let mut guard = lock_state(&state);
                    guard.is_syncing = true;
                    guard.pending_resume = false;
                    guard.last_error = None;
                    guard.abort_handle = Some(abort_handle);
                }
                let result = scanner
                    .sync_resume(&abort_token)
                    .map_err(WalletSyncError::from);
                update_state(&state, &result);
                if let Err(error) = &result {
                    error!(?error, "wallet resume synchronisation failed");
                }
            }
            SyncCommand::Rescan => {
                let from_height = {
                    let mut guard = lock_state(&state);
                    guard.is_syncing = true;
                    guard.last_error = None;
                    guard.pending_rescan.take().unwrap_or_default()
                };
                let (abort_handle, abort_token) = ScanAbortToken::new_pair();
                {
                    let mut guard = lock_state(&state);
                    guard.abort_handle = Some(abort_handle);
                }
                let result = scanner
                    .rescan_from(from_height, &abort_token)
                    .map_err(WalletSyncError::from);
                update_state(&state, &result);
                if let Err(error) = &result {
                    error!(?error, from_height, "wallet rescan failed");
                }
            }
        }
    }

    let mut guard = lock_state(&state);
    guard.is_syncing = false;
    guard.pending_resume = false;
    guard.pending_rescan = None;
}

fn update_state(state: &Arc<Mutex<StatusState>>, result: &Result<SyncStatus, WalletSyncError>) {
    let mut guard = lock_state(state);
    guard.is_syncing = false;
    guard.abort_handle = None;
    match result {
        Ok(status) => {
            guard.last_status = Some(status.clone());
            guard.last_error = None;
            // Successful sync clears previously recorded node hints.
            guard.node_issue = None;
            guard.node_hints.clear();
        }
        Err(error) => {
            guard.last_error = Some(error.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::wallet::{WalletFeeConfig, WalletPolicyConfig};
    use crate::db::WalletStore;
    use crate::indexer::client::{
        GetHeadersRequest, GetHeadersResponse, GetScripthashStatusRequest,
        GetScripthashStatusResponse, GetTransactionRequest, GetTransactionResponse, IndexedHeader,
        IndexerClientError, ListScripthashUtxosRequest, ListScripthashUtxosResponse,
    };
    use crate::indexer::scanner::{SyncCheckpoints, SyncMode};
    use crate::node_client::NodeRejectionHint;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::tempdir;
    use tokio::time::{sleep, Duration};

    struct CountingIndexer {
        calls: Arc<AtomicUsize>,
        heights: Arc<Mutex<VecDeque<u64>>>,
    }

    impl CountingIndexer {
        fn new() -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                heights: Arc::new(Mutex::new(VecDeque::new())),
            }
        }

        fn calls(&self) -> Arc<AtomicUsize> {
            Arc::clone(&self.calls)
        }

        fn last_heights(&self) -> Arc<Mutex<VecDeque<u64>>> {
            Arc::clone(&self.heights)
        }
    }

    impl IndexerClient for CountingIndexer {
        fn get_headers(
            &self,
            request: &GetHeadersRequest,
        ) -> Result<GetHeadersResponse, IndexerClientError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.heights
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push_back(request.start_height);
            let header = IndexedHeader::new(request.start_height, [0u8; 32], [0u8; 32], Vec::new());
            Ok(GetHeadersResponse::new(
                request.start_height + 1,
                vec![header],
            ))
        }

        fn get_scripthash_status(
            &self,
            _request: &GetScripthashStatusRequest,
        ) -> Result<GetScripthashStatusResponse, IndexerClientError> {
            Ok(GetScripthashStatusResponse::new(None))
        }

        fn list_scripthash_utxos(
            &self,
            _request: &ListScripthashUtxosRequest,
        ) -> Result<ListScripthashUtxosResponse, IndexerClientError> {
            Ok(ListScripthashUtxosResponse::new(Vec::new()))
        }

        fn get_transaction(
            &self,
            _request: &GetTransactionRequest,
        ) -> Result<GetTransactionResponse, IndexerClientError> {
            Ok(GetTransactionResponse::new(None))
        }
    }

    fn test_engine() -> Arc<WalletEngine> {
        let dir = tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(dir.path()).expect("store"));
        let policy = WalletPolicyConfig {
            external_gap_limit: 4,
            internal_gap_limit: 4,
            min_confirmations: 1,
            ..WalletPolicyConfig::default()
        };
        Arc::new(
            WalletEngine::new(
                Arc::clone(&store),
                [1u8; 32],
                policy,
                WalletFeeConfig::default(),
            )
            .expect("engine"),
        )
    }

    async fn wait_for_calls(counter: &Arc<AtomicUsize>, expected: usize) {
        for _ in 0..20 {
            if counter.load(Ordering::SeqCst) >= expected {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
        panic!("timed out waiting for sync calls");
    }

    #[tokio::test]
    async fn resume_requests_are_deduplicated() {
        let engine = test_engine();
        let indexer = CountingIndexer::new();
        let calls = indexer.calls();
        let coordinator =
            WalletSyncCoordinator::start(engine, Arc::new(indexer)).expect("coordinator");

        wait_for_calls(&calls, 1).await;
        assert!(coordinator.latest_status().is_some());

        assert!(coordinator.request_resume_sync().expect("schedule resume"));
        assert!(!coordinator
            .request_resume_sync()
            .expect("no duplicate resume"));

        wait_for_calls(&calls, 2).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        coordinator.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn rescan_requests_merge_latest_height() {
        let engine = test_engine();
        let indexer = CountingIndexer::new();
        let calls = indexer.calls();
        let heights = indexer.last_heights();
        let coordinator =
            WalletSyncCoordinator::start(engine, Arc::new(indexer)).expect("coordinator");

        wait_for_calls(&calls, 1).await;

        assert!(coordinator.request_rescan(5).expect("schedule rescan"));
        assert!(!coordinator.request_rescan(10).expect("deduplicate rescan"));

        wait_for_calls(&calls, 2).await;
        {
            let recorded = heights
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(recorded.contains(&10));
        }
        if let Some(status) = coordinator.latest_status() {
            assert_eq!(status.pending_ranges, vec![(10, 11)]);
        } else {
            panic!("missing sync status");
        }

        coordinator.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn node_failures_surface_hints_in_status() {
        let engine = test_engine();
        let indexer = CountingIndexer::new();
        let coordinator =
            WalletSyncCoordinator::start(engine, Arc::new(indexer)).expect("coordinator");

        {
            let mut guard = coordinator.state.lock().unwrap();
            guard.last_status = Some(SyncStatus {
                latest_height: 0,
                current_height: 0,
                target_height: 0,
                mode: SyncMode::Resume { from_height: 0 },
                scanned_scripthashes: 0,
                discovered_transactions: 0,
                pending_ranges: Vec::new(),
                checkpoints: SyncCheckpoints::default(),
                hints: Vec::new(),
                node_issue: None,
            });
        }

        let error = NodeClientError::rejected_with_hint(
            "fee",
            NodeRejectionHint::FeeRateTooLow { required: Some(21) },
        );
        coordinator.record_node_failure(&error);
        let status = coordinator.latest_status().expect("status with node hint");
        assert_eq!(
            status.node_issue,
            Some("node rejected transaction (fee rate too low (required 21 sats/vB))".to_string())
        );
        assert_eq!(
            status.hints,
            vec!["Increase the fee rate to at least 21 sats/vB and retry.".to_string()]
        );

        coordinator.clear_node_failure();
        let cleared = coordinator
            .latest_status()
            .expect("status after clearing node hint");
        assert!(cleared.node_issue.is_none());
        assert!(cleared.hints.is_empty());

        coordinator.shutdown().await.expect("shutdown");
    }
}
