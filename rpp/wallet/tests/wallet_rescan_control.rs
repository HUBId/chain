use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tempfile::TempDir;
use tokio::time::sleep;

use rpp_wallet::config::wallet::{
    WalletFeeConfig, WalletHwConfig, WalletPolicyConfig, WalletProverConfig, WalletZsiConfig,
};
use rpp_wallet::db::WalletStore;
use rpp_wallet::indexer::checkpoints::{
    last_compact_scan_ts, last_full_rescan_ts, last_scan_ts, last_targeted_rescan_ts,
    persist_birthday_height, resume_height,
};
use rpp_wallet::indexer::client::{
    GetHeadersRequest, GetHeadersResponse, GetScripthashStatusRequest, GetScripthashStatusResponse,
    GetTransactionRequest, GetTransactionResponse, IndexedHeader, IndexedUtxo, IndexerClient,
    IndexerClientError, ListScripthashUtxosRequest, ListScripthashUtxosResponse,
    TransactionPayload, TxOutpoint,
};
use rpp_wallet::node_client::{
    ChainHead, MempoolStatus, NodeClient, NodeClientResult, QueueWeightsConfig,
    TransactionSubmission,
};
use rpp_wallet::wallet::{Wallet, WalletMode, WalletPaths};

const RESUME_HEIGHT_LABEL: &str = "indexer::resume_height";

#[tokio::test]
async fn rescan_abort_persists_progress() {
    let setup = RescanSetup::new(48, 120, 42_000, 12);
    let indexer = setup.indexer.clone();
    let coordinator = setup
        .wallet
        .start_sync_coordinator(setup.indexer_client())
        .expect("coordinator");

    wait_for(|| setup.wallet.list_utxos().unwrap().len() == 1).await;

    indexer.set_latest_height(setup.latest_height + 50);
    indexer.set_delay(Duration::from_millis(15));
    assert!(coordinator
        .request_rescan(setup.birthday.saturating_sub(10))
        .expect("schedule rescan"));

    indexer.wait_for_scans(6).await;
    assert!(coordinator.abort_rescan());

    wait_for(|| !coordinator.is_syncing()).await;
    let error = coordinator.last_error().expect("aborted error").to_string();
    assert!(error.contains("RESCAN_ABORTED"));

    let resume_height = setup
        .store
        .get_checkpoint(RESUME_HEIGHT_LABEL)
        .expect("resume checkpoint")
        .expect("resume value");
    assert_eq!(resume_height, indexer.latest_height());

    coordinator.shutdown().await.expect("shutdown");

    let restart = setup
        .wallet
        .start_sync_coordinator(setup.indexer_client())
        .expect("restart coordinator");

    assert!(restart
        .request_rescan(setup.birthday.saturating_sub(10))
        .expect("schedule resumed rescan"));
    wait_for(|| indexer.headers_calls() >= 3).await;

    let utxos = setup.wallet.list_utxos().expect("utxos");
    let txs = setup.wallet.list_transactions().expect("txs");
    assert_eq!(utxos.len(), setup.deposits.len());
    assert_eq!(txs.len(), setup.deposits.len());

    let checkpoints = (
        resume_height(&setup.store).expect("resume height"),
        last_scan_ts(&setup.store).expect("last scan"),
        last_full_rescan_ts(&setup.store).expect("full rescan"),
        last_compact_scan_ts(&setup.store).expect("compact scan"),
        last_targeted_rescan_ts(&setup.store).expect("targeted rescan"),
    );
    assert!(checkpoints.0.is_some());
    assert!(checkpoints.1.is_some());
    assert!(checkpoints.2.is_some());
    assert!(checkpoints.3.is_some());
    assert!(checkpoints.4.is_some());

    restart.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn rescan_status_survives_restart() {
    let setup = RescanSetup::new(32, 80, 21_000, 8);
    let indexer = setup.indexer.clone();
    let coordinator = setup
        .wallet
        .start_sync_coordinator(setup.indexer_client())
        .expect("coordinator");

    wait_for(|| setup.wallet.list_utxos().unwrap().len() == setup.deposits.len()).await;

    indexer.set_latest_height(setup.latest_height + 20);
    assert!(coordinator
        .request_rescan(setup.birthday.saturating_sub(4))
        .expect("schedule rescan"));
    indexer.wait_for_scans(4).await;

    let pre_restart_resume = setup
        .store
        .get_checkpoint(RESUME_HEIGHT_LABEL)
        .expect("resume checkpoint")
        .expect("resume value");

    coordinator.shutdown().await.expect("shutdown");

    let restarted = setup
        .wallet
        .start_sync_coordinator(setup.indexer_client())
        .expect("restart coordinator");
    indexer.set_delay(Duration::from_millis(5));
    assert!(restarted
        .request_rescan(setup.birthday.saturating_sub(4))
        .expect("reschedule rescan"));
    wait_for(|| indexer.headers_calls() >= 2).await;

    let resume_height = setup
        .store
        .get_checkpoint(RESUME_HEIGHT_LABEL)
        .expect("resume checkpoint")
        .expect("resume value");
    assert!(resume_height >= pre_restart_resume);

    let status = restarted.latest_status().expect("latest status");
    assert_eq!(status.checkpoints.resume_height, Some(resume_height));
    assert_eq!(status.discovered_transactions, setup.deposits.len());
    assert_eq!(status.scanned_scripthashes, setup.expected_scans);

    let utxos = setup.wallet.list_utxos().expect("utxos");
    let txs = setup.wallet.list_transactions().expect("txs");
    assert_eq!(utxos.len(), setup.deposits.len());
    assert_eq!(txs.len(), setup.deposits.len());

    restarted.shutdown().await.expect("shutdown");
}

struct RescanSetup {
    _tempdir: TempDir,
    wallet: Wallet,
    store: Arc<WalletStore>,
    indexer: ControlledIndexer,
    birthday: u64,
    latest_height: u64,
    deposits: Vec<[u8; 32]>,
    expected_scans: usize,
}

impl RescanSetup {
    fn new(birthday: u64, latest_height: u64, deposit_value: u64, deposit_count: usize) -> Self {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(tempdir.path()).expect("store"));
        {
            let mut batch = store.batch().expect("batch");
            persist_birthday_height(&mut batch, Some(birthday)).expect("birthday");
            batch.commit().expect("commit");
        }

        let policy = WalletPolicyConfig {
            external_gap_limit: deposit_count * 2,
            internal_gap_limit: deposit_count,
            min_confirmations: 1,
        };
        let keystore = tempdir.path().join("keystore.toml");
        let backup = tempdir.path().join("backups");
        let wallet = Wallet::new(
            Arc::clone(&store),
            WalletMode::Full {
                root_seed: [7u8; 32],
            },
            policy,
            WalletFeeConfig::default(),
            WalletProverConfig::default(),
            WalletHwConfig::default(),
            WalletZsiConfig::default(),
            None,
            Arc::new(TestNodeClient::default()),
            WalletPaths::new(keystore, backup),
            Arc::new(rpp_wallet::telemetry::WalletActionTelemetry::new(false)),
        )
        .expect("wallet");

        let indexer = ControlledIndexer::new(latest_height);
        let mut deposits = Vec::new();
        for i in 0..deposit_count {
            let address = wallet.derive_address(false).expect("address");
            let txid = [i as u8 + 1; 32];
            let utxo = IndexedUtxo::new(
                TxOutpoint::new(txid, 0),
                deposit_value + i as u64,
                hex::decode(&address).expect("script"),
                Some(latest_height.saturating_sub(2)),
            );
            let payload = TransactionPayload::new(
                txid,
                Some(latest_height.saturating_sub(2)),
                Cow::Owned(vec![i as u8]),
            );
            indexer.register_utxo(&address, utxo, payload);
            deposits.push(txid);
        }

        Self {
            _tempdir: tempdir,
            wallet,
            store,
            indexer,
            birthday,
            latest_height,
            deposits,
            expected_scans: deposit_count * 2,
        }
    }

    fn indexer_client(&self) -> Arc<dyn IndexerClient> {
        Arc::new(self.indexer.clone())
    }
}

#[derive(Clone)]
struct ControlledIndexer {
    state: Arc<Mutex<IndexerState>>,
    scan_calls: Arc<AtomicUsize>,
    headers_calls: Arc<AtomicUsize>,
    requested_heights: Arc<Mutex<Vec<u64>>>,
    delay_ms: Arc<AtomicUsize>,
    notified: Arc<tokio::sync::Notify>,
}

struct IndexerState {
    latest_height: u64,
    statuses: HashSet<[u8; 32]>,
    utxos: HashMap<[u8; 32], Vec<IndexedUtxo>>,
    transactions: HashMap<[u8; 32], TransactionPayload>,
}

impl ControlledIndexer {
    fn new(latest_height: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(IndexerState {
                latest_height,
                statuses: HashSet::new(),
                utxos: HashMap::new(),
                transactions: HashMap::new(),
            })),
            scan_calls: Arc::new(AtomicUsize::new(0)),
            headers_calls: Arc::new(AtomicUsize::new(0)),
            requested_heights: Arc::new(Mutex::new(Vec::new())),
            delay_ms: Arc::new(AtomicUsize::new(0)),
            notified: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn register_utxo(&self, address: &str, utxo: IndexedUtxo, payload: TransactionPayload) {
        let hash = decode_address(address);
        let mut state = self.state.lock().expect("state");
        state.statuses.insert(hash);
        state.utxos.entry(hash).or_default().push(utxo.clone());
        state.transactions.insert(utxo.outpoint.txid, payload);
    }

    fn headers_calls(&self) -> usize {
        self.headers_calls.load(Ordering::SeqCst)
    }

    fn set_latest_height(&self, height: u64) {
        let mut state = self.state.lock().expect("state");
        state.latest_height = height;
    }

    fn latest_height(&self) -> u64 {
        self.state.lock().expect("state").latest_height
    }

    fn set_delay(&self, delay: Duration) {
        self.delay_ms
            .store(delay.as_millis() as usize, Ordering::SeqCst);
    }

    async fn wait_for_scans(&self, target: usize) {
        for _ in 0..80 {
            if self.scan_calls.load(Ordering::SeqCst) >= target {
                return;
            }
            self.notified.notified().await;
        }
        panic!("scan count did not reach target");
    }
}

impl IndexerClient for ControlledIndexer {
    fn get_headers(
        &self,
        request: &GetHeadersRequest,
    ) -> Result<GetHeadersResponse, IndexerClientError> {
        self.headers_calls.fetch_add(1, Ordering::SeqCst);
        self.requested_heights
            .lock()
            .expect("heights")
            .push(request.start_height);
        let state = self.state.lock().expect("state");
        let header = IndexedHeader::new(request.start_height, [0u8; 32], [0u8; 32], Vec::new());
        Ok(GetHeadersResponse::new(state.latest_height, vec![header]))
    }

    fn get_scripthash_status(
        &self,
        request: &GetScripthashStatusRequest,
    ) -> Result<GetScripthashStatusResponse, IndexerClientError> {
        self.scan_calls.fetch_add(1, Ordering::SeqCst);
        self.notified.notify_waiters();
        let delay = self.delay_ms.load(Ordering::SeqCst);
        if delay > 0 {
            std::thread::sleep(Duration::from_millis(delay as u64));
        }
        let state = self.state.lock().expect("state");
        let status = state
            .statuses
            .contains(&request.scripthash)
            .then(|| hex::encode(request.scripthash));
        Ok(GetScripthashStatusResponse::new(status))
    }

    fn list_scripthash_utxos(
        &self,
        request: &ListScripthashUtxosRequest,
    ) -> Result<ListScripthashUtxosResponse, IndexerClientError> {
        let state = self.state.lock().expect("state");
        let utxos = state
            .utxos
            .get(&request.scripthash)
            .cloned()
            .unwrap_or_default();
        Ok(ListScripthashUtxosResponse::new(utxos))
    }

    fn get_transaction(
        &self,
        request: &GetTransactionRequest,
    ) -> Result<GetTransactionResponse, IndexerClientError> {
        let state = self.state.lock().expect("state");
        let tx = state.transactions.get(&request.txid).cloned();
        Ok(GetTransactionResponse::new(tx))
    }
}

#[derive(Clone, Default)]
struct TestNodeClient;

impl NodeClient for TestNodeClient {
    fn submit_tx(&self, _submission: &TransactionSubmission) -> NodeClientResult<()> {
        Ok(())
    }

    fn submit_raw_tx(&self, _tx: &[u8]) -> NodeClientResult<()> {
        Ok(())
    }

    fn estimate_fee(&self, _confirmation_target: u16) -> NodeClientResult<u64> {
        Ok(1)
    }

    fn chain_head(&self) -> NodeClientResult<ChainHead> {
        Ok(ChainHead::new(0, [0u8; 32]))
    }

    fn mempool_status(&self) -> NodeClientResult<MempoolStatus> {
        Ok(MempoolStatus {
            transactions: Vec::new(),
            identities: Vec::new(),
            votes: Vec::new(),
            uptime_proofs: Vec::new(),
            queue_weights: QueueWeightsConfig::default(),
        })
    }
}

fn decode_address(address: &str) -> [u8; 32] {
    let bytes = hex::decode(address).expect("decode address");
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes[..32]);
    hash
}

async fn wait_for<F>(mut condition: F)
where
    F: FnMut() -> bool,
{
    for _ in 0..120 {
        if condition() {
            return;
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!("condition not satisfied within timeout");
}
