#![cfg(feature = "runtime")]

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tempfile::TempDir;
use tokio::time::sleep;

use rpp::runtime::config::QueueWeightsConfig;
use rpp::runtime::node::MempoolStatus;
use rpp_wallet::config::wallet::{
    WalletFeeConfig, WalletPolicyConfig, WalletProverConfig, WalletZsiConfig,
};
use rpp_wallet::db::WalletStore;
use rpp_wallet::engine::DraftTransaction;
use rpp_wallet::indexer::checkpoints::persist_birthday_height;
use rpp_wallet::indexer::client::{
    GetHeadersRequest, GetHeadersResponse, GetScripthashStatusRequest, GetScripthashStatusResponse,
    GetTransactionRequest, GetTransactionResponse, IndexedHeader, IndexedUtxo, IndexerClient,
    IndexerClientError, ListScripthashUtxosRequest, ListScripthashUtxosResponse,
    TransactionPayload, TxOutpoint,
};
use rpp_wallet::node_client::{ChainHead, NodeClient, NodeClientResult};
use rpp_wallet::telemetry::WalletActionTelemetry;
use rpp_wallet::wallet::{Wallet, WalletMode, WalletPaths};

const RESUME_HEIGHT_LABEL: &str = "indexer::resume_height";
const LAST_SCAN_TS_LABEL: &str = "indexer::last_scan_ts";
const BIRTHDAY_HEIGHT_LABEL: &str = "indexer::birthday_height";

#[tokio::test]
async fn fresh_sync_populates_store_and_checkpoints() {
    let setup = SyncSetup::new(120, 144, 75_000);
    let indexer = setup.indexer.clone();
    let coordinator = setup
        .wallet
        .start_sync_coordinator(setup.indexer_client())
        .expect("coordinator");

    wait_for(|| setup.wallet.list_utxos().unwrap().len() == 1).await;
    assert_eq!(indexer.headers_calls(), 1);
    assert_eq!(indexer.requested_heights(), vec![setup.birthday]);

    let balance = setup.wallet.balance().expect("balance");
    assert_eq!(balance.total(), setup.deposit_value as u128);

    let store = Arc::clone(&setup.store);
    assert_eq!(
        store
            .get_checkpoint(RESUME_HEIGHT_LABEL)
            .expect("resume checkpoint"),
        Some(setup.latest_height)
    );
    assert_eq!(
        store
            .get_checkpoint(BIRTHDAY_HEIGHT_LABEL)
            .expect("birthday checkpoint"),
        Some(setup.birthday)
    );
    let ts = store
        .get_checkpoint(LAST_SCAN_TS_LABEL)
        .expect("timestamp checkpoint")
        .expect("timestamp value");
    assert!(ts > 0);

    coordinator.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn resume_skips_duplicates_and_preserves_balance() {
    let setup = SyncSetup::new(64, 96, 50_000);
    let indexer = setup.indexer.clone();
    let coordinator = setup
        .wallet
        .start_sync_coordinator(setup.indexer_client())
        .expect("coordinator");

    wait_for(|| setup.wallet.list_utxos().unwrap().len() == 1).await;
    let initial_calls = indexer.headers_calls();
    assert_eq!(initial_calls, 1);

    let store = Arc::clone(&setup.store);
    let initial_resume = store
        .get_checkpoint(RESUME_HEIGHT_LABEL)
        .expect("resume checkpoint")
        .expect("resume value");
    let initial_timestamp = store
        .get_checkpoint(LAST_SCAN_TS_LABEL)
        .expect("timestamp checkpoint")
        .expect("timestamp value");
    let initial_balance = setup.wallet.balance().expect("balance");
    assert_eq!(initial_balance.total(), setup.deposit_value as u128);

    sleep(Duration::from_millis(10)).await;
    assert!(coordinator.request_resume_sync().expect("schedule resume"));
    wait_for(|| indexer.headers_calls() >= initial_calls + 1).await;

    let balance = setup.wallet.balance().expect("balance");
    assert_eq!(balance.total(), initial_balance.total());
    assert_eq!(setup.wallet.list_utxos().unwrap().len(), 1);
    assert_eq!(setup.wallet.list_transactions().unwrap().len(), 1);

    let updated_resume = store
        .get_checkpoint(RESUME_HEIGHT_LABEL)
        .expect("resume checkpoint")
        .expect("resume value");
    assert_eq!(updated_resume, initial_resume);

    let updated_timestamp = wait_for_result(|| {
        store
            .get_checkpoint(LAST_SCAN_TS_LABEL)
            .ok()
            .and_then(|value| value)
    })
    .await;
    assert!(updated_timestamp > initial_timestamp);

    coordinator.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn forced_rescan_replays_without_duplicates() {
    let setup = SyncSetup::new(200, 240, 90_000);
    let indexer = setup.indexer.clone();
    let coordinator = setup
        .wallet
        .start_sync_coordinator(setup.indexer_client())
        .expect("coordinator");

    wait_for(|| setup.wallet.list_utxos().unwrap().len() == 1).await;
    assert_eq!(indexer.headers_calls(), 1);

    let store = Arc::clone(&setup.store);
    let initial_resume = store
        .get_checkpoint(RESUME_HEIGHT_LABEL)
        .expect("resume checkpoint")
        .expect("resume value");
    let initial_birthday = store
        .get_checkpoint(BIRTHDAY_HEIGHT_LABEL)
        .expect("birthday checkpoint")
        .expect("birthday value");
    let initial_timestamp = store
        .get_checkpoint(LAST_SCAN_TS_LABEL)
        .expect("timestamp checkpoint")
        .expect("timestamp value");

    assert_eq!(setup.wallet.list_utxos().unwrap().len(), 1);
    assert_eq!(setup.wallet.list_transactions().unwrap().len(), 1);

    sleep(Duration::from_millis(10)).await;
    let rescan_height = initial_birthday - 50;
    indexer.set_latest_height(setup.latest_height + 32);
    assert!(coordinator
        .request_rescan(rescan_height)
        .expect("schedule rescan"));
    wait_for(|| indexer.headers_calls() >= 2).await;

    assert_eq!(setup.wallet.list_utxos().unwrap().len(), 1);
    assert_eq!(setup.wallet.list_transactions().unwrap().len(), 1);

    let resume_height = store
        .get_checkpoint(RESUME_HEIGHT_LABEL)
        .expect("resume checkpoint")
        .expect("resume value");
    assert_eq!(resume_height, indexer.latest_height());

    let birthday_height = store
        .get_checkpoint(BIRTHDAY_HEIGHT_LABEL)
        .expect("birthday checkpoint")
        .expect("birthday value");
    assert_eq!(birthday_height, rescan_height);

    let updated_timestamp = wait_for_result(|| {
        store
            .get_checkpoint(LAST_SCAN_TS_LABEL)
            .ok()
            .and_then(|value| value)
    })
    .await;
    assert!(updated_timestamp > initial_timestamp);
    assert!(resume_height >= initial_resume);

    coordinator.shutdown().await.expect("shutdown");
}

struct SyncSetup {
    _tempdir: TempDir,
    wallet: Wallet,
    store: Arc<WalletStore>,
    indexer: TestIndexer,
    birthday: u64,
    latest_height: u64,
    deposit_value: u64,
}

impl SyncSetup {
    fn new(birthday: u64, latest_height: u64, deposit_value: u64) -> Self {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(WalletStore::open(tempdir.path()).expect("store"));
        {
            let mut batch = store.batch().expect("batch");
            persist_birthday_height(&mut batch, Some(birthday)).expect("birthday");
            batch.commit().expect("commit");
        }

        let policy = WalletPolicyConfig {
            external_gap_limit: 4,
            internal_gap_limit: 4,
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
            WalletZsiConfig::default(),
            None,
            Arc::new(TestNodeClient::default()),
            WalletPaths::new(keystore, backup),
            Arc::new(WalletActionTelemetry::new(false)),
        )
        .expect("wallet");
        let deposit_address = wallet.derive_address(false).expect("address");

        let indexer = TestIndexer::new(latest_height);
        let txid = [3u8; 32];
        let utxo = IndexedUtxo::new(
            TxOutpoint::new(txid, 0),
            deposit_value,
            hex::decode(&deposit_address).expect("script"),
            Some(latest_height.saturating_sub(1)),
        );
        let payload = TransactionPayload::new(
            txid,
            Some(latest_height.saturating_sub(1)),
            Cow::Owned(vec![1, 2, 3]),
        );
        indexer.register_utxo(&deposit_address, utxo, payload);

        Self {
            _tempdir: tempdir,
            wallet,
            store,
            indexer,
            birthday,
            latest_height,
            deposit_value,
        }
    }

    fn indexer_client(&self) -> Arc<dyn IndexerClient> {
        Arc::new(self.indexer.clone())
    }
}

#[derive(Clone)]
struct TestIndexer {
    state: Arc<Mutex<TestIndexerState>>,
    headers_calls: Arc<AtomicUsize>,
    requested_heights: Arc<Mutex<Vec<u64>>>,
}

struct TestIndexerState {
    latest_height: u64,
    statuses: HashSet<[u8; 32]>,
    utxos: HashMap<[u8; 32], Vec<IndexedUtxo>>,
    transactions: HashMap<[u8; 32], TransactionPayload>,
}

impl TestIndexer {
    fn new(latest_height: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(TestIndexerState {
                latest_height,
                statuses: HashSet::new(),
                utxos: HashMap::new(),
                transactions: HashMap::new(),
            })),
            headers_calls: Arc::new(AtomicUsize::new(0)),
            requested_heights: Arc::new(Mutex::new(Vec::new())),
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

    fn requested_heights(&self) -> Vec<u64> {
        self.requested_heights.lock().expect("heights").clone()
    }

    fn set_latest_height(&self, height: u64) {
        let mut state = self.state.lock().expect("state");
        state.latest_height = height;
    }

    fn latest_height(&self) -> u64 {
        self.state.lock().expect("state").latest_height
    }
}

impl IndexerClient for TestIndexer {
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
    fn submit_tx(&self, _draft: &DraftTransaction) -> NodeClientResult<()> {
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
    for _ in 0..60 {
        if condition() {
            return;
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!("condition not satisfied within timeout");
}

async fn wait_for_result<F>(mut condition: F) -> u64
where
    F: FnMut() -> Option<u64>,
{
    for _ in 0..60 {
        if let Some(value) = condition() {
            return value;
        }
        sleep(Duration::from_millis(25)).await;
    }
    panic!("condition not satisfied within timeout");
}
