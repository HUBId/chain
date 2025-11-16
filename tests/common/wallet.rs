use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use rpp::runtime::wallet::sync::SyncStatus;
use rpp_wallet::config::wallet::{
    WalletFeeConfig, WalletHwConfig, WalletPolicyConfig, WalletProverConfig, WalletZsiConfig,
};
use rpp_wallet::db::WalletStore;
use rpp_wallet::indexer::checkpoints::persist_birthday_height;
use rpp_wallet::indexer::client::{
    GetHeadersRequest, GetHeadersResponse, GetScripthashStatusRequest, GetScripthashStatusResponse,
    GetTransactionRequest, GetTransactionResponse, IndexedHeader, IndexedUtxo, IndexerClient,
    IndexerClientError, ListScripthashUtxosRequest, ListScripthashUtxosResponse,
    TransactionPayload, TxOutpoint,
};
use rpp_wallet::node_client::{
    BlockFeeSummary, ChainHead, MempoolInfo, MempoolStatus, NodeClient, NodeClientError,
    NodeClientResult, QueueWeightsConfig, TransactionSubmission,
};
use rpp_wallet::proof_backend::ProofBackend;
use rpp_wallet::telemetry::WalletActionTelemetry;
use rpp_wallet::wallet::{Wallet, WalletError, WalletMode, WalletPaths, WalletSyncCoordinator};
use tempfile::TempDir;
use tokio::time::sleep;

/// Builder used to configure wallet integration test fixtures.
#[derive(Clone)]
pub struct WalletTestBuilder {
    deposit_values: Vec<u64>,
    birthday_height: u64,
    latest_height: u64,
    policy: WalletPolicyConfig,
    fees: WalletFeeConfig,
    prover: WalletProverConfig,
    zsi: WalletZsiConfig,
    zsi_backend: Option<Arc<dyn ProofBackend>>,
}

impl Default for WalletTestBuilder {
    fn default() -> Self {
        Self {
            deposit_values: vec![90_000],
            birthday_height: 120,
            latest_height: 180,
            policy: WalletPolicyConfig::default(),
            fees: WalletFeeConfig::default(),
            prover: WalletProverConfig::default(),
            zsi: WalletZsiConfig::default(),
            zsi_backend: None,
        }
    }
}

impl WalletTestBuilder {
    pub fn with_deposits(mut self, values: Vec<u64>) -> Self {
        self.deposit_values = values;
        self
    }

    pub fn with_birthday_height(mut self, height: u64) -> Self {
        self.birthday_height = height;
        self
    }

    pub fn with_latest_height(mut self, height: u64) -> Self {
        self.latest_height = height;
        self
    }

    pub fn with_policy(mut self, policy: WalletPolicyConfig) -> Self {
        self.policy = policy;
        self
    }

    pub fn update_policy<F>(mut self, mutate: F) -> Self
    where
        F: FnOnce(&mut WalletPolicyConfig),
    {
        mutate(&mut self.policy);
        self
    }

    pub fn with_fees(mut self, fees: WalletFeeConfig) -> Self {
        self.fees = fees;
        self
    }

    pub fn update_fees<F>(mut self, mutate: F) -> Self
    where
        F: FnOnce(&mut WalletFeeConfig),
    {
        mutate(&mut self.fees);
        self
    }

    pub fn with_prover(mut self, prover: WalletProverConfig) -> Self {
        self.prover = prover;
        self
    }

    pub fn with_zsi_config(mut self, config: WalletZsiConfig) -> Self {
        self.zsi = config;
        self
    }

    pub fn with_zsi_backend(mut self, backend: Arc<dyn ProofBackend>) -> Self {
        self.zsi_backend = Some(backend);
        self
    }

    pub fn build(self) -> Result<WalletTestFixture> {
        WalletTestFixture::new(
            self.deposit_values,
            self.birthday_height,
            self.latest_height,
            self.policy,
            self.fees,
            self.prover,
            self.zsi,
            self.zsi_backend,
        )
    }
}

#[derive(Clone, Debug)]
pub struct DepositRecord {
    pub address: String,
    pub amount: u64,
    pub txid: [u8; 32],
}

/// Fixture encapsulating a wallet instance together with mocked infrastructure.
pub struct WalletTestFixture {
    _tempdir: TempDir,
    wallet: Arc<Wallet>,
    node: Arc<MockNodeClient>,
    indexer: Arc<MockIndexer>,
    birthday_height: u64,
    latest_height: u64,
    deposits: Vec<DepositRecord>,
}

impl WalletTestFixture {
    fn new(
        deposit_values: Vec<u64>,
        birthday_height: u64,
        latest_height: u64,
        mut policy: WalletPolicyConfig,
        fees: WalletFeeConfig,
        prover: WalletProverConfig,
        zsi: WalletZsiConfig,
        zsi_backend: Option<Arc<dyn ProofBackend>>,
    ) -> Result<Self> {
        let tempdir = TempDir::new().context("create wallet temp directory")?;
        let store = Arc::new(WalletStore::open(tempdir.path()).context("open wallet store")?);

        {
            let mut batch = store.batch().context("open wallet store batch")?;
            persist_birthday_height(&mut batch, Some(birthday_height))
                .context("persist wallet birthday height")?;
            batch.commit().context("commit birthday checkpoint")?;
        }

        policy.pending_lock_timeout = policy.pending_lock_timeout.max(1);

        let node = Arc::new(MockNodeClient::new(fees.default_sats_per_vbyte));
        let wallet = Arc::new(
            Wallet::new(
                Arc::clone(&store),
                WalletMode::Full {
                    root_seed: seeded_seed(),
                },
                policy.clone(),
                fees,
                prover,
                WalletHwConfig::default(),
                zsi,
                zsi_backend,
                Arc::clone(&node),
                WalletPaths::for_data_dir(tempdir.path()),
                Arc::new(WalletActionTelemetry::new(false)),
            )
            .context("construct wallet instance")?,
        );

        let mut deposits = Vec::new();
        let indexer = Arc::new(MockIndexer::new(latest_height));
        for (index, amount) in deposit_values.iter().enumerate() {
            let address = wallet
                .derive_address(false)
                .context("derive deposit address")?;
            let mut txid = [0u8; 32];
            txid[0] = u8::try_from(index + 1).unwrap_or(u8::MAX);
            let script = decode_address(&address);
            let utxo = IndexedUtxo::new(
                TxOutpoint::new(txid, 0),
                *amount,
                script,
                Some(latest_height.saturating_sub(1)),
            );
            let payload = TransactionPayload::new(
                txid,
                Some(latest_height.saturating_sub(1)),
                Cow::Owned(vec![index as u8; 4]),
            );
            indexer.register_utxo(&address, utxo, payload);
            deposits.push(DepositRecord {
                address,
                amount: *amount,
                txid,
            });
        }

        Ok(Self {
            _tempdir: tempdir,
            wallet,
            node,
            indexer,
            birthday_height,
            latest_height,
            deposits,
        })
    }

    pub fn wallet(&self) -> Arc<Wallet> {
        Arc::clone(&self.wallet)
    }

    pub fn node(&self) -> Arc<MockNodeClient> {
        Arc::clone(&self.node)
    }

    pub fn indexer(&self) -> Arc<MockIndexer> {
        Arc::clone(&self.indexer)
    }

    pub fn birthday_height(&self) -> u64 {
        self.birthday_height
    }

    pub fn latest_height(&self) -> u64 {
        self.latest_height
    }

    pub fn deposits(&self) -> &[DepositRecord] {
        &self.deposits
    }

    pub fn total_deposit(&self) -> u64 {
        self.deposits.iter().map(|deposit| deposit.amount).sum()
    }

    pub fn indexer_client(&self) -> Arc<dyn IndexerClient> {
        Arc::clone(&self.indexer) as Arc<dyn IndexerClient>
    }

    pub fn start_sync(&self) -> Result<WalletSyncCoordinator, WalletError> {
        self.wallet
            .start_sync_coordinator(self.indexer_client())
            .map_err(Into::into)
    }
}

/// Recording indexer client used to simulate wallet sync flows in integration tests.
#[derive(Clone)]
pub struct MockIndexer {
    state: Arc<Mutex<IndexerState>>,
}

struct IndexerState {
    latest_height: u64,
    statuses: HashSet<[u8; 32]>,
    utxos: HashMap<[u8; 32], Vec<IndexedUtxo>>,
    transactions: HashMap<[u8; 32], TransactionPayload>,
    scan_requests: Vec<u64>,
}

impl MockIndexer {
    fn new(latest_height: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(IndexerState {
                latest_height,
                statuses: HashSet::new(),
                utxos: HashMap::new(),
                transactions: HashMap::new(),
                scan_requests: Vec::new(),
            })),
        }
    }

    pub fn register_utxo(&self, address: &str, utxo: IndexedUtxo, payload: TransactionPayload) {
        let hash = decode_address(address);
        let mut state = self.state.lock().unwrap();
        state.statuses.insert(hash);
        state.utxos.entry(hash).or_default().push(utxo);
        state.transactions.insert(payload.txid, payload);
    }

    pub fn scan_requests(&self) -> Vec<u64> {
        let state = self.state.lock().unwrap();
        state.scan_requests.clone()
    }

    pub fn set_latest_height(&self, height: u64) {
        let mut state = self.state.lock().unwrap();
        state.latest_height = height;
    }
}

impl IndexerClient for MockIndexer {
    fn get_headers(
        &self,
        request: &GetHeadersRequest,
    ) -> Result<GetHeadersResponse, IndexerClientError> {
        let mut state = self.state.lock().unwrap();
        state.scan_requests.push(request.start_height);
        let header = IndexedHeader::new(request.start_height, [0u8; 32], [0u8; 32], Vec::new());
        Ok(GetHeadersResponse::new(state.latest_height, vec![header]))
    }

    fn get_scripthash_status(
        &self,
        request: &GetScripthashStatusRequest,
    ) -> Result<GetScripthashStatusResponse, IndexerClientError> {
        let state = self.state.lock().unwrap();
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
        let state = self.state.lock().unwrap();
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
        let state = self.state.lock().unwrap();
        let tx = state.transactions.get(&request.txid).cloned();
        Ok(GetTransactionResponse::new(tx))
    }
}

/// Recording node client exposing hooks for fee hints and broadcast outcomes.
#[derive(Default)]
pub struct MockNodeClient {
    state: Mutex<NodeState>,
    head: Mutex<ChainHead>,
    mempool_status: Mutex<MempoolStatus>,
}

struct NodeState {
    submissions: Vec<SubmittedDraft>,
    raw_submissions: Vec<Vec<u8>>,
    next_error: Option<NodeClientError>,
    fee_estimate: u64,
    mempool_info: MempoolInfo,
    recent_blocks: Vec<BlockFeeSummary>,
}

#[derive(Clone, Debug)]
pub struct SubmittedDraft {
    pub fee_rate: u64,
    pub total_input_value: u128,
}

impl MockNodeClient {
    pub fn new(default_fee: u64) -> Self {
        Self {
            state: Mutex::new(NodeState {
                submissions: Vec::new(),
                raw_submissions: Vec::new(),
                next_error: None,
                fee_estimate: default_fee,
                mempool_info: MempoolInfo {
                    tx_count: 0,
                    vsize_limit: 1_000_000,
                    vsize_in_use: 0,
                    min_fee_rate: None,
                    max_fee_rate: None,
                },
                recent_blocks: Vec::new(),
            }),
            head: Mutex::new(ChainHead::new(0, [0u8; 32])),
            mempool_status: Mutex::new(MempoolStatus {
                transactions: Vec::new(),
                identities: Vec::new(),
                votes: Vec::new(),
                uptime_proofs: Vec::new(),
                queue_weights: QueueWeightsConfig::default(),
            }),
        }
    }

    pub fn set_fee_estimate(&self, rate: u64) {
        let mut state = self.state.lock().unwrap();
        state.fee_estimate = rate;
    }

    pub fn set_mempool_info(&self, info: MempoolInfo) {
        let mut state = self.state.lock().unwrap();
        state.mempool_info = info;
    }

    pub fn set_recent_blocks(&self, blocks: Vec<BlockFeeSummary>) {
        let mut state = self.state.lock().unwrap();
        state.recent_blocks = blocks;
    }

    pub fn set_chain_head(&self, head: ChainHead) {
        *self.head.lock().unwrap() = head;
    }

    pub fn set_mempool_status(&self, status: MempoolStatus) {
        *self.mempool_status.lock().unwrap() = status;
    }

    pub fn fail_next_submission(&self, error: NodeClientError) {
        let mut state = self.state.lock().unwrap();
        state.next_error = Some(error);
    }

    pub fn submission_count(&self) -> usize {
        let state = self.state.lock().unwrap();
        state.submissions.len()
    }

    pub fn submissions(&self) -> Vec<SubmittedDraft> {
        let state = self.state.lock().unwrap();
        state.submissions.clone()
    }

    pub fn last_submission(&self) -> Option<SubmittedDraft> {
        let state = self.state.lock().unwrap();
        state.submissions.last().cloned()
    }
}

impl NodeClient for MockNodeClient {
    fn submit_tx(&self, submission: &TransactionSubmission) -> NodeClientResult<()> {
        let mut state = self.state.lock().unwrap();
        if let Some(error) = state.next_error.take() {
            return Err(error);
        }
        state.submissions.push(SubmittedDraft {
            fee_rate: submission.fee_rate,
            total_input_value: submission.total_input_value(),
        });
        Ok(())
    }

    fn submit_raw_tx(&self, tx: &[u8]) -> NodeClientResult<()> {
        let mut state = self.state.lock().unwrap();
        if let Some(error) = state.next_error.take() {
            return Err(error);
        }
        state.raw_submissions.push(tx.to_vec());
        Ok(())
    }

    fn estimate_fee(&self, _confirmation_target: u16) -> NodeClientResult<u64> {
        let state = self.state.lock().unwrap();
        Ok(state.fee_estimate.max(1))
    }

    fn chain_head(&self) -> NodeClientResult<ChainHead> {
        Ok(*self.head.lock().unwrap())
    }

    fn mempool_status(&self) -> NodeClientResult<MempoolStatus> {
        Ok(self.mempool_status.lock().unwrap().clone())
    }

    fn mempool_info(&self) -> NodeClientResult<MempoolInfo> {
        let state = self.state.lock().unwrap();
        Ok(state.mempool_info.clone())
    }

    fn recent_blocks(&self, limit: usize) -> NodeClientResult<Vec<BlockFeeSummary>> {
        let state = self.state.lock().unwrap();
        Ok(state.recent_blocks.iter().take(limit).cloned().collect())
    }
}

pub async fn wait_for<F, Fut>(mut predicate: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..120 {
        if predicate().await {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not satisfied within timeout");
}

pub async fn wait_for_some<F, Fut, T>(mut predicate: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    for _ in 0..120 {
        if let Some(value) = predicate().await {
            return value;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not satisfied within timeout");
}

pub async fn wait_for_status<F>(sync: &Arc<WalletSyncCoordinator>, predicate: F) -> SyncStatus
where
    F: Fn(&SyncStatus) -> bool,
{
    wait_for_some(|| async { sync.latest_status().filter(|status| predicate(status)) }).await
}

fn decode_address(address: &str) -> Vec<u8> {
    hex::decode(address).expect("decode wallet address")
}

fn seeded_seed() -> [u8; 32] {
    [
        0x11, 0x42, 0x58, 0x7a, 0x90, 0xab, 0xcd, 0xef, 0x10, 0x27, 0x39, 0x4b, 0x5d, 0x6f, 0x80,
        0x91, 0xa3, 0xb5, 0xc7, 0xd9, 0xeb, 0xfc, 0x0d, 0x1e, 0x2f, 0x31, 0x43, 0x55, 0x67, 0x79,
        0x8b, 0x9d,
    ]
}
