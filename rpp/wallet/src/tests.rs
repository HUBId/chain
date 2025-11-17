use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::time::sleep;

use crate::engine::DraftTransaction;
use crate::indexer::client::{
    GetHeadersRequest, GetHeadersResponse, GetScripthashStatusRequest, GetScripthashStatusResponse,
    GetTransactionRequest, GetTransactionResponse, IndexedHeader, IndexedUtxo, IndexerClient,
    IndexerClientError, ListScripthashUtxosRequest, ListScripthashUtxosResponse,
    TransactionPayload,
};
use crate::node_client::{
    BlockFeeSummary, ChainHead, MempoolInfo, MempoolStatus, NodeClient, NodeClientResult,
    QueueWeightsConfig, TransactionSubmission,
};
use crate::rpc::dto::{JsonRpcRequest, JsonRpcResponse, JSONRPC_VERSION};

/// Minimal indexer implementation used by workflow integration tests.
#[derive(Clone)]
pub struct TestIndexer {
    state: Arc<Mutex<TestIndexerState>>,
}

struct TestIndexerState {
    latest_height: u64,
    statuses: HashSet<[u8; 32]>,
    utxos: HashMap<[u8; 32], Vec<IndexedUtxo>>,
    transactions: HashMap<[u8; 32], TransactionPayload>,
}

impl TestIndexer {
    pub fn new(latest_height: u64) -> Self {
        Self {
            state: Arc::new(Mutex::new(TestIndexerState {
                latest_height,
                statuses: HashSet::new(),
                utxos: HashMap::new(),
                transactions: HashMap::new(),
            })),
        }
    }

    pub fn register_utxo(&self, address: &str, utxo: IndexedUtxo, payload: TransactionPayload) {
        let mut state = self.state.lock().expect("test indexer state");
        let hash = decode_address(address);
        state.statuses.insert(hash);
        state.utxos.entry(hash).or_default().push(utxo);
        state.transactions.insert(payload.txid, payload);
    }
}

impl IndexerClient for TestIndexer {
    fn get_headers(
        &self,
        request: &GetHeadersRequest,
    ) -> Result<GetHeadersResponse, IndexerClientError> {
        let state = self.state.lock().expect("test indexer state");
        let header = IndexedHeader::new(request.start_height, [0u8; 32], [0u8; 32], Vec::new());
        Ok(GetHeadersResponse::new(state.latest_height, vec![header]))
    }

    fn get_scripthash_status(
        &self,
        request: &GetScripthashStatusRequest,
    ) -> Result<GetScripthashStatusResponse, IndexerClientError> {
        let state = self.state.lock().expect("test indexer state");
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
        let state = self.state.lock().expect("test indexer state");
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
        let state = self.state.lock().expect("test indexer state");
        let tx = state.transactions.get(&request.txid).cloned();
        Ok(GetTransactionResponse::new(tx))
    }
}

/// Recording node client used by integration suites to capture submissions.
#[derive(Default)]
pub struct RecordingNodeClient {
    submissions: Mutex<Vec<TransactionSubmission>>,
    raw_submissions: Mutex<Vec<Vec<u8>>>,
    fee_rate: u64,
    mempool_info: MempoolInfo,
    recent_blocks: Vec<BlockFeeSummary>,
}

impl RecordingNodeClient {
    pub fn submission_count(&self) -> usize {
        self.submissions.lock().expect("submissions").len()
    }

    pub fn last_submission(&self) -> Option<DraftTransaction> {
        self.submissions
            .lock()
            .expect("submissions")
            .last()
            .map(DraftTransaction::from)
    }

    pub fn set_fee_rate(&self, fee_rate: u64) {
        self.fee_rate = fee_rate;
    }

    pub fn set_mempool_info(&mut self, info: MempoolInfo) {
        self.mempool_info = info;
    }

    pub fn set_recent_blocks(&mut self, blocks: Vec<BlockFeeSummary>) {
        self.recent_blocks = blocks;
    }
}

impl NodeClient for RecordingNodeClient {
    fn submit_tx(&self, submission: &TransactionSubmission) -> NodeClientResult<()> {
        self.submissions
            .lock()
            .expect("submissions")
            .push(submission.clone());
        Ok(())
    }

    fn submit_raw_tx(&self, tx: &[u8]) -> NodeClientResult<()> {
        self.raw_submissions
            .lock()
            .expect("raw submissions")
            .push(tx.to_vec());
        Ok(())
    }

    fn estimate_fee(&self, _confirmation_target: u16) -> NodeClientResult<u64> {
        Ok(self.fee_rate.max(1))
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

    fn mempool_info(&self) -> NodeClientResult<MempoolInfo> {
        Ok(self.mempool_info.clone())
    }

    fn recent_blocks(&self, limit: usize) -> NodeClientResult<Vec<BlockFeeSummary>> {
        Ok(self.recent_blocks.iter().take(limit).cloned().collect())
    }
}

/// Await an RPC response and deserialize it into the requested type.
pub async fn rpc_call<T: DeserializeOwned>(
    client: &Client,
    endpoint: &str,
    method: &str,
    params: Option<Value>,
) -> Result<T> {
    let request = JsonRpcRequest {
        jsonrpc: Some(JSONRPC_VERSION.to_string()),
        id: Some(Value::from(1)),
        method: method.to_string(),
        params,
    };
    let response = client
        .post(format!("{endpoint}/rpc"))
        .json(&request)
        .send()
        .await
        .with_context(|| format!("send {method} request"))?;
    if !response.status().is_success() {
        bail!("wallet RPC returned HTTP status {}", response.status());
    }
    let payload: JsonRpcResponse = response.json().await.context("decode JSON-RPC response")?;
    if let Some(error) = payload.error {
        bail!("wallet RPC error ({}): {}", error.code, error.message);
    }
    let result = payload
        .result
        .context("wallet RPC response missing result field")?;
    let typed = serde_json::from_value(result).context("decode JSON-RPC payload")?;
    Ok(typed)
}

/// Extract a labelled field from CLI output.
pub fn extract_field(output: &str, label: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with(label) {
            trimmed
                .split_once(':')
                .map(|(_, value)| value.trim().to_string())
        } else {
            None
        }
    })
}

/// Wait until the provided condition returns `true`.
pub async fn wait_for<F>(mut condition: F)
where
    F: FnMut() -> bool,
{
    for _ in 0..120 {
        if condition() {
            return;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not satisfied within timeout");
}

/// Wait for a condition to yield a value and return it.
pub async fn wait_for_some<F, T>(mut condition: F) -> T
where
    F: FnMut() -> Option<T>,
{
    for _ in 0..120 {
        if let Some(value) = condition() {
            return value;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("condition not satisfied within timeout");
}

/// Decode the first 32 bytes of the hex-encoded address.
pub fn decode_address(address: &str) -> [u8; 32] {
    let bytes = hex::decode(address).expect("decode wallet address");
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes[..32]);
    hash
}
