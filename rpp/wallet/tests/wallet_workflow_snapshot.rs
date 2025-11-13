use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use assert_cmd::Command;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::time::sleep;

use rpp::runtime::config::QueueWeightsConfig;
use rpp::runtime::node::MempoolStatus;
use rpp::runtime::telemetry::metrics::RuntimeMetrics;
use rpp::runtime::wallet::{
    json_rpc_router, DeterministicSync, WalletRuntime, WalletRuntimeConfig, WalletRuntimeHandle,
};
use rpp_wallet::config::wallet::{WalletFeeConfig, WalletPolicyConfig, WalletProverConfig};
use rpp_wallet::db::WalletStore;
use rpp_wallet::engine::DraftTransaction;
use rpp_wallet::indexer::checkpoints::persist_birthday_height;
use rpp_wallet::indexer::client::{
    GetHeadersRequest, GetHeadersResponse, GetScripthashStatusRequest, GetScripthashStatusResponse,
    GetTransactionRequest, GetTransactionResponse, IndexedHeader, IndexedUtxo, IndexerClient,
    IndexerClientError, ListScripthashUtxosRequest, ListScripthashUtxosResponse,
    TransactionPayload, TxOutpoint,
};
use rpp_wallet::node_client::{
    BlockFeeSummary, ChainHead, MempoolInfo, NodeClient, NodeClientResult,
};
use rpp_wallet::rpc::dto::{
    BroadcastParams, BroadcastResponse, CreateTxParams, CreateTxResponse, DeriveAddressParams,
    DeriveAddressResponse, EstimateFeeParams, EstimateFeeResponse, GetPolicyResponse,
    JsonRpcRequest, JsonRpcResponse, ListPendingLocksResponse, ReleasePendingLocksParams,
    ReleasePendingLocksResponse, RescanParams, RescanResponse, SetPolicyParams, SetPolicyResponse,
    SignTxParams, SignTxResponse, SyncStatusResponse, JSONRPC_VERSION,
};
use rpp_wallet::rpc::{SyncHandle, WalletRpcRouter};
use rpp_wallet::wallet::{Wallet, WalletSyncCoordinator};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_runtime_rpc_happy_path() -> Result<()> {
    let fixture = WorkflowFixture::new().context("initialise wallet workflow fixture")?;
    let wallet = fixture.wallet();
    let sync = wallet
        .start_sync_coordinator(fixture.indexer_client())
        .context("start wallet sync coordinator")?;
    let sync = Arc::new(sync);

    wait_for(|| {
        wallet
            .list_utxos()
            .map(|utxos| utxos.len() == 1)
            .unwrap_or(false)
    })
    .await;
    let status = wait_for_some(|| sync.latest_status()).await;
    assert_eq!(status.latest_height, fixture.latest_height);

    let runtime = fixture
        .start_runtime(Arc::clone(&sync))
        .context("boot wallet runtime")?;
    let endpoint = runtime.endpoint();
    let client = Client::new();

    let sync_status: SyncStatusResponse = rpc_call(&client, &endpoint, "sync_status", None)
        .await
        .context("fetch sync_status")?;
    assert!(
        !sync_status.syncing,
        "wallet should not be actively syncing"
    );
    assert_eq!(sync_status.latest_height, Some(fixture.latest_height));
    assert_eq!(
        sync_status.pending_range,
        Some((fixture.birthday, fixture.latest_height))
    );
    assert!(sync_status
        .scanned_scripthashes
        .map_or(false, |count| count > 0));
    assert!(sync_status.last_error.is_none());

    let initial_policy: GetPolicyResponse = rpc_call(&client, &endpoint, "get_policy", None)
        .await
        .context("fetch initial policy snapshot")?;
    assert!(initial_policy.snapshot.is_none());

    let statements = vec!["allow tier".to_string()];
    let set_policy: SetPolicyResponse = rpc_call(
        &client,
        &endpoint,
        "set_policy",
        Some(json!(SetPolicyParams {
            statements: statements.clone(),
        })),
    )
    .await
    .context("update policy snapshot")?;
    assert_eq!(set_policy.snapshot.statements, statements);

    let refreshed_policy: GetPolicyResponse = rpc_call(&client, &endpoint, "get_policy", None)
        .await
        .context("fetch refreshed policy snapshot")?;
    assert_eq!(
        refreshed_policy
            .snapshot
            .expect("policy snapshot persisted")
            .statements,
        statements
    );

    let fee_estimate: EstimateFeeResponse = rpc_call(
        &client,
        &endpoint,
        "estimate_fee",
        Some(json!(EstimateFeeParams {
            confirmation_target: 3,
        })),
    )
    .await
    .context("estimate fee")?;
    assert_eq!(fee_estimate.confirmation_target, 3);
    assert_eq!(fee_estimate.fee_rate, 1);

    let derived: DeriveAddressResponse = rpc_call(
        &client,
        &endpoint,
        "derive_address",
        Some(json!(DeriveAddressParams { change: false })),
    )
    .await
    .context("derive address")?;
    assert!(
        !derived.address.is_empty(),
        "derived address should not be empty"
    );

    let amount = fixture.spend_amount();
    let create_params = CreateTxParams {
        to: derived.address.clone(),
        amount,
        fee_rate: Some(2),
    };
    let draft: CreateTxResponse =
        rpc_call(&client, &endpoint, "create_tx", Some(json!(create_params)))
            .await
            .context("create transaction draft")?;
    assert!(!draft.draft_id.is_empty(), "draft id should be populated");
    assert_eq!(draft.inputs.len(), 1, "expected single input draft");
    assert!(
        draft
            .outputs
            .iter()
            .any(|output| !output.change && output.value == amount),
        "draft should contain requested recipient output"
    );
    assert_eq!(
        draft.total_input_value,
        draft.total_output_value + draft.fee,
        "draft should conserve value"
    );
    assert_eq!(draft.locks.len(), 1, "expected pending lock to be recorded");
    assert!(
        draft.locks[0].spending_txid.is_none(),
        "draft lock should not yet reference a spending txid",
    );

    let listed_locks: ListPendingLocksResponse =
        rpc_call(&client, &endpoint, "list_pending_locks", None)
            .await
            .context("list pending locks")?;
    assert_eq!(listed_locks.locks.len(), 1);

    let sign_params = SignTxParams {
        draft_id: draft.draft_id.clone(),
    };
    let signed: SignTxResponse = rpc_call(&client, &endpoint, "sign_tx", Some(json!(sign_params)))
        .await
        .context("sign draft transaction")?;
    assert_eq!(signed.draft_id, draft.draft_id);
    assert!(
        signed.proof_generated,
        "mock prover should emit proof bytes"
    );
    assert!(
        signed.proof_size.unwrap_or_default() > 0,
        "proof size should be reported"
    );
    assert!(signed.witness_bytes > 0, "witness payload expected");
    assert_eq!(
        signed.locks.len(),
        1,
        "lock state should persist after signing"
    );
    assert!(
        signed.locks[0].spending_txid.is_some(),
        "signing should assign a spending txid to the lock",
    );

    let broadcast_params = BroadcastParams {
        draft_id: draft.draft_id.clone(),
    };
    let broadcast: BroadcastResponse = rpc_call(
        &client,
        &endpoint,
        "broadcast",
        Some(json!(broadcast_params)),
    )
    .await
    .context("broadcast signed draft")?;
    assert_eq!(broadcast.draft_id, draft.draft_id);
    assert!(broadcast.accepted, "node client should accept the draft");
    assert!(
        broadcast.locks.is_empty(),
        "locks should be cleared after successful broadcast",
    );

    let release_response: ReleasePendingLocksResponse = rpc_call(
        &client,
        &endpoint,
        "release_pending_locks",
        Some(json!(ReleasePendingLocksParams)),
    )
    .await
    .context("release pending locks")?;
    assert!(release_response.released.is_empty());

    let rescan_response: RescanResponse = rpc_call(
        &client,
        &endpoint,
        "rescan",
        Some(json!(RescanParams {
            from_height: None,
            lookback_blocks: Some(5),
        })),
    )
    .await
    .context("request rescan")?;
    assert!(rescan_response.scheduled);
    assert_eq!(
        rescan_response.from_height,
        fixture.latest_height.saturating_sub(5)
    );

    let node = fixture.node();
    let submission = node
        .last_submission()
        .expect("expected node client to record submission");
    assert_eq!(submission.fee_rate, draft.fee_rate);

    runtime
        .shutdown()
        .await
        .context("shutdown wallet runtime")?;
    sync.shutdown()
        .await
        .context("shutdown wallet sync coordinator")?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_blocks_duplicate_spends_until_locks_clear() -> Result<()> {
    let fixture = WorkflowFixture::new().context("initialise wallet workflow fixture")?;
    let wallet = fixture.wallet();
    let sync = wallet
        .start_sync_coordinator(fixture.indexer_client())
        .context("start wallet sync coordinator")?;
    let sync = Arc::new(sync);

    wait_for(|| {
        wallet
            .list_utxos()
            .map(|utxos| utxos.len() == 1)
            .unwrap_or(false)
    })
    .await;

    let destination = wallet
        .derive_address(false)
        .context("derive recipient address")?;
    let amount = fixture.spend_amount();
    let first = wallet
        .create_draft(destination.clone(), amount, Some(2))
        .context("create initial draft")?;
    let locks = wallet
        .pending_locks()
        .context("inspect locks after draft")?;
    assert_eq!(locks.len(), 1, "expected lock after first draft");

    let second_attempt = wallet.create_draft(destination.clone(), amount, Some(2));
    assert!(
        second_attempt.is_err(),
        "duplicate draft should fail while lock is held",
    );

    wallet
        .sign_and_prove(&first)
        .context("sign initial draft")?;
    wallet
        .broadcast(&first)
        .context("broadcast initial draft")?;
    assert!(
        wallet
            .pending_locks()
            .context("locks after broadcast")?
            .is_empty(),
        "locks should clear after successful broadcast",
    );

    let retry = wallet
        .create_draft(destination, amount, Some(2))
        .context("retry draft after releasing locks")?;
    assert_eq!(retry.inputs.len(), 1, "expected retry to succeed");

    sync.shutdown()
        .await
        .context("shutdown wallet sync coordinator")?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_cli_commands_render_expected_output() -> Result<()> {
    let fixture = WorkflowFixture::new().context("initialise wallet workflow fixture")?;
    let wallet = fixture.wallet();
    let sync = wallet
        .start_sync_coordinator(fixture.indexer_client())
        .context("start wallet sync coordinator")?;
    let sync = Arc::new(sync);

    wait_for(|| {
        wallet
            .list_utxos()
            .map(|utxos| utxos.len() == 1)
            .unwrap_or(false)
    })
    .await;

    let runtime = fixture
        .start_runtime(Arc::clone(&sync))
        .context("boot wallet runtime")?;
    let endpoint = runtime.endpoint();

    let error_output = Command::cargo_bin("wallet")?
        .args([
            "send",
            "sign",
            "--rpc-endpoint",
            &endpoint,
            "--draft-id",
            "missing",
        ])
        .output()
        .context("execute wallet send sign for missing draft")?;
    assert!(
        !error_output.status.success(),
        "missing draft should surface an error"
    );
    let error_stderr =
        String::from_utf8(error_output.stderr).context("decode wallet send sign stderr")?;
    assert!(
        error_stderr.contains("wallet RPC error"),
        "expected RPC error marker in stderr"
    );

    let sync_output = Command::cargo_bin("wallet")?
        .args(["sync", "--rpc-endpoint", &endpoint])
        .output()
        .context("execute wallet sync command")?;
    assert!(sync_output.status.success(), "sync command should succeed");
    let sync_stdout = String::from_utf8(sync_output.stdout).context("decode wallet sync stdout")?;
    assert!(sync_stdout.contains("Synchronisation status"));
    assert!(sync_stdout.contains("  Syncing           : false"));
    assert!(sync_stdout.contains(&format!("  Latest height     : {}", fixture.latest_height)));
    assert!(sync_stdout.contains(&format!(
        "  Pending range     : {} → {}",
        fixture.birthday, fixture.latest_height
    )));
    assert!(sync_stdout.contains("  Scanned scripts   : "));

    let policy_get_output = Command::cargo_bin("wallet")?
        .args(["policy", "get", "--rpc-endpoint", &endpoint])
        .output()
        .context("execute wallet policy get command")?;
    assert!(
        policy_get_output.status.success(),
        "policy get should succeed"
    );
    let policy_get_stdout =
        String::from_utf8(policy_get_output.stdout).context("decode wallet policy get stdout")?;
    assert!(policy_get_stdout.contains("Policy snapshot"));
    assert!(policy_get_stdout.contains("Snapshot   : none recorded"));

    let policy_set_output = Command::cargo_bin("wallet")?
        .args([
            "policy",
            "set",
            "--rpc-endpoint",
            &endpoint,
            "--statement",
            "allow tier",
        ])
        .output()
        .context("execute wallet policy set command")?;
    assert!(
        policy_set_output.status.success(),
        "policy set should succeed"
    );
    let policy_set_stdout =
        String::from_utf8(policy_set_output.stdout).context("decode wallet policy set stdout")?;
    assert!(policy_set_stdout.contains("Policy snapshot updated"));
    assert!(policy_set_stdout.contains("Statements :"));
    assert!(policy_set_stdout.contains("allow tier"));

    let policy_refresh_output = Command::cargo_bin("wallet")?
        .args(["policy", "get", "--rpc-endpoint", &endpoint])
        .output()
        .context("execute wallet policy get command after update")?;
    assert!(policy_refresh_output.status.success());
    let policy_refresh_stdout = String::from_utf8(policy_refresh_output.stdout)
        .context("decode refreshed wallet policy get stdout")?;
    assert!(policy_refresh_stdout.contains("allow tier"));

    let fee_output = Command::cargo_bin("wallet")?
        .args([
            "fees",
            "estimate",
            "--rpc-endpoint",
            &endpoint,
            "--target",
            "3",
        ])
        .output()
        .context("execute wallet fees estimate command")?;
    assert!(fee_output.status.success(), "fees estimate should succeed");
    let fee_stdout =
        String::from_utf8(fee_output.stdout).context("decode wallet fees estimate stdout")?;
    assert!(fee_stdout.contains("Fee estimate"));
    assert!(fee_stdout.contains("Target confirmations : 3"));

    let addr_output = Command::cargo_bin("wallet")?
        .args(["addr", "new", "--rpc-endpoint", &endpoint])
        .output()
        .context("execute wallet addr new command")?;
    assert!(addr_output.status.success(), "addr new should succeed");
    let addr_stdout = String::from_utf8(addr_output.stdout).context("decode wallet addr stdout")?;
    assert!(addr_stdout.contains("Generated address"));
    assert!(addr_stdout.contains("Kind   : external"));
    let recipient = extract_field(&addr_stdout, "Address")
        .context("extract derived address from CLI output")?;

    let amount = fixture.spend_amount();
    let create_output = Command::cargo_bin("wallet")?
        .args([
            "send",
            "create",
            "--rpc-endpoint",
            &endpoint,
            "--to",
            &recipient,
            "--amount",
            &amount.to_string(),
            "--fee-rate",
            "2",
        ])
        .output()
        .context("execute wallet send create command")?;
    assert!(create_output.status.success(), "send create should succeed");
    let create_stdout =
        String::from_utf8(create_output.stdout).context("decode wallet send create stdout")?;
    assert!(create_stdout.contains("Draft transaction created"));
    assert!(create_stdout.contains("  Spend model   :"));
    let draft_id =
        extract_field(&create_stdout, "Draft ID").context("extract draft id from CLI output")?;

    let locks_list_output = Command::cargo_bin("wallet")?
        .args(["locks", "list", "--rpc-endpoint", &endpoint])
        .output()
        .context("execute wallet locks list command")?;
    assert!(
        locks_list_output.status.success(),
        "locks list should succeed"
    );
    let locks_list_stdout =
        String::from_utf8(locks_list_output.stdout).context("decode wallet locks list stdout")?;
    assert!(locks_list_stdout.contains("Pending locks"));
    assert!(locks_list_stdout.contains("Locks:"));

    let sign_output = Command::cargo_bin("wallet")?
        .args([
            "send",
            "sign",
            "--rpc-endpoint",
            &endpoint,
            "--draft-id",
            &draft_id,
        ])
        .output()
        .context("execute wallet send sign command")?;
    assert!(sign_output.status.success(), "send sign should succeed");
    let sign_stdout =
        String::from_utf8(sign_output.stdout).context("decode wallet send sign stdout")?;
    assert!(sign_stdout.contains("Draft signed successfully"));
    assert!(sign_stdout.contains(&format!("Draft ID      : {}", draft_id)));
    assert!(sign_stdout.contains("Proof generated: true"));

    let broadcast_output = Command::cargo_bin("wallet")?
        .args([
            "send",
            "broadcast",
            "--rpc-endpoint",
            &endpoint,
            "--draft-id",
            &draft_id,
        ])
        .output()
        .context("execute wallet send broadcast command")?;
    assert!(
        broadcast_output.status.success(),
        "send broadcast should succeed"
    );
    let broadcast_stdout = String::from_utf8(broadcast_output.stdout)
        .context("decode wallet send broadcast stdout")?;
    assert!(broadcast_stdout.contains("Broadcast result"));
    assert!(broadcast_stdout.contains(&format!("Draft ID : {}", draft_id)));
    assert!(broadcast_stdout.contains("Accepted : true"));

    let locks_release_output = Command::cargo_bin("wallet")?
        .args(["locks", "release", "--rpc-endpoint", &endpoint])
        .output()
        .context("execute wallet locks release command")?;
    assert!(
        locks_release_output.status.success(),
        "locks release should succeed"
    );
    let locks_release_stdout = String::from_utf8(locks_release_output.stdout)
        .context("decode wallet locks release stdout")?;
    assert!(locks_release_stdout.contains("Released pending locks"));
    assert!(locks_release_stdout.contains("Locks        : none"));

    let rescan_output = Command::cargo_bin("wallet")?
        .args([
            "rescan",
            "--rpc-endpoint",
            &endpoint,
            "--lookback-blocks",
            "5",
        ])
        .output()
        .context("execute wallet rescan command")?;
    assert!(
        rescan_output.status.success(),
        "rescan command should succeed"
    );
    let rescan_stdout =
        String::from_utf8(rescan_output.stdout).context("decode wallet rescan stdout")?;
    assert!(rescan_stdout.contains("Rescan request submitted"));
    assert!(rescan_stdout.contains("From height"));

    let node = fixture.node();
    assert_eq!(node.submission_count(), 1, "broadcast should submit once");

    runtime
        .shutdown()
        .await
        .context("shutdown wallet runtime")?;
    sync.shutdown()
        .await
        .context("shutdown wallet sync coordinator")?;

    Ok(())
}

struct WorkflowFixture {
    _tempdir: TempDir,
    wallet: Arc<Wallet>,
    indexer: TestIndexer,
    node: Arc<RecordingNodeClient>,
    birthday: u64,
    latest_height: u64,
    deposit_value: u64,
}

impl WorkflowFixture {
    fn new() -> Result<Self> {
        let tempdir = TempDir::new().context("create wallet temp directory")?;
        let store = Arc::new(WalletStore::open(tempdir.path()).context("open wallet store")?);

        let birthday = 120u64;
        {
            let mut batch = store.batch().context("open store batch")?;
            persist_birthday_height(&mut batch, Some(birthday))
                .context("persist birthday height")?;
            batch.commit().context("commit birthday checkpoint")?;
        }

        let node = Arc::new(RecordingNodeClient::default());
        let policy = WalletPolicyConfig {
            external_gap_limit: 4,
            internal_gap_limit: 4,
            min_confirmations: 1,
        };
        let wallet = Arc::new(
            Wallet::new(
                Arc::clone(&store),
                [42u8; 32],
                policy,
                WalletFeeConfig::default(),
                WalletProverConfig::default(),
                node.clone(),
            )
            .context("construct wallet instance")?,
        );
        let deposit_address = wallet
            .derive_address(false)
            .context("derive deposit address")?;

        let latest_height = 180u64;
        let deposit_value = 90_000u64;
        let indexer = TestIndexer::new(latest_height);
        let txid = [5u8; 32];
        let utxo = IndexedUtxo::new(
            TxOutpoint::new(txid, 0),
            deposit_value,
            hex::decode(&deposit_address).context("decode deposit script")?,
            Some(latest_height - 1),
        );
        let payload = TransactionPayload::new(
            txid,
            Some(latest_height - 1),
            Cow::Owned(vec![0xde, 0xad, 0xbe, 0xef]),
        );
        indexer.register_utxo(&deposit_address, utxo, payload);

        Ok(Self {
            _tempdir: tempdir,
            wallet,
            indexer,
            node,
            birthday,
            latest_height,
            deposit_value,
        })
    }

    fn wallet(&self) -> Arc<Wallet> {
        Arc::clone(&self.wallet)
    }

    fn indexer_client(&self) -> Arc<dyn IndexerClient> {
        Arc::new(self.indexer.clone())
    }

    fn node(&self) -> Arc<RecordingNodeClient> {
        Arc::clone(&self.node)
    }

    fn spend_amount(&self) -> u128 {
        u128::from(self.deposit_value / 2)
    }

    fn start_runtime(&self, sync: Arc<WalletSyncCoordinator>) -> Result<RuntimeHarness> {
        let metrics = RuntimeMetrics::noop();
        let mut config = WalletRuntimeConfig::new("127.0.0.1:0".parse().unwrap());
        let sync_handle: Arc<dyn SyncHandle> = sync.clone();
        let router = Arc::new(WalletRpcRouter::new(self.wallet(), Some(sync_handle)));
        let rpc_router = json_rpc_router(Arc::clone(&router), Arc::clone(&metrics), &config)
            .context("construct wallet RPC router")?;
        let handle = WalletRuntime::start(
            self.wallet(),
            config,
            Arc::clone(&metrics),
            Box::new(DeterministicSync::new("workflow-snapshot").with_height(self.latest_height)),
            None,
            None,
            Some(rpc_router),
        )
        .context("start wallet runtime")?;
        Ok(RuntimeHarness {
            handle,
            _metrics: metrics,
        })
    }
}

struct RuntimeHarness {
    handle: WalletRuntimeHandle,
    _metrics: Arc<RuntimeMetrics>,
}

impl RuntimeHarness {
    fn endpoint(&self) -> String {
        format!("http://{}", self.handle.listen_addr())
    }

    async fn shutdown(&self) -> Result<()> {
        self.handle
            .shutdown()
            .await
            .context("shutdown wallet runtime handle")
    }
}

#[derive(Clone)]
struct TestIndexer {
    state: Arc<Mutex<TestIndexerState>>,
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
        }
    }

    fn register_utxo(&self, address: &str, utxo: IndexedUtxo, payload: TransactionPayload) {
        let mut state = self.state.lock().unwrap();
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
        let state = self.state.lock().unwrap();
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

#[derive(Default)]
struct RecordingNodeClient {
    submissions: Mutex<Vec<DraftTransaction>>,
    fee_rate: u64,
    mempool_info: MempoolInfo,
    recent_blocks: Vec<BlockFeeSummary>,
}

impl RecordingNodeClient {
    fn submission_count(&self) -> usize {
        self.submissions.lock().unwrap().len()
    }

    fn last_submission(&self) -> Option<DraftTransaction> {
        self.submissions.lock().unwrap().last().cloned()
    }
}

impl NodeClient for RecordingNodeClient {
    fn submit_tx(&self, draft: &DraftTransaction) -> NodeClientResult<()> {
        self.submissions.lock().unwrap().push(draft.clone());
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

async fn rpc_call<T: DeserializeOwned>(
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

fn extract_field(output: &str, label: &str) -> Option<String> {
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

async fn wait_for<F>(mut condition: F)
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

async fn wait_for_some<F, T>(mut condition: F) -> T
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

fn decode_address(address: &str) -> [u8; 32] {
    let bytes = hex::decode(address).expect("decode wallet address");
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes[..32]);
    hash
}
