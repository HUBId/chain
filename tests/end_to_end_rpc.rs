#![cfg(feature = "prover-stwo")]

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use parking_lot::RwLock;
use reqwest::{Client, StatusCode};
use serde_json::Value;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use rpp_chain::api;
use rpp_chain::crypto::{
    address_from_public_key, generate_keypair, sign_message, vrf_public_key_to_hex,
};
use rpp_chain::node::NodeHandle;
use rpp_chain::proof_system::ProofVerifier;
use rpp_chain::reputation::{ReputationWeights, Tier};
use rpp_chain::runtime::config::{NetworkLimitsConfig, NetworkTlsConfig};
use rpp_chain::runtime::RuntimeMode;
use rpp_chain::stwo::circuit::transaction::TransactionWitness;
use rpp_chain::stwo::circuit::ExecutionTrace;
use rpp_chain::stwo::proof::{
    CommitmentSchemeProofData, FriProof, ProofKind, ProofPayload, StarkProof,
};
use rpp_chain::stwo::verifier::NodeVerifier;
use rpp_chain::types::{
    Account, ChainProof, SignedTransaction, Stake, Transaction, TransactionProofBundle,
};
use rpp_chain::vrf::{derive_tier_seed, generate_vrf, PoseidonVrfInput, VrfProof};

mod support;

use support::cluster::TestCluster;

struct RpcTestHarness {
    client: Client,
    base_url: String,
    node_handle: NodeHandle,
    rpc_task: Option<JoinHandle<rpp_chain::errors::ChainResult<()>>>,
    cluster: Option<TestCluster>,
}

impl RpcTestHarness {
    async fn start() -> Result<Self> {
        Self::launch(true).await
    }

    async fn start_without_wait() -> Result<Self> {
        Self::launch(false).await
    }

    async fn launch(wait_for_ready: bool) -> Result<Self> {
        let cluster = TestCluster::start(3)
            .await
            .context("failed to boot validator cluster")?;
        cluster
            .wait_for_full_mesh(Duration::from_secs(10))
            .await
            .context("cluster mesh formation failed")?;

        let primary = cluster
            .nodes()
            .first()
            .context("cluster returned no nodes")?;
        let addr = primary.config.network.rpc.listen;
        let node_handle = primary.node_handle.clone();
        let runtime_handle = node_handle.clone();
        let wallet = primary.wallet.clone();
        let orchestrator = primary.orchestrator.clone();

        let runtime_mode = Arc::new(RwLock::new(RuntimeMode::Node));
        let context = api::ApiContext::new(
            runtime_mode,
            Some(runtime_handle),
            Some(wallet.clone()),
            Some(orchestrator),
            None,
            false,
            None,
            true,
        );
        let rpc_task = tokio::spawn(async move {
            api::serve(
                context,
                addr,
                None,
                None,
                NetworkLimitsConfig::default(),
                NetworkTlsConfig::default(),
            )
            .await
        });

        let client = Client::builder()
            .build()
            .context("failed to build client")?;
        let base_url = format!("http://{}", addr);

        if wait_for_ready {
            if let Err(err) = wait_for_server(&client, &base_url).await {
                rpc_task.abort();
                let _ = rpc_task.await;
                cluster
                    .shutdown()
                    .await
                    .context("failed to stop validator cluster")?;
                return Err(err);
            }
        }

        Ok(Self {
            client,
            base_url,
            node_handle,
            rpc_task: Some(rpc_task),
            cluster: Some(cluster),
        })
    }

    fn client(&self) -> Client {
        self.client.clone()
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    async fn wait_for_ready(&self) -> Result<()> {
        let client = self.client();
        wait_for_server(&client, self.base_url()).await
    }

    fn node_address(&self) -> String {
        self.node_handle.address().to_string()
    }

    async fn shutdown(mut self) -> Result<()> {
        if let Some(handle) = self.rpc_task.take() {
            handle.abort();
            let _ = handle.await;
        }

        if let Some(cluster) = self.cluster.take() {
            cluster
                .shutdown()
                .await
                .context("failed to stop validator cluster")?;
        }

        Ok(())
    }
}

impl Drop for RpcTestHarness {
    fn drop(&mut self) {
        if let Some(handle) = self.rpc_task.take() {
            handle.abort();
        }
        if let Some(cluster) = self.cluster.take() {
            tokio::spawn(async move {
                let _ = cluster.shutdown().await;
            });
        }
    }
}

async fn wait_for_server(client: &Client, base_url: &str) -> Result<()> {
    let health_url = format!("{}/health", base_url);
    for attempt in 0..50 {
        match client.get(&health_url).send().await {
            Ok(response) if response.status() == StatusCode::OK => return Ok(()),
            Ok(_) | Err(_) => sleep(Duration::from_millis(100)).await,
        }
        if attempt == 49 {
            anyhow::bail!("RPC server failed to become ready");
        }
    }
    unreachable!("wait_for_server loop must return or bail");
}

fn sample_transaction_bundle(to: &str) -> TransactionProofBundle {
    let keypair = generate_keypair();
    let from = address_from_public_key(&keypair.public);
    let tx = Transaction::new(from.clone(), to.to_string(), 42, 1, 1, None);
    let signature = sign_message(&keypair, &tx.canonical_bytes());
    let signed_tx = SignedTransaction::new(tx, signature, &keypair.public);

    let mut sender = Account::new(from.clone(), 1_000_000, Stake::from_u128(1_000));
    sender.nonce = 0;

    let receiver = Account::new(to.to_string(), 0, Stake::default());

    let witness = TransactionWitness {
        signed_tx: signed_tx.clone(),
        sender_account: sender,
        receiver_account: Some(receiver),
        required_tier: Tier::Tl0,
        reputation_weights: ReputationWeights::default(),
    };

    let proof_payload = ProofPayload::Transaction(witness.clone());
    let proof = StarkProof {
        kind: ProofKind::Transaction,
        commitment: String::new(),
        public_inputs: Vec::new(),
        payload: proof_payload.clone(),
        trace: ExecutionTrace {
            segments: Vec::new(),
        },
        commitment_proof: CommitmentSchemeProofData::default(),
        fri_proof: FriProof::default(),
    };

    TransactionProofBundle::new(
        signed_tx,
        ChainProof::Stwo(proof),
        Some(witness),
        Some(proof_payload),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_endpoint_returns_node_snapshot() -> Result<()> {
    let harness = match RpcTestHarness::start().await {
        Ok(harness) => harness,
        Err(err) => {
            eprintln!("skipping status endpoint test: {err:?}");
            return Ok(());
        }
    };
    let client = harness.client();
    let base_url = harness.base_url().to_string();

    let response = client
        .get(format!("{}/status/node", base_url))
        .send()
        .await
        .context("failed to fetch node status")?;
    assert_eq!(response.status(), StatusCode::OK);

    let payload: Value = response.json().await.context("invalid status payload")?;
    assert_eq!(payload["height"].as_u64(), Some(0));
    assert_eq!(payload["pending_transactions"].as_u64(), Some(0));
    assert_eq!(payload["epoch"].as_u64(), Some(0));

    harness.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn p2p_endpoint_returns_meta_telemetry_snapshot() -> Result<()> {
    let harness = match RpcTestHarness::start().await {
        Ok(harness) => harness,
        Err(err) => {
            eprintln!("skipping p2p telemetry test: {err:?}");
            return Ok(());
        }
    };
    let client = harness.client();
    let base_url = harness.base_url().to_string();

    let response = client
        .get(format!("{}/p2p/peers", base_url))
        .send()
        .await
        .context("failed to fetch p2p meta telemetry")?;
    assert_eq!(response.status(), StatusCode::OK);

    let payload: Value = response
        .json()
        .await
        .context("invalid p2p meta telemetry payload")?;
    let local_peer = payload["local_peer_id"]
        .as_str()
        .context("missing local peer id")?;
    assert!(!local_peer.is_empty());

    let peer_count = payload["peer_count"]
        .as_u64()
        .context("missing peer count")?;
    assert!(peer_count >= 1, "expected at least one connected peer");

    let peers = payload["peers"].as_array().context("missing peers array")?;
    assert!(!peers.is_empty(), "expected peer telemetry entries");
    assert!(peers.len() as u64 <= peer_count);
    for peer in peers {
        assert!(peer["peer"].as_str().is_some(), "peer id missing");
        assert!(peer["version"].as_str().is_some(), "peer version missing");
        assert!(peer["latency_ms"].as_u64().is_some(), "latency missing");
        assert!(peer["last_seen"].as_u64().is_some(), "last seen missing");
    }

    harness.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_probes_track_startup_and_shutdown() -> Result<()> {
    let mut harness = match RpcTestHarness::start_without_wait().await {
        Ok(harness) => harness,
        Err(err) => {
            eprintln!("skipping health probe test: {err:?}");
            return Ok(());
        }
    };

    let client = harness.client();
    let base_url = harness.base_url().to_string();

    let live_url = format!("{}/health/live", base_url);
    let ready_url = format!("{}/health/ready", base_url);

    let initial_live = client.get(&live_url).send().await;
    let initial_live_status = initial_live
        .ok()
        .map(|response| response.status())
        .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(initial_live_status, StatusCode::SERVICE_UNAVAILABLE);

    let initial_ready = client.get(&ready_url).send().await;
    let initial_ready_status = initial_ready
        .ok()
        .map(|response| response.status())
        .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(initial_ready_status, StatusCode::SERVICE_UNAVAILABLE);

    harness.wait_for_ready().await?;

    let live_ready = client
        .get(&live_url)
        .send()
        .await
        .context("failed to hit live probe after startup")?;
    assert_eq!(live_ready.status(), StatusCode::OK);

    let ready_ready = client
        .get(&ready_url)
        .send()
        .await
        .context("failed to hit ready probe after startup")?;
    assert_eq!(ready_ready.status(), StatusCode::OK);

    harness
        .node_handle
        .stop()
        .await
        .context("failed to stop node runtime")?;

    let live_shutdown = client.get(&live_url).send().await;
    let live_shutdown_status = live_shutdown
        .ok()
        .map(|response| response.status())
        .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(live_shutdown_status, StatusCode::SERVICE_UNAVAILABLE);

    let ready_shutdown = client.get(&ready_url).send().await;
    let ready_shutdown_status = ready_shutdown
        .ok()
        .map(|response| response.status())
        .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(ready_shutdown_status, StatusCode::SERVICE_UNAVAILABLE);

    harness.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ledger_endpoint_returns_genesis_block() -> Result<()> {
    let harness = match RpcTestHarness::start().await {
        Ok(harness) => harness,
        Err(err) => {
            eprintln!("skipping ledger endpoint test: {err:?}");
            return Ok(());
        }
    };
    let client = harness.client();
    let base_url = harness.base_url().to_string();

    let response = client
        .get(format!("{}/blocks/0", base_url))
        .send()
        .await
        .context("failed to fetch genesis block")?;
    assert_eq!(response.status(), StatusCode::OK);

    let payload: Value = response.json().await.context("invalid block payload")?;
    assert!(payload.is_object(), "genesis block must be present");
    assert_eq!(payload["header"]["height"].as_u64(), Some(0));

    if let Some(state_root) = payload["header"]["state_root"].as_str() {
        assert_eq!(state_root.len(), 64);
    } else {
        panic!("missing state root");
    }

    harness.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submitting_valid_transaction_populates_mempool() -> Result<()> {
    let harness = match RpcTestHarness::start().await {
        Ok(harness) => harness,
        Err(err) => {
            eprintln!("skipping transaction submission test: {err:?}");
            return Ok(());
        }
    };
    let client = harness.client();
    let base_url = harness.base_url().to_string();
    let node_address = harness.node_address();

    let bundle = sample_transaction_bundle(&node_address);
    let verifier = NodeVerifier::new();
    if let ChainProof::Stwo(_) = &bundle.proof {
        if let Err(err) = verifier.verify_transaction(&bundle.proof) {
            panic!(
                "expected STWO transaction verification pipeline success, but verification returned {err:?}"
            );
        }
    } else {
        panic!("expected STWO transaction proof in bundle");
    }
    let expected_hash = bundle.hash();

    let response = client
        .post(format!("{}/transactions", base_url))
        .json(&bundle)
        .send()
        .await
        .context("failed to submit transaction")?;
    assert_eq!(response.status(), StatusCode::OK);

    let payload: Value = response.json().await.context("invalid submit payload")?;
    assert_eq!(payload["hash"].as_str(), Some(expected_hash.as_str()));

    let mempool_response = client
        .get(format!("{}/status/mempool", base_url))
        .send()
        .await
        .context("failed to fetch mempool status")?;
    assert_eq!(mempool_response.status(), StatusCode::OK);
    let mempool: Value = mempool_response
        .json()
        .await
        .context("invalid mempool payload")?;
    let transactions = mempool["transactions"]
        .as_array()
        .expect("transactions array");
    assert_eq!(transactions.len(), 1);
    assert_eq!(
        transactions[0]["hash"].as_str(),
        Some(expected_hash.as_str())
    );

    harness.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submitting_invalid_transaction_returns_bad_request() -> Result<()> {
    let harness = match RpcTestHarness::start().await {
        Ok(harness) => harness,
        Err(err) => {
            eprintln!("skipping invalid transaction test: {err:?}");
            return Ok(());
        }
    };
    let client = harness.client();
    let base_url = harness.base_url().to_string();

    let response = client
        .post(format!("{}/transactions", base_url))
        .body("{\"invalid\": true}")
        .header("content-type", "application/json")
        .send()
        .await
        .context("failed to submit invalid transaction")?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    harness.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validator_membership_endpoint_returns_active_validator() -> Result<()> {
    let harness = match RpcTestHarness::start().await {
        Ok(harness) => harness,
        Err(err) => {
            eprintln!("skipping validator membership test: {err:?}");
            return Ok(());
        }
    };
    let client = harness.client();
    let base_url = harness.base_url().to_string();
    let node_address = harness.node_address();

    let response = client
        .get(format!("{}/ui/bft/membership", base_url))
        .send()
        .await
        .context("failed to fetch validator membership")?;
    assert_eq!(response.status(), StatusCode::OK);

    let payload: Value = response
        .json()
        .await
        .context("invalid membership payload")?;
    let validators = payload["validators"].as_array().expect("validators array");
    assert!(!validators.is_empty(), "expected at least one validator");
    assert_eq!(
        validators[0]["address"].as_str(),
        Some(node_address.as_str())
    );

    harness.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn uptime_scheduler_endpoints_handle_failure_path() -> Result<()> {
    let harness = match RpcTestHarness::start().await {
        Ok(harness) => harness,
        Err(err) => {
            eprintln!("skipping uptime scheduler test: {err:?}");
            return Ok(());
        }
    };
    let client = harness.client();
    let base_url = harness.base_url().to_string();

    let status_url = format!("{}/wallet/uptime/scheduler", base_url);
    let trigger_url = format!("{}/wallet/uptime/scheduler/trigger", base_url);
    let offload_url = format!("{}/wallet/uptime/scheduler/offload", base_url);

    let initial_status = client
        .get(&status_url)
        .send()
        .await
        .context("failed to fetch initial uptime scheduler status")?;
    assert_eq!(initial_status.status(), StatusCode::OK);
    let initial_payload: Value = initial_status
        .json()
        .await
        .context("invalid initial scheduler payload")?;
    assert_eq!(initial_payload["enabled"].as_bool(), Some(true));
    assert_eq!(initial_payload["running"].as_bool(), Some(false));
    assert_eq!(initial_payload["interval_secs"].as_u64(), Some(3_600));
    assert!(initial_payload.get("last_success").is_none());
    assert!(initial_payload.get("last_error").is_none());

    let trigger_response = client
        .post(&trigger_url)
        .send()
        .await
        .context("failed to trigger uptime scheduler")?;
    assert_eq!(trigger_response.status(), StatusCode::BAD_REQUEST);
    let trigger_error: Value = trigger_response
        .json()
        .await
        .context("invalid trigger error payload")?;
    let trigger_message = trigger_error["error"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        trigger_message.contains("validated genesis identity"),
        "unexpected trigger error: {}",
        trigger_message
    );

    let failure_status = client
        .get(&status_url)
        .send()
        .await
        .context("failed to fetch failure uptime scheduler status")?;
    assert_eq!(failure_status.status(), StatusCode::OK);
    let failure_payload: Value = failure_status
        .json()
        .await
        .context("invalid failure scheduler payload")?;
    let failure_message = failure_payload["last_error"]["message"]
        .as_str()
        .unwrap_or_default();
    assert!(
        failure_message.contains("validated genesis identity"),
        "unexpected scheduler failure message: {}",
        failure_message
    );

    let offload_response = client
        .post(&offload_url)
        .send()
        .await
        .context("failed to offload uptime proof")?;
    assert_eq!(offload_response.status(), StatusCode::NOT_FOUND);

    harness.shutdown().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vrf_submit_and_threshold_endpoints() -> Result<()> {
    let harness = RpcTestHarness::start().await?;

    let status = harness
        .node_handle
        .node_status()
        .context("failed to fetch node status")?;

    let secrets = harness.node_handle.vrf_secrets_config();
    let key_path = harness.node_handle.vrf_key_path();
    let keypair = secrets
        .load_or_generate_vrf_keypair(&key_path)
        .context("failed to load VRF keypair")?;

    let timetoke_hours = 96;
    let tier_seed = derive_tier_seed(&status.address, timetoke_hours);
    let last_hash_bytes = hex::decode(&status.last_hash).context("invalid tip hash encoding")?;
    let mut last_block_header = [0u8; 32];
    last_block_header.copy_from_slice(&last_hash_bytes);
    let input = PoseidonVrfInput::new(last_block_header, status.epoch, tier_seed);
    let output = generate_vrf(&input, &keypair.secret).context("failed to generate VRF output")?;
    let proof = VrfProof::from_output(&output);

    let request = serde_json::json!({
        "address": status.address,
        "public_key": vrf_public_key_to_hex(&keypair.public),
        "input": {
            "last_block_header": status.last_hash,
            "epoch": status.epoch,
            "tier_seed": hex::encode(tier_seed),
        },
        "proof": proof,
        "tier": Tier::Tl3,
        "timetoke_hours": timetoke_hours,
    });

    let submit_response = harness
        .client()
        .post(format!("{}/consensus/vrf/submit", harness.base_url()))
        .json(&request)
        .send()
        .await
        .context("failed to submit VRF proof")?;
    assert_eq!(submit_response.status(), StatusCode::ACCEPTED);

    let threshold_response = harness
        .client()
        .get(format!("{}/consensus/vrf/threshold", harness.base_url()))
        .send()
        .await
        .context("failed to fetch VRF threshold status")?;
    assert_eq!(threshold_response.status(), StatusCode::OK);

    let payload: Value = threshold_response
        .json()
        .await
        .context("invalid VRF threshold payload")?;
    assert!(payload.get("committee_target").is_some());
    assert!(payload.get("participation_rate").is_some());

    harness.shutdown().await?;
    Ok(())
}
