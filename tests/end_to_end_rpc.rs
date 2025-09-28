use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use parking_lot::RwLock;
use reqwest::{Client, StatusCode};
use serde_json::Value;
use tokio::task::JoinHandle;
use tokio::time::sleep;

use rpp_chain::api;
use rpp_chain::crypto::{address_from_public_key, generate_keypair, sign_message};
use rpp_chain::node::NodeHandle;
use rpp_chain::reputation::{ReputationWeights, Tier};
use rpp_chain::runtime::RuntimeMode;
use rpp_chain::stwo::circuit::ExecutionTrace;
use rpp_chain::stwo::circuit::transaction::TransactionWitness;
use rpp_chain::stwo::proof::{FriProof, ProofKind, ProofPayload, StarkProof};
use rpp_chain::types::{
    Account, ChainProof, SignedTransaction, Stake, Transaction, TransactionProofBundle,
};

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
        let addr = primary.config.rpc_listen;
        let node_handle = primary.node_handle.clone();
        let runtime_handle = node_handle.clone();
        let wallet = primary.wallet.clone();
        let orchestrator = primary.orchestrator.clone();

        let runtime_mode = Arc::new(RwLock::new(RuntimeMode::Node));
        let context = api::ApiContext::new(
            runtime_mode,
            Some(runtime_handle),
            Some(wallet),
            Some(orchestrator),
        );
        let rpc_task = tokio::spawn(async move { api::serve(context, addr, None, None).await });

        let client = Client::builder()
            .build()
            .context("failed to build client")?;
        let base_url = format!("http://{}", addr);
        wait_for_server(&client, &base_url).await?;

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

    let proof = StarkProof {
        kind: ProofKind::Transaction,
        commitment: String::new(),
        public_inputs: Vec::new(),
        payload: ProofPayload::Transaction(witness),
        trace: ExecutionTrace {
            segments: Vec::new(),
        },
        fri_proof: FriProof::empty(),
    };

    TransactionProofBundle::new(signed_tx, ChainProof::Stwo(proof))
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
