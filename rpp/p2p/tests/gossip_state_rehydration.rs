use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use libp2p::PeerId;
use serde::Deserialize;
use tempfile::tempdir;
use tokio::time;

use rpp_chain::config::NodeConfig;
use rpp_chain::crypto::{address_from_public_key, generate_keypair, sign_message};
use rpp_chain::gossip::{spawn_node_event_worker, NodeGossipProcessor};
use rpp_chain::node::Node;
use rpp_chain::proof_system::ProofVerifierRegistry;
use rpp_chain::runtime::node_runtime::node::{NodeEvent, NodeRuntimeConfig};
use rpp_chain::runtime::node_runtime::{NodeHandle as P2pHandle, NodeInner as P2pNode};
use rpp_chain::runtime::RuntimeMetrics;
use rpp_chain::types::{
    Account, ChainProof, ExecutionTrace, ProofKind, ProofPayload, ReputationWeights,
    SignedTransaction, Stake, StarkProof, Tier, Transaction, TransactionProofBundle,
    TransactionWitness,
};
use rpp_p2p::{GossipTopic, TierLevel};

#[derive(Debug, Deserialize, Clone)]
struct GossipSnapshot {
    subscriptions: Vec<String>,
    #[serde(default)]
    mesh_peers: std::collections::HashMap<String, Vec<String>>,
    #[serde(default)]
    recent_digests: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct StoredPeerRecordSnapshot {
    peer_id: String,
    reputation: f64,
    tier: TierLevel,
    #[serde(default)]
    addresses: Vec<String>,
    #[serde(default)]
    last_seen: Option<u64>,
    #[serde(default)]
    ping_failures: u32,
    #[serde(default)]
    features: BTreeMap<String, bool>,
}

fn sample_node_config(base: &Path) -> NodeConfig {
    let data_dir = base.join("data");
    let keys_dir = base.join("keys");
    fs::create_dir_all(&data_dir).expect("node data dir");
    fs::create_dir_all(&keys_dir).expect("node key dir");

    let mut config = NodeConfig::default();
    config.data_dir = data_dir.clone();
    config.snapshot_dir = data_dir.join("snapshots");
    config.proof_cache_dir = data_dir.join("proofs");
    config.p2p.peerstore_path = data_dir.join("p2p/peerstore.json");
    config.p2p.gossip_path = Some(data_dir.join("p2p/gossip.json"));
    config.key_path = keys_dir.join("node.toml");
    config.p2p_key_path = keys_dir.join("p2p.toml");
    config.vrf_key_path = keys_dir.join("vrf.toml");
    config.block_time_ms = 200;
    config.mempool_limit = 64;
    config.rollout.feature_gates.pruning = false;
    config.rollout.feature_gates.recursive_proofs = false;
    config.rollout.feature_gates.reconstruction = false;
    config.rollout.feature_gates.consensus_enforcement = false;
    config.rollout.feature_gates.malachite_consensus = true;
    config.rollout.feature_gates.timetoke_rewards = true;
    config.rollout.feature_gates.witness_network = true;
    config.ensure_directories().expect("node directories");
    config
}

fn sample_transaction_bundle(to: &str, nonce: u64) -> TransactionProofBundle {
    let keypair = generate_keypair();
    let from = address_from_public_key(&keypair.public);
    let tx = Transaction::new(from.clone(), to.to_string(), 42, nonce, 1, None);
    let signature = sign_message(&keypair, &tx.canonical_bytes());
    let signed_tx = SignedTransaction::new(tx, signature, &keypair.public);

    let mut sender = Account::new(from.clone(), 1_000_000, Stake::from_u128(1_000));
    sender.nonce = nonce;
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
        commitment_proof: Default::default(),
        fri_proof: Default::default(),
    };

    TransactionProofBundle::new(
        signed_tx,
        ChainProof::Stwo(proof),
        Some(witness),
        Some(proof_payload),
    )
}

fn random_listen_addr() -> (String, u16) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind random port");
    let port = listener.local_addr().expect("addr").port();
    drop(listener);
    (format!("/ip4/127.0.0.1/tcp/{port}"), port)
}

async fn wait_for_peer(handle: &P2pHandle, expected: PeerId) -> Result<()> {
    let mut events = handle.subscribe();
    time::timeout(Duration::from_secs(10), async move {
        loop {
            match events.recv().await {
                Ok(NodeEvent::PeerConnected { peer, .. }) if peer == expected => return Ok(()),
                Ok(_) => {}
                Err(err) => return Err(anyhow!("peer event stream closed: {err}")),
            }
        }
    })
    .await
    .map_err(|_| anyhow!("timed out waiting for peer {expected}"))??;
    Ok(())
}

fn read_peerstore_snapshot(path: &Path, peer_id: &str) -> Result<Option<StoredPeerRecordSnapshot>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read(path)?;
    if raw.is_empty() {
        return Ok(None);
    }
    let records: Vec<StoredPeerRecordSnapshot> = serde_json::from_slice(&raw)?;
    Ok(records.into_iter().find(|record| record.peer_id == peer_id))
}

fn read_gossip_snapshot(path: &Path) -> Result<GossipSnapshot> {
    let raw =
        fs::read(path).with_context(|| format!("read gossip state from {}", path.display()))?;
    serde_json::from_slice(&raw).context("decode gossip snapshot")
}

fn digest_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gossip_state_rehydrates_after_restart() -> Result<()> {
    let dir_a = tempdir()?;
    let dir_b = tempdir()?;

    let mut config_a = sample_node_config(dir_a.path());
    let mut config_b = sample_node_config(dir_b.path());

    let (listen_a, _port_a) = random_listen_addr();
    let (listen_b, _port_b) = random_listen_addr();
    config_a.p2p.listen_addr = listen_a.clone();
    config_b.p2p.listen_addr = listen_b.clone();
    config_b.p2p.bootstrap_peers = vec![listen_a.clone()];

    let node_a = Node::new(config_a.clone(), RuntimeMetrics::noop())?;
    let node_b = Node::new(config_b.clone(), RuntimeMetrics::noop())?;
    let handle_a = node_a.handle();
    let handle_b = node_b.handle();

    let identity_a = node_a.network_identity_profile()?;
    let identity_b = node_b.network_identity_profile()?;

    let mut runtime_a = NodeRuntimeConfig::from(&config_a);
    runtime_a.metrics = RuntimeMetrics::noop();
    runtime_a.identity = Some(identity_a.into());
    let mut runtime_b = NodeRuntimeConfig::from(&config_b);
    runtime_b.metrics = RuntimeMetrics::noop();
    runtime_b.identity = Some(identity_b.into());

    let (p2p_a, handle_a_runtime) = P2pNode::new(runtime_a)?;
    let (p2p_b, handle_b_runtime) = P2pNode::new(runtime_b)?;

    let task_a = tokio::spawn(async move {
        p2p_a.run().await.expect("run p2p a");
    });
    let mut task_b = tokio::spawn(async move {
        p2p_b.run().await.expect("run p2p b");
    });

    handle_a.attach_p2p(handle_a_runtime.clone()).await;
    handle_b.attach_p2p(handle_b_runtime.clone()).await;

    let proof_storage_path = config_b.proof_cache_dir.join("gossip_proofs.json");
    let cache_namespace = ProofVerifierRegistry::backend_fingerprint();
    let proof_cache_retain = config_b.proof_cache.retain_for_backend(&cache_namespace);
    let processor = Arc::new(NodeGossipProcessor::new(
        handle_b.clone(),
        proof_storage_path,
        proof_cache_retain,
        cache_namespace,
    ));
    let gossip_worker = spawn_node_event_worker(handle_b_runtime.subscribe(), processor, None);

    wait_for_peer(&handle_b_runtime, handle_a_runtime.local_peer_id()).await?;

    let mut witness_rx = handle_b.subscribe_witness_gossip(GossipTopic::WitnessProofs);
    let bundle = sample_transaction_bundle(handle_b.address(), 0);
    let payload = serde_json::to_vec(&bundle)?;

    handle_a_runtime
        .publish_gossip(GossipTopic::WitnessProofs, payload.clone())
        .await?;

    let witness_payload =
        time::timeout(Duration::from_secs(10), async { witness_rx.recv().await }).await??;
    let received: TransactionProofBundle = serde_json::from_slice(&witness_payload)?;
    assert_eq!(received.hash(), bundle.hash());

    let gossip_path = config_b
        .p2p
        .gossip_path
        .clone()
        .expect("gossip path configured");
    let snapshot = read_gossip_snapshot(&gossip_path)?;
    assert!(snapshot.subscriptions.iter().any(|topic| topic == "proofs"));
    let mesh_peers = snapshot
        .mesh_peers
        .get("proofs")
        .cloned()
        .unwrap_or_default();
    let broadcaster_peer = handle_a_runtime.local_peer_id().to_base58();
    assert!(mesh_peers.iter().any(|entry| entry == &broadcaster_peer));
    let digest_hex = digest_hex(&payload);
    assert!(snapshot
        .recent_digests
        .iter()
        .any(|entry| entry == &digest_hex));

    let peerstore_path = config_b.p2p.peerstore_path.clone();
    let initial_peer_record = read_peerstore_snapshot(&peerstore_path, &broadcaster_peer)?
        .expect("peerstore snapshot for broadcaster");
    assert!(!initial_peer_record.addresses.is_empty());
    assert_eq!(initial_peer_record.features.get("pruning"), Some(&false));
    assert_eq!(
        initial_peer_record.features.get("malachite_consensus"),
        Some(&true)
    );
    assert_eq!(
        initial_peer_record.features.get("timetoke_rewards"),
        Some(&true)
    );
    assert_eq!(
        initial_peer_record.features.get("witness_network"),
        Some(&true)
    );

    handle_b_runtime.shutdown().await?;
    gossip_worker.await.expect("gossip worker completed")?;
    task_b.await.expect("p2p b stopped");

    config_b.p2p.bootstrap_peers.clear();

    let node_b_restart = Node::new(config_b.clone(), RuntimeMetrics::noop())?;
    let handle_b_restart = node_b_restart.handle();
    let identity_b_restart = node_b_restart.network_identity_profile()?;

    let mut runtime_b_restart = NodeRuntimeConfig::from(&config_b);
    runtime_b_restart.metrics = RuntimeMetrics::noop();
    runtime_b_restart.identity = Some(identity_b_restart.into());
    let (p2p_b_restart, handle_b_runtime_restart) = P2pNode::new(runtime_b_restart)?;

    task_b = tokio::spawn(async move {
        p2p_b_restart.run().await.expect("run restarted p2p node");
    });

    handle_b_restart
        .attach_p2p(handle_b_runtime_restart.clone())
        .await;

    let cache_namespace = ProofVerifierRegistry::backend_fingerprint();
    let proof_cache_retain = config_b.proof_cache.retain_for_backend(&cache_namespace);
    let processor_restart = Arc::new(NodeGossipProcessor::new(
        handle_b_restart.clone(),
        config_b.proof_cache_dir.join("gossip_proofs_restart.json"),
        proof_cache_retain,
        cache_namespace,
    ));
    let gossip_worker_restart = spawn_node_event_worker(
        handle_b_runtime_restart.subscribe(),
        processor_restart,
        None,
    );

    wait_for_peer(&handle_b_runtime_restart, handle_a_runtime.local_peer_id()).await?;

    let mut witness_rx_restart =
        handle_b_restart.subscribe_witness_gossip(GossipTopic::WitnessProofs);

    // Duplicate payload should be ignored after replay cache preload.
    handle_a_runtime
        .publish_gossip(GossipTopic::WitnessProofs, payload.clone())
        .await?;

    match time::timeout(Duration::from_secs(3), async {
        witness_rx_restart.recv().await
    })
    .await
    {
        Ok(Ok(bytes)) => {
            panic!(
                "duplicate gossip payload was re-delivered after restart: {} bytes",
                bytes.len()
            );
        }
        Ok(Err(err)) => panic!("witness receiver error after restart: {err}"),
        Err(_) => {}
    }

    let bundle_fresh = sample_transaction_bundle(handle_b_restart.address(), 1);
    let payload_fresh = serde_json::to_vec(&bundle_fresh)?;
    handle_a_runtime
        .publish_gossip(GossipTopic::WitnessProofs, payload_fresh.clone())
        .await?;

    let witness_payload_restart = time::timeout(Duration::from_secs(10), async {
        witness_rx_restart.recv().await
    })
    .await??;
    let received_restart: TransactionProofBundle =
        serde_json::from_slice(&witness_payload_restart)?;
    assert_eq!(received_restart.hash(), bundle_fresh.hash());

    let snapshot_restart = read_gossip_snapshot(&gossip_path)?;
    assert!(snapshot_restart
        .recent_digests
        .iter()
        .any(|entry| entry == &digest_hex));
    let fresh_digest_hex = digest_hex(&payload_fresh);
    assert!(snapshot_restart
        .recent_digests
        .iter()
        .any(|entry| entry == &fresh_digest_hex));

    let restart_peer_record = read_peerstore_snapshot(&peerstore_path, &broadcaster_peer)?
        .expect("peerstore snapshot after restart");
    assert_eq!(restart_peer_record.peer_id, broadcaster_peer);
    assert!(restart_peer_record.reputation >= initial_peer_record.reputation);
    assert_eq!(restart_peer_record.ping_failures, 0);
    assert_eq!(
        restart_peer_record.features.get("malachite_consensus"),
        Some(&true)
    );
    assert_eq!(
        restart_peer_record.features.get("timetoke_rewards"),
        Some(&true)
    );
    assert_eq!(
        restart_peer_record.features.get("witness_network"),
        Some(&true)
    );
    if let (Some(before_seen), Some(after_seen)) =
        (initial_peer_record.last_seen, restart_peer_record.last_seen)
    {
        assert!(
            after_seen >= before_seen,
            "peer last_seen timestamp did not advance after restart"
        );
    }

    handle_b_runtime_restart.shutdown().await?;
    gossip_worker_restart
        .await
        .expect("gossip worker restart completed")?;
    task_b.await.expect("restarted p2p node stopped");

    handle_a_runtime.shutdown().await?;
    task_a.await.expect("p2p a completed");

    Ok(())
}
