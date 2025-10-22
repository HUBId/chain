use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::convert::TryFrom;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use tempfile::tempdir;
use tokio::time;

use rpp_chain::config::NodeConfig;
use rpp_chain::crypto::{address_from_public_key, generate_keypair, sign_message};
use rpp_chain::gossip::{spawn_node_event_worker, NodeGossipProcessor};
use rpp_chain::node::Node;
use rpp_chain::runtime::node_runtime::node::{MetaTelemetryReport, NodeRuntimeConfig};
use rpp_chain::runtime::node_runtime::{
    NodeEvent, NodeHandle as P2pHandle, NodeInner as P2pNode, PeerTelemetry,
};
use rpp_chain::types::{
    Account, ChainProof, ExecutionTrace, ProofKind, ProofPayload, ReputationWeights,
    SignedTransaction, Stake, StarkProof, Tier, Transaction, TransactionProofBundle,
    TransactionWitness,
};
use rpp_p2p::{GossipTopic, NetworkMetaTelemetryReport};
use serde_json;

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

fn system_time_to_millis(time: SystemTime) -> u64 {
    time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn wait_for_peer(handle: &P2pHandle, expected: libp2p::PeerId) {
    let mut events = handle.subscribe();
    let _ = time::timeout(Duration::from_secs(5), async move {
        loop {
            match events.recv().await {
                Ok(NodeEvent::PeerConnected { peer, .. }) if peer == expected => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proof_gossip_propagates_between_nodes() -> Result<()> {
    let dir_a = tempdir()?;
    let dir_b = tempdir()?;

    let mut config_a = sample_node_config(dir_a.path());
    let mut config_b = sample_node_config(dir_b.path());

    let (listen_a, _) = random_listen_addr();
    let (listen_b, _) = random_listen_addr();
    config_a.p2p.listen_addr = listen_a.clone();
    config_b.p2p.listen_addr = listen_b.clone();
    config_b.p2p.bootstrap_peers = vec![listen_a.clone()];

    let node_a = Node::new(config_a.clone())?;
    let node_b = Node::new(config_b.clone())?;
    let handle_a = node_a.handle();
    let handle_b = node_b.handle();

    let identity_a = node_a.network_identity_profile()?;
    let identity_b = node_b.network_identity_profile()?;

    let mut runtime_a = NodeRuntimeConfig::from(&config_a);
    runtime_a.identity = Some(identity_a.into());
    let mut runtime_b = NodeRuntimeConfig::from(&config_b);
    runtime_b.identity = Some(identity_b.into());

    let (p2p_a, handle_a_runtime) = P2pNode::new(runtime_a)?;
    let (p2p_b, handle_b_runtime) = P2pNode::new(runtime_b)?;

    let task_a = tokio::spawn(async move {
        p2p_a.run().await.expect("run p2p a");
    });
    let task_b = tokio::spawn(async move {
        p2p_b.run().await.expect("run p2p b");
    });

    handle_a.attach_p2p(handle_a_runtime.clone()).await;
    handle_b.attach_p2p(handle_b_runtime.clone()).await;

    wait_for_peer(&handle_b_runtime, handle_a_runtime.local_peer_id()).await;

    let processor = Arc::new(NodeGossipProcessor::new(handle_b.clone()));
    let gossip_worker = spawn_node_event_worker(handle_b_runtime.subscribe(), processor, None);

    let bundle = sample_transaction_bundle(handle_b.address(), 0);
    let payload = serde_json::to_vec(&bundle)?;
    handle_a_runtime
        .publish_gossip(GossipTopic::Proofs, payload)
        .await?;

    let mut proofs_rx = handle_b.subscribe_witness_gossip(GossipTopic::Proofs);
    let witness_payload =
        time::timeout(Duration::from_secs(5), async { proofs_rx.recv().await }).await??;
    let received: TransactionProofBundle = serde_json::from_slice(&witness_payload)?;
    assert_eq!(received.hash(), bundle.hash());

    let mut retry = 0;
    let hash = bundle.hash();
    loop {
        if retry > 10 {
            panic!("transaction not ingested into mempool");
        }
        if handle_b
            .mempool_status()?
            .transactions
            .iter()
            .any(|entry| entry.hash == hash)
        {
            break;
        }
        time::sleep(Duration::from_millis(100)).await;
        retry += 1;
    }

    handle_a_runtime.shutdown().await?;
    handle_b_runtime.shutdown().await?;
    gossip_worker.await.expect("gossip worker completed")?;
    task_a.await.expect("p2p a completed");
    task_b.await.expect("p2p b completed");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn meta_telemetry_heartbeat_propagates() -> Result<()> {
    let dir_a = tempdir()?;
    let dir_b = tempdir()?;

    let mut config_a = sample_node_config(dir_a.path());
    let mut config_b = sample_node_config(dir_b.path());
    config_a.p2p.heartbeat_interval_ms = 200;
    config_b.p2p.heartbeat_interval_ms = 200;

    let (listen_a, _) = random_listen_addr();
    let (listen_b, _) = random_listen_addr();
    config_a.p2p.listen_addr = listen_a.clone();
    config_b.p2p.listen_addr = listen_b.clone();
    config_b.p2p.bootstrap_peers = vec![listen_a.clone()];

    let node_a = Node::new(config_a.clone())?;
    let node_b = Node::new(config_b.clone())?;
    let handle_a = node_a.handle();
    let handle_b = node_b.handle();

    let identity_a = node_a.network_identity_profile()?;
    let identity_b = node_b.network_identity_profile()?;

    let mut runtime_a = NodeRuntimeConfig::from(&config_a);
    runtime_a.identity = Some(identity_a.into());
    let mut runtime_b = NodeRuntimeConfig::from(&config_b);
    runtime_b.identity = Some(identity_b.into());

    let (p2p_a, handle_a_runtime) = P2pNode::new(runtime_a)?;
    let (p2p_b, handle_b_runtime) = P2pNode::new(runtime_b)?;

    let task_a = tokio::spawn(async move {
        p2p_a.run().await.expect("run p2p a");
    });
    let task_b = tokio::spawn(async move {
        p2p_b.run().await.expect("run p2p b");
    });

    handle_a.attach_p2p(handle_a_runtime.clone()).await;
    handle_b.attach_p2p(handle_b_runtime.clone()).await;

    wait_for_peer(&handle_b_runtime, handle_a_runtime.local_peer_id()).await;

    let mut events_b = handle_b_runtime.subscribe();
    let remote_peer = handle_a_runtime.local_peer_id();
    let local_peer = handle_b_runtime.local_peer_id();

    let (remote_sample, local_view): (PeerTelemetry, PeerTelemetry) = time::timeout(
        Duration::from_secs(10),
        async {
            let mut remote_measurement: Option<PeerTelemetry> = None;
            loop {
                match events_b.recv().await {
                    Ok(NodeEvent::Gossip { peer, topic, data })
                        if peer == remote_peer && topic == GossipTopic::Meta =>
                    {
                        if let Ok(network_report) =
                            serde_json::from_slice::<NetworkMetaTelemetryReport>(&data)
                        {
                            if let Ok(report) = MetaTelemetryReport::try_from(network_report) {
                                if let Some(entry) = report
                                    .peers
                                    .into_iter()
                                    .find(|telemetry| telemetry.peer == local_peer)
                                {
                                    remote_measurement = Some(entry);
                                }
                            }
                        }
                    }
                    Ok(NodeEvent::MetaTelemetry(report)) => {
                        if let Some(remote) = remote_measurement.as_ref() {
                            if let Some(entry) = report
                                .peers
                                .iter()
                                .find(|telemetry| telemetry.peer == remote_peer)
                            {
                                if entry.latency_ms == remote.latency_ms
                                    && system_time_to_millis(entry.last_seen)
                                        == system_time_to_millis(remote.last_seen)
                                {
                                    return Ok((remote.clone(), entry.clone()));
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(err) => return Err(err),
                }
            }
        },
    )
    .await??;

    assert_eq!(local_view.peer, remote_peer);
    assert_eq!(remote_sample.peer, local_peer);
    assert_eq!(local_view.latency_ms, remote_sample.latency_ms);
    assert_eq!(
        system_time_to_millis(local_view.last_seen),
        system_time_to_millis(remote_sample.last_seen)
    );

    handle_a_runtime.shutdown().await?;
    handle_b_runtime.shutdown().await?;
    task_a.await.expect("p2p a completed");
    task_b.await.expect("p2p b completed");

    Ok(())
}
