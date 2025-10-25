use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use libp2p::PeerId;
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
use rpp_chain::runtime::RuntimeMetrics;
use rpp_chain::types::{
    Account, ChainProof, ExecutionTrace, ProofKind, ProofPayload, ReputationWeights,
    SignedTransaction, Stake, StarkProof, Tier, Transaction, TransactionProofBundle,
    TransactionWitness,
};
use rpp_p2p::{GossipTopic, NetworkMetaTelemetryReport, TierLevel};
use serde::Deserialize;
use serde_json;

#[derive(Debug, Deserialize, Clone)]
struct StoredPeerRecordSnapshot {
    peer_id: String,
    reputation: f64,
    tier: TierLevel,
    #[serde(default)]
    ban_until: Option<u64>,
    #[serde(default)]
    features: BTreeMap<String, bool>,
}

fn reputation_floor_for_tier(tier: TierLevel) -> f64 {
    match tier {
        TierLevel::Tl0 => 0.0,
        TierLevel::Tl1 => 1.0,
        TierLevel::Tl2 => 2.0,
        TierLevel::Tl3 => 3.0,
        TierLevel::Tl4 => 4.0,
        TierLevel::Tl5 => 5.0,
    }
}

fn read_peerstore_snapshot(
    path: &Path,
    peer_id: &str,
) -> anyhow::Result<Option<StoredPeerRecordSnapshot>> {
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

fn system_time_to_millis(time: SystemTime) -> u64 {
    time.duration_since(std::time::UNIX_EPOCH)
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
    let task_b = tokio::spawn(async move {
        p2p_b.run().await.expect("run p2p b");
    });

    handle_a.attach_p2p(handle_a_runtime.clone()).await;
    handle_b.attach_p2p(handle_b_runtime.clone()).await;

    wait_for_peer(&handle_b_runtime, handle_a_runtime.local_peer_id()).await;

    let broadcaster_peer_id = handle_a_runtime.local_peer_id().to_base58();
    let peerstore_path = config_b.p2p.peerstore_path.clone();
    let baseline_record = read_peerstore_snapshot(&peerstore_path, &broadcaster_peer_id)?;

    let proof_storage_path = config_b.proof_cache_dir.join("gossip_proofs.json");
    let processor = Arc::new(NodeGossipProcessor::new(
        handle_b.clone(),
        proof_storage_path,
    ));
    let gossip_worker = spawn_node_event_worker(handle_b_runtime.subscribe(), processor, None);

    let bundle = sample_transaction_bundle(handle_b.address(), 0);
    let payload = serde_json::to_vec(&bundle)?;
    handle_a_runtime
        .publish_gossip(GossipTopic::WitnessProofs, payload)
        .await?;

    let mut proofs_rx = handle_b.subscribe_witness_gossip(GossipTopic::WitnessProofs);
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

    let peerstore_path_clone = peerstore_path.clone();
    let broadcaster_peer_id_clone = broadcaster_peer_id.clone();
    let post_gossip_record = time::timeout(Duration::from_secs(5), async move {
        loop {
            match read_peerstore_snapshot(&peerstore_path_clone, &broadcaster_peer_id_clone) {
                Ok(Some(record)) => return Ok(record),
                Ok(None) => {}
                Err(err) => return Err(err),
            }
            time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;

    let tier_floor = reputation_floor_for_tier(post_gossip_record.tier);
    if let Some(baseline) = baseline_record {
        assert_eq!(baseline.features.get("malachite_consensus"), Some(&true));
        assert_eq!(baseline.features.get("timetoke_rewards"), Some(&true));
        assert_eq!(baseline.features.get("witness_network"), Some(&true));
        assert!(
            post_gossip_record.reputation > baseline.reputation,
            "broadcaster peer {broadcaster_peer_id} reputation did not increase after gossip: baseline={:.3}, post={:.3}, tier={:?}, floor={:.3}",
            baseline.reputation,
            post_gossip_record.reputation,
            post_gossip_record.tier,
            tier_floor,
        );
    } else {
        assert!(
            post_gossip_record.reputation > tier_floor,
            "broadcaster peer {broadcaster_peer_id} reputation did not exceed tier floor after gossip: post={:.3}, tier={:?}, floor={:.3}",
            post_gossip_record.reputation,
            post_gossip_record.tier,
            tier_floor,
        );
    }

    assert_eq!(
        post_gossip_record.features.get("malachite_consensus"),
        Some(&true)
    );
    assert_eq!(
        post_gossip_record.features.get("timetoke_rewards"),
        Some(&true)
    );
    assert_eq!(
        post_gossip_record.features.get("witness_network"),
        Some(&true)
    );

    handle_a_runtime.shutdown().await?;
    handle_b_runtime.shutdown().await?;
    gossip_worker.await.expect("gossip worker completed")?;
    task_a.await.expect("p2p a completed");
    task_b.await.expect("p2p b completed");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_proof_gossip_penalizes_sender() -> Result<()> {
    let dir_a = tempdir()?;
    let dir_b = tempdir()?;

    let mut config_a = sample_node_config(dir_a.path());
    let mut config_b = sample_node_config(dir_b.path());

    let (listen_a, _) = random_listen_addr();
    let (listen_b, _) = random_listen_addr();
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
    let task_b = tokio::spawn(async move {
        p2p_b.run().await.expect("run p2p b");
    });

    handle_a.attach_p2p(handle_a_runtime.clone()).await;
    handle_b.attach_p2p(handle_b_runtime.clone()).await;

    wait_for_peer(&handle_b_runtime, handle_a_runtime.local_peer_id()).await;

    let broadcaster_peer_id = handle_a_runtime.local_peer_id().to_base58();
    let peerstore_path = config_b.p2p.peerstore_path.clone();
    let baseline_record = read_peerstore_snapshot(&peerstore_path, &broadcaster_peer_id)?;

    let proof_storage_path = config_b.proof_cache_dir.join("gossip_proofs_invalid.json");
    let processor = Arc::new(NodeGossipProcessor::new(
        handle_b.clone(),
        proof_storage_path,
    ));
    let gossip_worker = spawn_node_event_worker(handle_b_runtime.subscribe(), processor, None);

    handle_a_runtime
        .publish_gossip(GossipTopic::WitnessProofs, Vec::new())
        .await?;

    let peerstore_path_clone = peerstore_path.clone();
    let broadcaster_peer_id_clone = broadcaster_peer_id.clone();
    let penalty_record = time::timeout(Duration::from_secs(5), async move {
        loop {
            match read_peerstore_snapshot(&peerstore_path_clone, &broadcaster_peer_id_clone) {
                Ok(Some(record)) => return Ok(record),
                Ok(None) => {}
                Err(err) => return Err(err),
            }
            time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;

    let tier_floor = reputation_floor_for_tier(penalty_record.tier);
    if let Some(baseline) = baseline_record {
        assert_eq!(baseline.features.get("malachite_consensus"), Some(&true));
        assert_eq!(baseline.features.get("timetoke_rewards"), Some(&true));
        assert_eq!(baseline.features.get("witness_network"), Some(&true));
        assert!(
            penalty_record.reputation < baseline.reputation || penalty_record.ban_until.is_some(),
            "broadcaster peer {broadcaster_peer_id} reputation did not decrease after invalid gossip: baseline={:.3}, post={:.3}, tier={:?}, floor={:.3}",
            baseline.reputation,
            penalty_record.reputation,
            penalty_record.tier,
            tier_floor,
        );
    } else {
        assert!(
            penalty_record.reputation < tier_floor || penalty_record.ban_until.is_some(),
            "broadcaster peer {broadcaster_peer_id} was not penalised after invalid gossip: post={:.3}, tier={:?}, floor={:.3}",
            penalty_record.reputation,
            penalty_record.tier,
            tier_floor,
        );
    }

    assert_eq!(
        penalty_record.features.get("malachite_consensus"),
        Some(&true)
    );
    assert_eq!(penalty_record.features.get("timetoke_rewards"), Some(&true));
    assert_eq!(penalty_record.features.get("witness_network"), Some(&true));

    handle_a_runtime.shutdown().await?;
    handle_b_runtime.shutdown().await?;
    gossip_worker.await.expect("gossip worker completed")?;
    task_a.await.expect("p2p a completed");
    task_b.await.expect("p2p b completed");

    Ok(())
}

#[test]
fn proof_cache_rehydrates_on_restart() -> Result<()> {
    let dir = tempdir()?;
    let config = sample_node_config(dir.path());
    let proof_storage_path = config.proof_cache_dir.join("gossip_proofs.json");

    let node = Node::new(config.clone(), RuntimeMetrics::noop())?;
    let handle = node.handle();
    let processor = NodeGossipProcessor::new(handle.clone(), proof_storage_path.clone());

    let bundle = sample_transaction_bundle(handle.address(), 0);
    let payload = serde_json::to_vec(&bundle)?;
    let peer = PeerId::random();
    processor.handle_proof(&peer, &payload)?;

    assert!(proof_storage_path.exists());

    drop(processor);
    drop(handle);
    drop(node);

    let node_restarted = Node::new(config.clone(), RuntimeMetrics::noop())?;
    let handle_restarted = node_restarted.handle();
    assert!(handle_restarted.mempool_status()?.transactions.is_empty());

    let _rehydrated =
        NodeGossipProcessor::new(handle_restarted.clone(), proof_storage_path.clone());

    let mempool = handle_restarted.mempool_status()?;
    assert_eq!(mempool.transactions.len(), 1);
    assert_eq!(mempool.transactions[0].hash, bundle.hash());

    drop(node_restarted);

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
    let task_b = tokio::spawn(async move {
        p2p_b.run().await.expect("run p2p b");
    });

    handle_a.attach_p2p(handle_a_runtime.clone()).await;
    handle_b.attach_p2p(handle_b_runtime.clone()).await;

    wait_for_peer(&handle_b_runtime, handle_a_runtime.local_peer_id()).await;

    let mut events_b = handle_b_runtime.subscribe();
    let remote_peer = handle_a_runtime.local_peer_id();
    let local_peer = handle_b_runtime.local_peer_id();

    let (remote_sample, local_view): (PeerTelemetry, PeerTelemetry) =
        time::timeout(Duration::from_secs(10), async {
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
        })
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
