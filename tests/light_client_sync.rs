mod support;

use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rpp_chain::config::NodeConfig;
use rpp_chain::errors::ChainError;
use rpp_chain::node::Node;
use rpp_chain::runtime::sync::{ReconstructionEngine, RuntimeRecursiveProofVerifier};
use rpp_chain::runtime::RuntimeMetrics;
use rpp_p2p::{
    GossipTopic, LightClientSync, NetworkLightClientUpdate, NetworkStateSyncChunk,
    NetworkStateSyncPlan, PipelineError, SnapshotStore,
};
use serde::Serialize;
use tempfile::TempDir;
use tokio::sync::broadcast::{self, Receiver};
use tokio::time::timeout;

use support::{collect_state_sync_artifacts, mutate_hex};

const GOSSIP_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn light_client_stream_verifies_state_sync() {
    let fixture = StateSyncFixture::new();
    let mut light_client =
        LightClientSync::new(Arc::new(RuntimeRecursiveProofVerifier::default()), None);
    let mut receiver = fixture
        .node
        .subscribe_witness_gossip(GossipTopic::Snapshots);

    let plan_bytes = publish_snapshot(&fixture.handle, &mut receiver, &fixture.plan).await;
    light_client
        .ingest_plan(&plan_bytes)
        .expect("ingest state sync plan");

    let mut head_rx = light_client.subscribe_light_client_heads();
    assert!(
        head_rx.borrow().is_none(),
        "head channel should start empty"
    );

    for chunk in &fixture.chunk_messages {
        let bytes = publish_snapshot(&fixture.handle, &mut receiver, chunk).await;
        light_client
            .ingest_chunk(&bytes)
            .expect("ingest state sync chunk");
        assert!(
            head_rx.borrow().is_none(),
            "chunks alone should not emit heads"
        );
    }

    for update in &fixture.updates {
        let bytes = publish_snapshot(&fixture.handle, &mut receiver, update).await;
        light_client
            .ingest_light_client_update(&bytes)
            .expect("ingest light client update");
    }

    timeout(GOSSIP_TIMEOUT, head_rx.changed())
        .await
        .expect("head update notification")
        .expect("head channel not closed");
    let latest_head = head_rx
        .borrow()
        .clone()
        .expect("verified head should be available");
    let expected_height = fixture.updates.last().expect("fixture has updates").height;
    assert_eq!(latest_head.height, expected_height);

    let verified = light_client.verify().expect("verify snapshot");
    assert!(verified, "snapshot verification should succeed");
}

#[tokio::test]
async fn state_sync_chunk_index_errors_surface_chain_error() {
    let fixture = StateSyncFixture::new();
    let mut store = SnapshotStore::new(8);
    let root = store.insert(vec![0u8; 32]);

    let stream = fixture
        .handle
        .stream_state_sync_chunks(&store, &root)
        .expect("stream snapshot chunks");
    assert_eq!(stream.total(), 4, "chunk stream computes expected length");

    let error = fixture
        .handle
        .state_sync_chunk_by_index(&store, &root, 10)
        .expect_err("invalid chunk index should surface error");
    match error {
        ChainError::Config(message) => {
            assert!(
                message.contains("chunk 10"),
                "unexpected error message: {message}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[tokio::test]
async fn light_client_rejects_mismatched_commitment() {
    let fixture = StateSyncFixture::new();
    let mut light_client =
        LightClientSync::new(Arc::new(RuntimeRecursiveProofVerifier::default()), None);
    let mut receiver = fixture
        .node
        .subscribe_witness_gossip(GossipTopic::Snapshots);

    let plan_bytes = publish_snapshot(&fixture.handle, &mut receiver, &fixture.plan).await;
    light_client
        .ingest_plan(&plan_bytes)
        .expect("ingest state sync plan");

    // Provide the chunk so the client can progress to proof validation.
    for chunk in &fixture.chunk_messages {
        let bytes = publish_snapshot(&fixture.handle, &mut receiver, chunk).await;
        light_client
            .ingest_chunk(&bytes)
            .expect("ingest state sync chunk");
    }

    let mut bad_update = fixture
        .updates
        .first()
        .expect("at least one light client update")
        .clone();
    bad_update.proof_commitment = mutate_hex(&bad_update.proof_commitment);

    let bytes = publish_snapshot(&fixture.handle, &mut receiver, &bad_update).await;
    let error = light_client
        .ingest_light_client_update(&bytes)
        .expect_err("commitment mismatch should be rejected");

    match error {
        PipelineError::SnapshotVerification(message) => {
            assert!(message.contains("commitment mismatch"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[tokio::test]
async fn light_client_fails_when_chunk_missing() {
    let fixture = StateSyncFixture::new();
    let mut light_client =
        LightClientSync::new(Arc::new(RuntimeRecursiveProofVerifier::default()), None);
    let mut receiver = fixture
        .node
        .subscribe_witness_gossip(GossipTopic::Snapshots);

    let plan_bytes = publish_snapshot(&fixture.handle, &mut receiver, &fixture.plan).await;
    light_client
        .ingest_plan(&plan_bytes)
        .expect("ingest state sync plan");

    for update in &fixture.updates {
        let bytes = publish_snapshot(&fixture.handle, &mut receiver, update).await;
        light_client
            .ingest_light_client_update(&bytes)
            .expect("ingest light client update");
    }

    let error = light_client
        .verify()
        .expect_err("verification should fail without chunks");
    match error {
        PipelineError::SnapshotVerification(message) => {
            assert!(message.contains("incomplete chunk set"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn light_client_accepts_plan_with_valid_manifest_signature() {
    let fixture = StateSyncFixture::new();
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let verifying = Arc::new(VerifyingKey::from(&signing));
    let mut plan = fixture.plan.clone();
    plan.snapshot.manifest_signature = sign_snapshot_summary(&plan, &signing);
    let mut light_client = LightClientSync::new(
        Arc::new(RuntimeRecursiveProofVerifier::default()),
        Some(verifying),
    );
    let payload = serde_json::to_vec(&plan).expect("encode snapshot plan");
    light_client
        .ingest_plan(&payload)
        .expect("manifest signature should be accepted");
}

#[test]
fn light_client_rejects_plan_with_invalid_manifest_signature() {
    let fixture = StateSyncFixture::new();
    let signing = SigningKey::from_bytes(&[9u8; 32]);
    let verifying = Arc::new(VerifyingKey::from(&signing));
    let mut plan = fixture.plan.clone();
    plan.snapshot.manifest_signature = sign_snapshot_summary(&plan, &signing);
    plan.snapshot.manifest_signature = corrupt_signature(&plan.snapshot.manifest_signature);
    let mut light_client = LightClientSync::new(
        Arc::new(RuntimeRecursiveProofVerifier::default()),
        Some(verifying),
    );
    let payload = serde_json::to_vec(&plan).expect("encode snapshot plan");
    let error = light_client
        .ingest_plan(&payload)
        .expect_err("invalid signature should be rejected");
    match error {
        PipelineError::SnapshotVerification(message) => {
            assert!(
                message.contains("manifest signature"),
                "unexpected message: {message}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

fn sign_snapshot_summary(plan: &NetworkStateSyncPlan, signing: &SigningKey) -> String {
    let payload = plan
        .snapshot
        .signing_bytes()
        .expect("snapshot summary payload");
    let signature = signing.sign(&payload);
    general_purpose::STANDARD.encode(signature.to_bytes())
}

fn corrupt_signature(signature: &str) -> String {
    let mut chars: Vec<char> = signature.chars().collect();
    if let Some(first) = chars.first_mut() {
        *first = if *first == 'A' { 'B' } else { 'A' };
    }
    chars.into_iter().collect()
}

async fn publish_snapshot<T>(
    handle: &rpp_chain::node::NodeHandle,
    receiver: &mut Receiver<Vec<u8>>,
    payload: &T,
) -> Vec<u8>
where
    T: Serialize,
{
    drain_receiver(receiver);
    let bytes = serde_json::to_vec(payload).expect("encode snapshot payload");
    handle.fanout_witness_gossip(GossipTopic::Snapshots, &bytes);
    let received = timeout(GOSSIP_TIMEOUT, receiver.recv())
        .await
        .expect("snapshot gossip receive timeout")
        .expect("snapshot gossip payload");
    assert_eq!(received, bytes);
    received
}

fn drain_receiver(receiver: &mut Receiver<Vec<u8>>) {
    loop {
        match receiver.try_recv() {
            Ok(_) => continue,
            Err(broadcast::error::TryRecvError::Empty) => break,
            Err(broadcast::error::TryRecvError::Closed) => break,
        }
    }
}

struct StateSyncFixture {
    #[allow(dead_code)]
    temp_dir: TempDir,
    node: Node,
    handle: rpp_chain::node::NodeHandle,
    plan: NetworkStateSyncPlan,
    chunk_messages: Vec<NetworkStateSyncChunk>,
    updates: Vec<NetworkLightClientUpdate>,
}

impl StateSyncFixture {
    fn new() -> Self {
        let (config, temp_dir) = prepare_config();
        let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
        let handle = node.handle();
        let storage = handle.storage();
        let pruned = storage
            .prune_block_payload(0)
            .expect("prune genesis payload");
        assert!(pruned, "expected genesis payload to be pruned");
        let engine = ReconstructionEngine::new(storage.clone());
        let artifacts = collect_state_sync_artifacts(&engine, 1).expect("state sync artifacts");
        assert!(
            !artifacts.plan.chunks.is_empty(),
            "state sync plan should contain at least one chunk"
        );
        Self {
            temp_dir,
            node,
            handle,
            plan: artifacts.network_plan,
            chunk_messages: artifacts.chunk_messages,
            updates: artifacts.updates,
        }
    }
}

fn prepare_config() -> (NodeConfig, TempDir) {
    let temp_dir = TempDir::new().expect("temp dir");
    let mut config = NodeConfig::default();
    let data_dir = temp_dir.path().join("data");
    let keys_dir = temp_dir.path().join("keys");
    std::fs::create_dir_all(&data_dir).expect("data dir");
    std::fs::create_dir_all(&keys_dir).expect("keys dir");
    config.data_dir = data_dir.clone();
    config.snapshot_dir = data_dir.join("snapshots");
    config.proof_cache_dir = data_dir.join("proofs");
    config.network.p2p.peerstore_path = data_dir.join("p2p/peerstore.json");
    config.network.p2p.gossip_path = Some(data_dir.join("p2p/gossip.json"));
    config.key_path = keys_dir.join("node.toml");
    config.p2p_key_path = keys_dir.join("p2p.toml");
    config.vrf_key_path = keys_dir.join("vrf.toml");
    config.network.rpc.listen = "127.0.0.1:0".parse().expect("rpc listen");
    (config, temp_dir)
}
