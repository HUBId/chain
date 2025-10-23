use std::sync::Arc;
use std::time::Duration;

use rpp_chain::config::NodeConfig;
use rpp_chain::node::Node;
use rpp_chain::runtime::sync::{ReconstructionEngine, RuntimeRecursiveProofVerifier};
use rpp_p2p::{
    GossipTopic, LightClientSync, NetworkLightClientUpdate, NetworkStateSyncChunk,
    NetworkStateSyncPlan, PipelineError,
};
use serde::Serialize;
use tempfile::TempDir;
use tokio::sync::broadcast::{self, Receiver};
use tokio::time::timeout;

const GOSSIP_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn light_client_stream_verifies_state_sync() {
    let fixture = StateSyncFixture::new();
    let mut light_client = LightClientSync::new(Arc::new(RuntimeRecursiveProofVerifier::default()));
    let mut receiver = fixture
        .node
        .subscribe_witness_gossip(GossipTopic::Snapshots);

    let plan_bytes = publish_snapshot(&fixture.handle, &mut receiver, &fixture.plan).await;
    light_client
        .ingest_plan(&plan_bytes)
        .expect("ingest state sync plan");

    for chunk in &fixture.chunk_messages {
        let bytes = publish_snapshot(&fixture.handle, &mut receiver, chunk).await;
        light_client
            .ingest_chunk(&bytes)
            .expect("ingest state sync chunk");
    }

    for update in &fixture.updates {
        let bytes = publish_snapshot(&fixture.handle, &mut receiver, update).await;
        light_client
            .ingest_light_client_update(&bytes)
            .expect("ingest light client update");
    }

    let verified = light_client.verify().expect("verify snapshot");
    assert!(verified, "snapshot verification should succeed");
}

#[tokio::test]
async fn light_client_rejects_mismatched_commitment() {
    let fixture = StateSyncFixture::new();
    let mut light_client = LightClientSync::new(Arc::new(RuntimeRecursiveProofVerifier::default()));
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
    bad_update.proof_commitment = flip_last_hex_digit(&bad_update.proof_commitment);

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
    let mut light_client = LightClientSync::new(Arc::new(RuntimeRecursiveProofVerifier::default()));
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

fn flip_last_hex_digit(commitment: &str) -> String {
    assert_eq!(commitment.len(), 64, "commitment must be 32-byte hex");
    let mut chars: Vec<char> = commitment.chars().collect();
    let last = chars
        .last_mut()
        .expect("commitment should contain at least one character");
    *last = match *last {
        '0' => '1',
        '1' => '2',
        '2' => '3',
        '3' => '4',
        '4' => '5',
        '5' => '6',
        '6' => '7',
        '7' => '8',
        '8' => '9',
        '9' => 'a',
        'a' => 'b',
        'b' => 'c',
        'c' => 'd',
        'd' => 'e',
        'e' => 'f',
        'f' => '0',
        other => panic!("unexpected hex digit: {other}"),
    };
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
        let node = Node::new(config).expect("node");
        let handle = node.handle();
        let storage = handle.storage();
        let pruned = storage
            .prune_block_payload(0)
            .expect("prune genesis payload");
        assert!(pruned, "expected genesis payload to be pruned");
        let engine = ReconstructionEngine::new(storage.clone());
        let plan = engine.state_sync_plan(1).expect("state sync plan");
        assert!(
            !plan.chunks.is_empty(),
            "state sync plan should contain at least one chunk"
        );
        let plan_summary = plan.to_network_plan().expect("network state sync plan");
        let chunk_messages = plan.chunk_messages().expect("chunk messages");
        let updates = plan.light_client_messages().expect("light client updates");
        Self {
            temp_dir,
            node,
            handle,
            plan: plan_summary,
            chunk_messages,
            updates,
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
    config.p2p.peerstore_path = data_dir.join("p2p/peerstore.json");
    config.p2p.gossip_path = Some(data_dir.join("p2p/gossip.json"));
    config.key_path = keys_dir.join("node.toml");
    config.p2p_key_path = keys_dir.join("p2p.toml");
    config.vrf_key_path = keys_dir.join("vrf.toml");
    config.rpc_listen = "127.0.0.1:0".parse().expect("rpc listen");
    (config, temp_dir)
}
