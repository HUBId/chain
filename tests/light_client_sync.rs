use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose};
use rpp_chain::config::NodeConfig;
use rpp_chain::node::{Node, NodeHandle};
use rpp_chain::proof_system::ProofVerifier;
use rpp_chain::stwo::verifier::NodeVerifier;
use rpp_chain::sync::{
    LightClientUpdate, PayloadExpectations, ReconstructionEngine, ReconstructionRequest,
    StateSyncChunk, StateSyncPlan,
};
use rpp_chain::types::ChainProof;
use rpp_p2p::{
    GossipTopic, HandshakePayload, LightClientSync, Network, NetworkError, PipelineError, TierLevel,
};
use rpp_p2p::{NodeIdentity, Peerstore, PeerstoreConfig};
use serde::{Deserialize, Serialize};
use tempfile::tempdir;
use tokio::time::sleep;

/// Integration test ensuring the light-client sync machinery can consume a
/// snapshot broadcast emitted by a validator node and validate it locally.
///
/// The network stack is still under construction, so the test is ignored until
/// the snapshot gossip broadcaster is fully wired up in CI.
#[ignore = "snapshot gossip integration pending"]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn light_client_sync_reconstructs_snapshot_stream() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    let temp = tempdir().context("temporary directory")?;
    let node_data = temp.path().join("node");
    let key_dir = temp.path().join("keys");
    std::fs::create_dir_all(&node_data).context("node dir")?;
    std::fs::create_dir_all(&key_dir).context("keys dir")?;

    let mut node_config = NodeConfig::default();
    node_config.data_dir = node_data.clone();
    node_config.key_path = key_dir.join("node.toml");
    node_config.p2p_key_path = key_dir.join("p2p.toml");
    node_config.vrf_key_path = key_dir.join("vrf.toml");
    node_config.snapshot_dir = node_data.join("snapshots");
    node_config.proof_cache_dir = node_data.join("proofs");
    node_config.block_time_ms = 100;
    node_config.mempool_limit = 32;

    let node = Node::new(node_config.clone()).context("spawn node")?;
    let handle = node.handle();

    let node_task = tokio::spawn(async move {
        let _ = node.start().await;
    });

    wait_for_min_height(&handle, 2).await?;

    node_task.abort();
    let _ = node_task.await;

    let storage = handle.storage();
    let tip_metadata = storage
        .tip()
        .context("node tip")?
        .ok_or_else(|| anyhow!("node tip missing"))?;
    for height in 1..=tip_metadata.height {
        storage
            .prune_block_payload(height)
            .with_context(|| format!("prune payload at height {height}"))?;
    }

    let engine = ReconstructionEngine::new(storage.clone());
    let plan = engine.state_sync_plan(1).context("state sync plan")?;
    assert!(
        !plan.chunks.is_empty(),
        "state sync plan should include pruned chunks"
    );
    assert!(
        plan.light_client_updates.len() > 1,
        "plan should include recursive proofs for multiple heights"
    );

    // Simulate the SnapshotBroadcaster output by translating the runtime plan
    // into the gossip payloads consumed by the light client.
    let network_plan = encode_network_plan(&plan)?;
    let plan_payload = serde_json::to_vec(&network_plan).context("encode plan")?;
    let chunk_payloads: Vec<Vec<u8>> = network_plan
        .chunks
        .iter()
        .map(|chunk| serde_json::to_vec(chunk).expect("encode chunk"))
        .collect();
    let update_payloads: Vec<Vec<u8>> = network_plan
        .light_client_updates
        .iter()
        .map(|update| serde_json::to_vec(update).expect("encode update"))
        .collect();

    assert!(
        !chunk_payloads.is_empty(),
        "snapshot broadcaster must emit at least one chunk"
    );
    assert!(
        update_payloads.len() >= 2,
        "snapshot broadcaster must emit multiple recursive proofs"
    );

    let verifier = Arc::new(RuntimeRecursiveVerifier::new());
    let light_client_identity = Arc::new(
        NodeIdentity::load_or_generate(temp.path().join("light-client.key"))
            .context("light client identity")?,
    );
    let peerstore = Arc::new(Peerstore::open(PeerstoreConfig::memory()).context("peerstore")?);
    let handshake = HandshakePayload::new("light-client", Vec::new(), TierLevel::Tl1);
    let mut light_client_network = Network::new(light_client_identity, peerstore, handshake, None)
        .context("light client network")?;

    // Ensure the peer subscribes to the snapshot gossip topic eagerly.
    let _peer_id = light_client_network.local_peer_id();
    match light_client_network.publish(GossipTopic::Snapshots, b"dry-run".to_vec()) {
        Ok(_) => {}
        Err(NetworkError::Gossipsub(_)) | Err(NetworkError::Persistence(_)) => {}
        Err(other) => panic!("unexpected publish error: {other:?}"),
    }

    let mut client = LightClientSync::new(verifier.clone());
    client.ingest_plan(&plan_payload).context("ingest plan")?;
    for payload in &chunk_payloads {
        client.ingest_chunk(payload).context("ingest chunk")?;
    }
    for payload in &update_payloads {
        client
            .ingest_light_client_update(payload)
            .context("ingest update")?;
    }
    assert!(client.verify().context("verify plan")?);
    assert_eq!(plan.tip.height, tip_metadata.height);
    assert_eq!(plan.tip.hash, tip_metadata.hash);

    // Missing recursive proof should prevent verification.
    let mut missing_proof = LightClientSync::new(verifier.clone());
    missing_proof
        .ingest_plan(&plan_payload)
        .context("ingest plan (missing proof)")?;
    for payload in &chunk_payloads {
        missing_proof
            .ingest_chunk(payload)
            .context("ingest chunk (missing proof)")?;
    }
    for payload in update_payloads.iter().take(update_payloads.len() - 1) {
        missing_proof
            .ingest_light_client_update(payload)
            .context("ingest partial updates")?;
    }
    match missing_proof.verify() {
        Err(PipelineError::SnapshotVerification(_)) => {}
        other => panic!("expected snapshot verification error, got {other:?}"),
    }

    // Corrupted chunk payload must be rejected during ingestion.
    let mut corrupted_chunk: GossipStateSyncChunk =
        serde_json::from_slice(&chunk_payloads[0]).context("decode chunk")?;
    if let Some(first_proof) = corrupted_chunk.proofs.get_mut(0) {
        if first_proof.len() > 4 {
            first_proof.replace_range(0..4, "dead");
        } else {
            first_proof.push_str("dead");
        }
    }
    let corrupted_payload = serde_json::to_vec(&corrupted_chunk).context("encode bad chunk")?;
    let mut corrupted_client = LightClientSync::new(verifier);
    corrupted_client
        .ingest_plan(&plan_payload)
        .context("ingest plan (corrupted chunk)")?;
    assert!(
        corrupted_client.ingest_chunk(&corrupted_payload).is_err(),
        "corrupted chunk payload should be rejected"
    );

    Ok(())
}

async fn wait_for_min_height(handle: &NodeHandle, target: u64) -> Result<()> {
    for _ in 0..30 {
        if let Some(block) = handle.latest_block().context("latest block")? {
            if block.header.height >= target {
                return Ok(());
            }
        }
        sleep(Duration::from_millis(200)).await;
    }
    bail!("timed out waiting for height {target}");
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GossipStateSyncPlan {
    snapshot: GossipSnapshotSummary,
    tip: GossipBlockMetadata,
    chunks: Vec<GossipStateSyncChunk>,
    light_client_updates: Vec<GossipLightClientUpdate>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GossipSnapshotSummary {
    height: u64,
    block_hash: String,
    commitments: GossipGlobalStateCommitments,
    chain_commitment: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GossipGlobalStateCommitments {
    global_state_root: String,
    utxo_root: String,
    reputation_root: String,
    timetoke_root: String,
    zsi_root: String,
    proof_root: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GossipBlockMetadata {
    height: u64,
    hash: String,
    timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GossipStateSyncChunk {
    start_height: u64,
    end_height: u64,
    requests: Vec<GossipReconstructionRequest>,
    proofs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GossipReconstructionRequest {
    height: u64,
    block_hash: String,
    tx_root: String,
    state_root: String,
    utxo_root: String,
    reputation_root: String,
    timetoke_root: String,
    zsi_root: String,
    proof_root: String,
    pruning_commitment: String,
    aggregated_commitment: String,
    previous_commitment: Option<String>,
    payload_expectations: GossipPayloadExpectations,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GossipPayloadExpectations {
    transaction_proofs: usize,
    transaction_witnesses: usize,
    timetoke_witnesses: usize,
    reputation_witnesses: usize,
    zsi_witnesses: usize,
    consensus_witnesses: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GossipLightClientUpdate {
    height: u64,
    block_hash: String,
    state_root: String,
    proof_commitment: String,
    #[serde(default)]
    previous_commitment: Option<String>,
    #[serde(default)]
    recursive_proof: String,
}

fn encode_network_plan(plan: &StateSyncPlan) -> Result<GossipStateSyncPlan> {
    let commitments = GossipGlobalStateCommitments {
        global_state_root: hex::encode(plan.snapshot.commitments.global_state_root),
        utxo_root: hex::encode(plan.snapshot.commitments.utxo_root),
        reputation_root: hex::encode(plan.snapshot.commitments.reputation_root),
        timetoke_root: hex::encode(plan.snapshot.commitments.timetoke_root),
        zsi_root: hex::encode(plan.snapshot.commitments.zsi_root),
        proof_root: hex::encode(plan.snapshot.commitments.proof_root),
    };
    let snapshot = GossipSnapshotSummary {
        height: plan.snapshot.height,
        block_hash: plan.snapshot.block_hash.clone(),
        commitments,
        chain_commitment: plan.snapshot.chain_commitment.clone(),
    };
    let tip = GossipBlockMetadata {
        height: plan.tip.height,
        hash: plan.tip.hash.clone(),
        timestamp: plan.tip.timestamp,
    };
    let chunks = plan
        .chunks
        .iter()
        .map(encode_chunk)
        .collect::<Result<Vec<_>>>()?;
    let updates = encode_updates(&plan.snapshot.chain_commitment, &plan.light_client_updates)?;
    Ok(GossipStateSyncPlan {
        snapshot,
        tip,
        chunks,
        light_client_updates: updates,
    })
}

fn encode_chunk(chunk: &StateSyncChunk) -> Result<GossipStateSyncChunk> {
    let requests = chunk
        .requests
        .iter()
        .map(encode_request)
        .collect::<Result<Vec<_>>>()?;
    let proofs = requests
        .iter()
        .map(|req| req.aggregated_commitment.clone())
        .collect();
    Ok(GossipStateSyncChunk {
        start_height: chunk.start_height,
        end_height: chunk.end_height,
        requests,
        proofs,
    })
}

fn encode_request(request: &ReconstructionRequest) -> Result<GossipReconstructionRequest> {
    Ok(GossipReconstructionRequest {
        height: request.height,
        block_hash: request.block_hash.clone(),
        tx_root: request.tx_root.clone(),
        state_root: request.state_root.clone(),
        utxo_root: request.utxo_root.clone(),
        reputation_root: request.reputation_root.clone(),
        timetoke_root: request.timetoke_root.clone(),
        zsi_root: request.zsi_root.clone(),
        proof_root: request.proof_root.clone(),
        pruning_commitment: request.pruning_commitment.clone(),
        aggregated_commitment: request.aggregated_commitment.clone(),
        previous_commitment: request.previous_commitment.clone(),
        payload_expectations: encode_expectations(&request.payload_expectations),
    })
}

fn encode_expectations(expectations: &PayloadExpectations) -> GossipPayloadExpectations {
    GossipPayloadExpectations {
        transaction_proofs: expectations.transaction_proofs,
        transaction_witnesses: expectations.transaction_witnesses,
        timetoke_witnesses: expectations.timetoke_witnesses,
        reputation_witnesses: expectations.reputation_witnesses,
        zsi_witnesses: expectations.zsi_witnesses,
        consensus_witnesses: expectations.consensus_witnesses,
    }
}

fn encode_updates(
    snapshot_commitment: &str,
    updates: &[LightClientUpdate],
) -> Result<Vec<GossipLightClientUpdate>> {
    let mut previous = Some(snapshot_commitment.to_string());
    let mut encoded = Vec::with_capacity(updates.len());
    for update in updates {
        let stark = match &update.recursive_proof {
            ChainProof::Stwo(proof) => proof.clone(),
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => {
                bail!("plonky3 backend not supported in light client sync tests")
            }
        };
        let proof_bytes = serde_json::to_vec(&ChainProof::Stwo(stark.clone()))?;
        let recursive_proof = general_purpose::STANDARD.encode(proof_bytes);
        encoded.push(GossipLightClientUpdate {
            height: update.height,
            block_hash: update.block_hash.clone(),
            state_root: update.state_root.clone(),
            proof_commitment: stark.commitment.clone(),
            previous_commitment: previous.clone(),
            recursive_proof,
        });
        previous = Some(stark.commitment);
    }
    Ok(encoded)
}

#[derive(Clone)]
struct RuntimeRecursiveVerifier {
    inner: NodeVerifier,
}

impl RuntimeRecursiveVerifier {
    fn new() -> Self {
        Self {
            inner: NodeVerifier::new(),
        }
    }
}

impl Default for RuntimeRecursiveVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RuntimeRecursiveVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeRecursiveVerifier").finish()
    }
}

impl rpp_p2p::RecursiveProofVerifier for RuntimeRecursiveVerifier {
    fn verify_recursive(
        &self,
        proof: &[u8],
        expected_commitment: &str,
        previous_commitment: Option<&str>,
    ) -> Result<(), PipelineError> {
        let chain_proof: ChainProof = serde_json::from_slice(proof).map_err(|err| {
            PipelineError::Validation(format!("invalid recursive proof payload: {err}"))
        })?;
        let stark = match chain_proof {
            ChainProof::Stwo(proof) => proof,
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => {
                return Err(PipelineError::SnapshotVerification(
                    "plonky3 proofs are not supported in this verifier".into(),
                ));
            }
        };
        if stark.commitment != expected_commitment {
            return Err(PipelineError::SnapshotVerification(format!(
                "recursive proof commitment mismatch: expected {expected_commitment}, got {}",
                stark.commitment
            )));
        }
        if let Some(expected_previous) = previous_commitment {
            if let Some(actual_previous) = stark.public_inputs.get(0) {
                if actual_previous != expected_previous {
                    return Err(PipelineError::SnapshotVerification(format!(
                        "previous commitment mismatch: expected {expected_previous}, got {actual_previous}"
                    )));
                }
            }
        }
        self.inner
            .verify_recursive(&ChainProof::Stwo(stark.clone()))
            .map_err(|err| PipelineError::SnapshotVerification(err.to_string()))
    }
}
