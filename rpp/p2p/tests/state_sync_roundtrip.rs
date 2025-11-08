use base64::{engine::general_purpose, Engine as _};
use rpp_p2p::{
    NetworkBlockMetadata, NetworkGlobalStateCommitments, NetworkLightClientUpdate,
    NetworkPayloadExpectations, NetworkPruningCommitment, NetworkPruningEnvelope,
    NetworkPruningSegment, NetworkPruningSnapshot, NetworkReconstructionRequest,
    NetworkSnapshotSummary, NetworkStateSyncChunk, NetworkStateSyncPlan, NetworkTaggedDigestHex,
};
use rpp_pruning::{
    DomainTag, COMMITMENT_TAG, DIGEST_LENGTH, ENVELOPE_TAG, PROOF_SEGMENT_TAG, SNAPSHOT_STATE_TAG,
};

fn tagged_bytes(tag: DomainTag, byte: u8) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(DIGEST_LENGTH + tag.as_bytes().len());
    bytes.extend_from_slice(&tag.as_bytes());
    bytes.extend(std::iter::repeat(byte).take(DIGEST_LENGTH));
    bytes
}

fn tagged_hex(tag: DomainTag, byte: u8) -> String {
    hex::encode(tagged_bytes(tag, byte))
}

fn tagged_base64(tag: DomainTag, byte: u8) -> String {
    general_purpose::STANDARD.encode(tagged_bytes(tag, byte))
}

fn tagged_hex_digest(tag: DomainTag, byte: u8) -> NetworkTaggedDigestHex {
    NetworkTaggedDigestHex::from(tagged_hex(tag, byte))
}

fn sample_pruning_envelope() -> NetworkPruningEnvelope {
    NetworkPruningEnvelope {
        schema_version: 1,
        parameter_version: 0,
        snapshot: NetworkPruningSnapshot {
            schema_version: 1,
            parameter_version: 0,
            block_height: 0,
            state_commitment: tagged_hex_digest(SNAPSHOT_STATE_TAG, 0x01),
        },
        segments: vec![NetworkPruningSegment {
            schema_version: 1,
            parameter_version: 0,
            segment_index: 0,
            start_height: 0,
            end_height: 0,
            segment_commitment: tagged_hex_digest(PROOF_SEGMENT_TAG, 0x02),
        }],
        commitment: NetworkPruningCommitment {
            schema_version: 1,
            parameter_version: 0,
            aggregate_commitment: tagged_hex_digest(COMMITMENT_TAG, 0x03),
        },
        binding_digest: tagged_hex_digest(ENVELOPE_TAG, 0x04),
    }
}

#[test]
fn state_sync_plan_roundtrip() {
    let pruning = sample_pruning_envelope();
    let plan = NetworkStateSyncPlan {
        snapshot: NetworkSnapshotSummary {
            height: 0,
            block_hash: "snapshot".into(),
            commitments: NetworkGlobalStateCommitments {
                global_state_root: "00".repeat(32),
                utxo_root: "11".repeat(32),
                reputation_root: "22".repeat(32),
                timetoke_root: "33".repeat(32),
                zsi_root: "44".repeat(32),
                proof_root: "55".repeat(32),
            },
            chain_commitment: "aa".repeat(32),
            manifest_signature: String::new(),
        },
        tip: NetworkBlockMetadata {
            height: 1,
            hash: "tip".into(),
            timestamp: 42,
            previous_state_root: "66".repeat(32),
            new_state_root: "77".repeat(32),
            proof_hash: "88".repeat(32),
            pruning: Some(pruning.clone()),
            recursion_anchor: "anchor".into(),
        },
        chunks: vec![NetworkStateSyncChunk {
            start_height: 0,
            end_height: 1,
            requests: vec![NetworkReconstructionRequest {
                height: 0,
                block_hash: "block".into(),
                tx_root: "tx".into(),
                state_root: "state".into(),
                utxo_root: "utxo".into(),
                reputation_root: "reputation".into(),
                timetoke_root: "timetoke".into(),
                zsi_root: "zsi".into(),
                proof_root: "proof".into(),
                pruning: pruning.clone(),
                previous_commitment: None,
                payload_expectations: NetworkPayloadExpectations::default(),
            }],
            proofs: vec![tagged_base64(COMMITMENT_TAG, 0x03)],
        }],
        light_client_updates: vec![NetworkLightClientUpdate {
            height: 1,
            block_hash: "block".into(),
            state_root: "state".into(),
            proof_commitment: "bb".repeat(32),
            previous_commitment: Some("aa".repeat(32)),
            recursive_proof: String::new(),
        }],
    };

    let encoded = serde_json::to_vec(&plan).expect("encode plan");
    let decoded: NetworkStateSyncPlan = serde_json::from_slice(&encoded).expect("decode plan");
    assert_eq!(decoded.snapshot.block_hash, plan.snapshot.block_hash);
    assert_eq!(decoded.chunks.len(), 1);
    assert_eq!(decoded.light_client_updates.len(), 1);
}

#[test]
fn state_sync_chunk_roundtrip() {
    let proof_one = tagged_base64(COMMITMENT_TAG, 0x05);
    let proof_two = tagged_base64(COMMITMENT_TAG, 0x06);
    let chunk = NetworkStateSyncChunk {
        start_height: 10,
        end_height: 12,
        requests: vec![NetworkReconstructionRequest {
            height: 10,
            block_hash: "block-10".into(),
            tx_root: "tx".into(),
            state_root: "state".into(),
            utxo_root: "utxo".into(),
            reputation_root: "rep".into(),
            timetoke_root: "time".into(),
            zsi_root: "zsi".into(),
            proof_root: "proof".into(),
            pruning: sample_pruning_envelope(),
            previous_commitment: None,
            payload_expectations: NetworkPayloadExpectations::default(),
        }],
        proofs: vec![proof_one.clone(), proof_two.clone()],
    };

    let encoded = serde_json::to_vec(&chunk).expect("encode chunk");
    let decoded: NetworkStateSyncChunk = serde_json::from_slice(&encoded).expect("decode chunk");
    assert_eq!(decoded.proofs, vec![proof_one, proof_two]);
}

#[test]
fn light_client_update_roundtrip() {
    let proof_payload = general_purpose::STANDARD.encode(b"recursive-proof");
    let update = NetworkLightClientUpdate {
        height: 5,
        block_hash: "block-5".into(),
        state_root: "state".into(),
        proof_commitment: "dd".repeat(32),
        previous_commitment: Some("cc".repeat(32)),
        recursive_proof: proof_payload.clone(),
    };

    let encoded = serde_json::to_vec(&update).expect("encode update");
    let decoded: NetworkLightClientUpdate =
        serde_json::from_slice(&encoded).expect("decode update");
    assert_eq!(decoded.recursive_proof, proof_payload);
    assert_eq!(decoded.proof_commitment, update.proof_commitment);
}
