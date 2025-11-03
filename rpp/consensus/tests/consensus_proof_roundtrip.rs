use hex;
use rpp_consensus::messages::{
    compute_consensus_bindings, BlockId, ConsensusCertificate, ConsensusProofMetadata,
    ConsensusVrfEntry, ConsensusVrfPoseidonInput,
};
use rpp_consensus::proof_backend::ProofSystemKind;
use rpp_crypto_vrf::{VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH};
use serde_json::Value;

fn vrf_entry(randomness_byte: u8, proof_byte: u8) -> ConsensusVrfEntry {
    let poseidon_seed = randomness_byte.wrapping_add(1);
    ConsensusVrfEntry {
        randomness: hex::encode([randomness_byte; 32]),
        pre_output: hex::encode(vec![randomness_byte; VRF_PREOUTPUT_LENGTH]),
        proof: hex::encode(vec![proof_byte; VRF_PROOF_LENGTH]),
        public_key: hex::encode([randomness_byte.wrapping_add(2); 32]),
        poseidon: ConsensusVrfPoseidonInput {
            digest: hex::encode([poseidon_seed; 32]),
            last_block_header: hex::encode([poseidon_seed.wrapping_add(1); 32]),
            epoch: format!("{}", poseidon_seed),
            tier_seed: hex::encode([poseidon_seed.wrapping_add(2); 32]),
        },
    }
}

fn metadata_fixture(
    vrf_entries: Vec<ConsensusVrfEntry>,
    witness_commitments: Vec<String>,
    reputation_roots: Vec<String>,
    epoch: u64,
    slot: u64,
    quorum_bitmap_root: String,
    quorum_signature_root: String,
) -> ConsensusProofMetadata {
    ConsensusProofMetadata {
        vrf_entries,
        witness_commitments,
        reputation_roots,
        epoch,
        slot,
        quorum_bitmap_root,
        quorum_signature_root,
    }
}

fn sample_metadata() -> ConsensusProofMetadata {
    metadata_fixture(
        vec![vrf_entry(0x11, 0x22)],
        vec!["77".repeat(32), "88".repeat(32)],
        vec!["99".repeat(32)],
        3,
        9,
        "aa".repeat(32),
        "bb".repeat(32),
    )
}

fn sample_certificate() -> ConsensusCertificate {
    ConsensusCertificate {
        block_hash: BlockId("aa".repeat(32)),
        height: 42,
        round: 7,
        total_power: 10,
        quorum_threshold: 7,
        prevote_power: 8,
        precommit_power: 8,
        commit_power: 8,
        prevotes: Vec::new(),
        precommits: Vec::new(),
        metadata: sample_metadata(),
    }
}

#[test]
fn consensus_witness_roundtrip_preserves_metadata() {
    let certificate = sample_certificate();
    let witness = certificate
        .encode_witness(ProofSystemKind::Mock)
        .expect("encode consensus witness");
    let (_, decoded): (_, ConsensusCertificate) =
        witness.decode().expect("decode consensus witness");
    assert_eq!(decoded.metadata, certificate.metadata);
}

#[test]
fn consensus_public_inputs_include_structured_metadata() {
    let certificate = sample_certificate();
    let inputs = certificate
        .consensus_public_inputs()
        .expect("public inputs");

    assert_eq!(inputs.vrf_outputs.len(), 1);
    assert_eq!(inputs.vrf_proofs.len(), 1);
    assert_eq!(inputs.witness_commitments.len(), 2);
    assert_eq!(inputs.reputation_roots.len(), 1);
    assert_eq!(inputs.epoch, sample_metadata().epoch);
    assert_eq!(inputs.slot, sample_metadata().slot);
    assert_eq!(
        inputs.quorum_bitmap_root,
        hex_to_array(&sample_metadata().quorum_bitmap_root)
    );

    let mut buffer = [0u8; 32];
    buffer.copy_from_slice(&hex::decode(&certificate.metadata.vrf_entries[0].randomness).unwrap());
    assert_eq!(inputs.vrf_outputs[0], buffer);
}

#[test]
fn consensus_metadata_json_roundtrip_preserves_poseidon() {
    let metadata = sample_metadata();
    let json = serde_json::to_string(&metadata).expect("serialize metadata");
    let value: Value = serde_json::from_str(&json).expect("parse metadata json");
    let entries = value
        .get("vrf_entries")
        .and_then(Value::as_array)
        .expect("vrf entries array");
    assert_eq!(entries.len(), 1);
    let poseidon = entries[0]
        .get("poseidon")
        .and_then(Value::as_object)
        .expect("poseidon object");
    let expected = &metadata.vrf_entries[0].poseidon;
    assert_eq!(
        poseidon.get("digest").unwrap(),
        &Value::String(expected.digest.clone())
    );
    assert_eq!(
        poseidon.get("last_block_header").unwrap(),
        &Value::String(expected.last_block_header.clone())
    );
    assert_eq!(
        poseidon.get("epoch").unwrap(),
        &Value::String(expected.epoch.clone())
    );
    assert_eq!(
        poseidon.get("tier_seed").unwrap(),
        &Value::String(expected.tier_seed.clone())
    );

    let roundtrip: ConsensusProofMetadata =
        serde_json::from_str(&json).expect("roundtrip metadata");
    assert_eq!(roundtrip, metadata);
}

#[test]
fn consensus_public_inputs_match_expected_bindings() {
    let certificate = sample_certificate();
    let inputs = certificate
        .consensus_public_inputs()
        .expect("public inputs");

    let block_hash = hex_to_array(&certificate.block_hash.0);
    let (vrf_outputs, vrf_proofs): (Vec<[u8; 32]>, Vec<Vec<u8>>) = certificate
        .metadata
        .vrf_entries
        .iter()
        .map(|entry| {
            let mut randomness = [0u8; 32];
            randomness.copy_from_slice(&hex::decode(&entry.randomness).expect("decode randomness"));
            let proof = hex::decode(&entry.proof).expect("decode proof");
            (randomness, proof)
        })
        .unzip();
    let witness_commitments: Vec<[u8; 32]> = certificate
        .metadata
        .witness_commitments
        .iter()
        .map(|value| hex_to_array(value))
        .collect();
    let reputation_roots: Vec<[u8; 32]> = certificate
        .metadata
        .reputation_roots
        .iter()
        .map(|value| hex_to_array(value))
        .collect();

    let bindings = compute_consensus_bindings(
        &block_hash,
        &vrf_outputs,
        &vrf_proofs,
        &witness_commitments,
        &reputation_roots,
        &inputs.quorum_bitmap_root,
        &inputs.quorum_signature_root,
    );

    assert_eq!(inputs.vrf_output_binding, bindings.vrf_output);
    assert_eq!(inputs.vrf_proof_binding, bindings.vrf_proof);
    assert_eq!(
        inputs.witness_commitment_binding,
        bindings.witness_commitment
    );
    assert_eq!(inputs.reputation_root_binding, bindings.reputation_root);
    assert_eq!(inputs.quorum_bitmap_binding, bindings.quorum_bitmap);
    assert_eq!(inputs.quorum_signature_binding, bindings.quorum_signature);
}

fn hex_to_array(value: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&hex::decode(value).unwrap());
    bytes
}
