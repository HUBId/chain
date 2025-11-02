use plonky3_backend::{
    encode_consensus_public_inputs, validate_consensus_public_inputs, ConsensusCircuit,
    ConsensusVrfPoseidonWitness, ConsensusVrfWitnessEntry, ConsensusWitness, VotePower,
    VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH,
};
use serde_json::Value;

fn sample_vote(label: &str, weight: u64) -> VotePower {
    VotePower {
        voter: label.to_string(),
        weight,
    }
}

fn sample_witness() -> ConsensusWitness {
    let block_hash = "11".repeat(32);
    ConsensusWitness {
        block_hash: block_hash.clone(),
        round: 7,
        epoch: 3,
        slot: 9,
        leader_proposal: "22".repeat(32),
        quorum_threshold: 2,
        pre_votes: vec![sample_vote("validator-a", 2)],
        pre_commits: vec![sample_vote("validator-a", 2)],
        commit_votes: vec![sample_vote("validator-a", 2)],
        quorum_bitmap_root: "33".repeat(32),
        quorum_signature_root: "44".repeat(32),
        vrf_entries: vec![ConsensusVrfWitnessEntry {
            randomness: "55".repeat(32),
            pre_output: "66".repeat(VRF_PREOUTPUT_LENGTH),
            proof: "77".repeat(VRF_PROOF_LENGTH),
            public_key: "88".repeat(32),
            poseidon: ConsensusVrfPoseidonWitness {
                digest: "99".repeat(32),
                last_block_header: block_hash,
                epoch: "3".to_string(),
                tier_seed: "aa".repeat(32),
            },
        }],
        witness_commitments: vec!["bb".repeat(32)],
        reputation_roots: vec!["cc".repeat(32)],
    }
}

#[test]
fn consensus_public_inputs_round_trip() {
    let witness = sample_witness();
    let circuit = ConsensusCircuit::new(witness.clone()).expect("valid witness");
    let public_inputs = circuit.public_inputs_value().expect("encode public inputs");
    assert_eq!(
        public_inputs
            .get("block_height")
            .and_then(Value::as_u64)
            .expect("block height"),
        witness.round,
    );
    let vrf_entries = public_inputs
        .get("vrf_entries")
        .and_then(Value::as_array)
        .expect("vrf entries array");
    assert_eq!(vrf_entries.len(), witness.vrf_entries.len());
    let randomness = vrf_entries[0]
        .get("randomness")
        .and_then(Value::as_array)
        .expect("randomness array");
    assert_eq!(randomness.len(), 32);
    let proof_bytes = vrf_entries[0]
        .get("proof")
        .and_then(Value::as_array)
        .expect("proof array");
    assert_eq!(proof_bytes.len(), VRF_PROOF_LENGTH);
    validate_consensus_public_inputs(&public_inputs).expect("validate public inputs");
    let decoded = ConsensusCircuit::from_public_inputs_value(&public_inputs)
        .expect("decode circuit from inputs");
    assert_eq!(decoded.witness().round, witness.round);
    assert_eq!(decoded.vrf_entries().len(), witness.vrf_entries.len());
    assert_eq!(decoded.bindings().quorum_bitmap.len(), 64);
}

#[test]
fn consensus_rejects_invalid_vrf_proof_length() {
    let mut witness = sample_witness();
    witness.vrf_entries[0].proof.push_str("ff");
    assert!(ConsensusCircuit::new(witness).is_err());
}

#[test]
fn consensus_rejects_invalid_poseidon_digest_length() {
    let mut witness = sample_witness();
    witness.vrf_entries[0].poseidon.digest = "dd".repeat(31);
    assert!(ConsensusCircuit::new(witness).is_err());
}

#[test]
fn consensus_rejects_invalid_poseidon_epoch() {
    let mut witness = sample_witness();
    witness.vrf_entries[0].poseidon.epoch = "".into();
    assert!(ConsensusCircuit::new(witness).is_err());
}

#[test]
fn consensus_rejects_binding_tampering() {
    let witness = sample_witness();
    let mut public_inputs = encode_consensus_public_inputs(witness).expect("encode inputs");
    let bindings = public_inputs
        .get_mut("bindings")
        .and_then(Value::as_object_mut)
        .expect("bindings object");
    bindings.insert("quorum_bitmap".into(), Value::String("99".repeat(32)));
    assert!(validate_consensus_public_inputs(&public_inputs).is_err());
}
