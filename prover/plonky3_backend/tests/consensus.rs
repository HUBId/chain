use plonky3_backend::{
    encode_consensus_public_inputs, validate_consensus_public_inputs, ConsensusCircuit,
    ConsensusWitness, VotePower, VRF_PROOF_LENGTH,
};
use serde_json::Value;

fn sample_vote(label: &str, weight: u64) -> VotePower {
    VotePower {
        voter: label.to_string(),
        weight,
    }
}

fn sample_witness() -> ConsensusWitness {
    ConsensusWitness {
        block_hash: "11".repeat(32),
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
        vrf_outputs: vec!["55".repeat(32)],
        vrf_proofs: vec!["66".repeat(VRF_PROOF_LENGTH)],
        witness_commitments: vec!["77".repeat(32)],
        reputation_roots: vec!["88".repeat(32)],
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
    validate_consensus_public_inputs(&public_inputs).expect("validate public inputs");
    let decoded = ConsensusCircuit::from_public_inputs_value(&public_inputs)
        .expect("decode circuit from inputs");
    assert_eq!(decoded.witness().round, witness.round);
    assert_eq!(decoded.bindings().quorum_bitmap.len(), 64);
}

#[test]
fn consensus_rejects_invalid_vrf_proof_length() {
    let mut witness = sample_witness();
    witness.vrf_proofs[0].push_str("ff");
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
