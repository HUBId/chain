use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use plonky3_backend::{
    encode_consensus_public_inputs, prove_consensus, validate_consensus_public_inputs,
    verify_consensus, ConsensusCircuit, ConsensusProof, ConsensusVrfEntry,
    ConsensusVrfPoseidonInput, ConsensusWitness, ProverContext, ProvingKey, VerifierContext,
    VerifyingKey, VotePower, VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH,
};
use serde::Deserialize;
use serde_json::json;
use serde_json::Value;
use std::fs;

fn sample_vote(label: &str, weight: u64) -> VotePower {
    VotePower {
        voter: label.to_string(),
        weight,
    }
}

#[derive(Deserialize)]
struct FixtureKey {
    value: String,
}

#[derive(Deserialize)]
struct FixtureDoc {
    verifying_key: FixtureKey,
    proving_key: FixtureKey,
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
        vrf_entries: vec![ConsensusVrfEntry {
            randomness: "55".repeat(32),
            pre_output: "66".repeat(VRF_PREOUTPUT_LENGTH),
            proof: "77".repeat(VRF_PROOF_LENGTH),
            public_key: "88".repeat(32),
            poseidon: ConsensusVrfPoseidonInput {
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

fn sample_keys() -> (VerifyingKey, ProvingKey) {
    let contents =
        fs::read_to_string("config/plonky3/setup/consensus.json").expect("read consensus fixture");
    let fixture: FixtureDoc = serde_json::from_str(&contents).expect("parse consensus fixture");
    let verifying_bytes = BASE64_STANDARD
        .decode(fixture.verifying_key.value.as_bytes())
        .expect("decode verifying key");
    let verifying_key =
        VerifyingKey::from_bytes(verifying_bytes, "consensus").expect("verifying key constructs");
    let verifying_metadata = verifying_key.metadata();
    let proving_bytes = BASE64_STANDARD
        .decode(fixture.proving_key.value.as_bytes())
        .expect("decode proving key");
    let proving_key = ProvingKey::from_bytes(proving_bytes, "consensus", Some(&verifying_metadata))
        .expect("proving key constructs");
    (verifying_key, proving_key)
}

fn sample_contexts() -> (ProverContext, VerifierContext) {
    let (verifying_key, proving_key) = sample_keys();
    let prover = ProverContext::new("consensus", verifying_key.clone(), proving_key, 64, false)
        .expect("prover context builds");
    let verifier = prover.verifier();
    (prover, verifier)
}

fn prove_sample_witness() -> (ConsensusProof, VerifierContext) {
    let (prover, verifier) = sample_contexts();
    let witness = sample_witness();
    let circuit = ConsensusCircuit::new(witness).expect("consensus circuit");
    let proof = prove_consensus(&prover, &circuit).expect("consensus proving succeeds");
    (proof, verifier)
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
fn consensus_verification_rejects_tampered_vrf_randomness() {
    let (proof, verifier) = prove_sample_witness();
    verify_consensus(&verifier, &proof).expect("baseline verification succeeds");

    let mut tampered = proof.clone();
    if let Value::Object(ref mut root) = tampered.public_inputs {
        if let Some(Value::Array(ref mut entries)) = root.get_mut("vrf_entries") {
            if let Some(Value::Object(entry)) = entries.first_mut() {
                if let Some(Value::Array(randomness)) = entry.get_mut("randomness") {
                    randomness[0] = json!(255u64);
                }
            }
        }
    }

    let err = verify_consensus(&verifier, &tampered).expect_err("tampered VRF must fail");
    assert!(matches!(
        err,
        plonky3_backend::BackendError::InvalidPublicInputs { .. }
    ));
}

#[test]
fn consensus_verification_rejects_tampered_quorum_digest() {
    let (proof, verifier) = prove_sample_witness();
    verify_consensus(&verifier, &proof).expect("baseline verification succeeds");

    let mut tampered = proof.clone();
    if let Value::Object(ref mut root) = tampered.public_inputs {
        if let Some(Value::Object(bindings)) = root.get_mut("bindings") {
            bindings.insert("quorum_bitmap".into(), json!("deadbeef"));
        }
    }

    let err = verify_consensus(&verifier, &tampered).expect_err("tampered quorum must fail");
    assert!(matches!(
        err,
        plonky3_backend::BackendError::InvalidPublicInputs { .. }
    ));
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
fn consensus_rejects_poseidon_epoch_mismatch() {
    let mut witness = sample_witness();
    witness.vrf_entries[0].poseidon.epoch = "999".into();
    assert!(ConsensusCircuit::new(witness).is_err());
}

#[test]
fn consensus_rejects_poseidon_last_block_header_mismatch() {
    let mut witness = sample_witness();
    witness.vrf_entries[0].poseidon.last_block_header = "aa".repeat(32);
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
