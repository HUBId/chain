#![cfg(feature = "backend-stwo")]

use crate::stwo::air::AirDefinition;
use crate::stwo::circuit::{ExecutionTrace, StarkCircuit};
use crate::stwo::circuit::transaction::TransactionCircuit;
use crate::stwo::params::{FieldElement, StarkParameters};
use crate::stwo::proof::{
    CommitmentSchemeProofData, FriProof, ProofKind, ProofPayload, StarkProof,
};
use crate::stwo::verifier::NodeVerifier;

const VALID_PROOF_JSON: &str = include_str!("vectors/valid_proof.json");

fn should_run_fixture() -> bool {
    std::env::var_os("STWO_RUN_VALID_FRI_FIXTURE").is_some()
}

fn decode_public_inputs(parameters: &StarkParameters, inputs: &[String]) -> Vec<FieldElement> {
    inputs
        .iter()
        .map(|input| {
            let bytes = hex::decode(input).unwrap_or_else(|_| input.as_bytes().to_vec());
            parameters.element_from_bytes(&bytes)
        })
        .collect()
}

fn load_fixture_proof() -> StarkProof {
    serde_json::from_str(VALID_PROOF_JSON).expect("deserialize STARK proof fixture")
}

fn prepare_transaction_components(
    proof: &StarkProof,
) -> (Vec<FieldElement>, ExecutionTrace, AirDefinition) {
    let parameters = StarkParameters::blueprint_default();
    let public_inputs = decode_public_inputs(&parameters, &proof.public_inputs);
    let witness = match &proof.payload {
        ProofPayload::Transaction(witness) => witness.clone(),
        _ => panic!("fixture should embed a transaction witness"),
    };

    let circuit = TransactionCircuit::new(witness);
    circuit
        .evaluate_constraints()
        .expect("transaction constraints should be satisfied");
    let trace = circuit
        .generate_trace(&parameters)
        .expect("generate execution trace");
    circuit
        .verify_air(&parameters, &trace)
        .expect("air verification should succeed");
    let air = circuit
        .define_air(&parameters, &trace)
        .expect("define air from trace");

    (public_inputs, trace, air)
}

#[test]
fn valid_proof_fixture_passes_fri_verification() {
    if !should_run_fixture() {
        // The fixture is large and only needed for explicit verification runs.
        // Skip the expensive reconstruction unless explicitly requested.
        return;
    }
    let proof = load_fixture_proof();

    assert_eq!(
        proof.kind,
        ProofKind::Transaction,
        "fixture should contain a transaction proof",
    );

    let parameters = StarkParameters::blueprint_default();
    let public_inputs = decode_public_inputs(&parameters, &proof.public_inputs);
    let hasher = parameters.poseidon_hasher();
    let expected_commitment = hasher.hash(&public_inputs).to_hex();
    assert_eq!(
        expected_commitment, proof.commitment,
        "commitment should match inputs"
    );

    let (_inputs, trace, air) = prepare_transaction_components(&proof);

    let verifier = NodeVerifier::new();
    verifier
        .check_fri(&proof, &public_inputs, &trace, &air)
        .expect("fri verification should succeed");
}

#[test]
fn corrupted_fri_commitment_is_rejected() {
    if !should_run_fixture() {
        return;
    }

    let baseline = load_fixture_proof();
    let (public_inputs, trace, air) = prepare_transaction_components(&baseline);
    let mut corrupted = baseline.clone();

    let mut commitment_proof = corrupted
        .commitment_proof
        .to_official()
        .expect("fixture should contain a commitment proof");
    let mut fri_proof = corrupted
        .fri_proof
        .to_official()
        .expect("fixture should contain a fri proof");

    if let Some(layer) = fri_proof.inner_layers.get_mut(0) {
        layer.commitment.0[0] ^= 1;
        let commitment_layer = commitment_proof
            .fri_proof
            .inner_layers
            .get_mut(0)
            .expect("commitment proof should mirror fri layers");
        commitment_layer.commitment = layer.commitment;
    } else {
        fri_proof.first_layer.commitment.0[0] ^= 1;
        commitment_proof.fri_proof.first_layer.commitment = fri_proof.first_layer.commitment;
    }

    corrupted.commitment_proof = CommitmentSchemeProofData::from_official(&commitment_proof);
    corrupted.fri_proof = FriProof::from_official(&fri_proof);

    let verifier = NodeVerifier::new();
    let err = verifier
        .check_fri(&corrupted, &public_inputs, &trace, &air)
        .expect_err("fri verification should fail after commitment corruption");
    assert!(
        err.to_string().contains("fri verification failed"),
        "unexpected error message: {err}"
    );
}

#[test]
fn corrupted_merkle_decommitment_is_rejected() {
    if !should_run_fixture() {
        return;
    }

    let baseline = load_fixture_proof();
    let (public_inputs, trace, air) = prepare_transaction_components(&baseline);
    let mut corrupted = baseline.clone();

    let mut commitment_proof = corrupted
        .commitment_proof
        .to_official()
        .expect("fixture should contain a commitment proof");
    let _fri_proof = corrupted
        .fri_proof
        .to_official()
        .expect("fixture should contain a fri proof");
    let first_tree = commitment_proof
        .decommitments
        .get_mut(0)
        .expect("fixture should contain at least one decommitment");
    let first_hash = first_tree
        .hash_witness
        .get_mut(0)
        .expect("decommitment should contain witness hashes");
    first_hash.0[0] ^= 1;

    corrupted.commitment_proof = CommitmentSchemeProofData::from_official(&commitment_proof);

    let verifier = NodeVerifier::new();
    let err = verifier
        .check_fri(&corrupted, &public_inputs, &trace, &air)
        .expect_err("merkle verification should fail after witness corruption");
    assert!(
        err.to_string().contains("Root mismatch"),
        "unexpected error message: {err}"
    );
}

#[test]
fn invalid_proof_of_work_is_rejected() {
    if !should_run_fixture() {
        return;
    }

    let baseline = load_fixture_proof();
    let (public_inputs, trace, air) = prepare_transaction_components(&baseline);
    let mut corrupted = baseline.clone();

    let mut commitment_proof = corrupted
        .commitment_proof
        .to_official()
        .expect("fixture should contain a commitment proof");
    let _fri_proof = corrupted
        .fri_proof
        .to_official()
        .expect("fixture should contain a fri proof");
    assert_ne!(commitment_proof.proof_of_work, 0, "fixture should include non-zero pow");
    commitment_proof.proof_of_work = 0;
    corrupted.commitment_proof = CommitmentSchemeProofData::from_official(&commitment_proof);

    let verifier = NodeVerifier::new();
    let err = verifier
        .check_fri(&corrupted, &public_inputs, &trace, &air)
        .expect_err("proof of work verification should fail after corruption");
    assert!(
        err
            .to_string()
            .contains("proof of work verification failed"),
        "unexpected error message: {err}"
    );
}
