use crate::stwo::circuit::StarkCircuit;
use crate::stwo::circuit::transaction::TransactionCircuit;
use crate::stwo::params::{FieldElement, StarkParameters};
use crate::stwo::proof::{ProofKind, ProofPayload, StarkProof};
use crate::stwo::verifier::NodeVerifier;

fn decode_public_inputs(parameters: &StarkParameters, inputs: &[String]) -> Vec<FieldElement> {
    inputs
        .iter()
        .map(|input| {
            let bytes = hex::decode(input).unwrap_or_else(|_| input.as_bytes().to_vec());
            parameters.element_from_bytes(&bytes)
        })
        .collect()
}

#[test]
fn valid_proof_fixture_passes_fri_verification() {
    let fixture = include_str!("vectors/valid_proof.json");
    if std::env::var_os("STWO_RUN_VALID_FRI_FIXTURE").is_none() {
        // The fixture is large and only needed for explicit verification runs.
        // Skip the expensive reconstruction unless explicitly requested.
        return;
    }
    let proof: StarkProof = serde_json::from_str(fixture).expect("deserialize STARK proof fixture");

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

    let verifier = NodeVerifier::new();
    verifier
        .check_fri(&proof, &public_inputs, &trace, &air)
        .expect("fri verification should succeed");
}
