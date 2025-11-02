use prover_stwo_backend::circuits::identity::{IdentityGenesis, IdentityWitness};
use prover_stwo_backend::circuits::{CircuitTrace, CircuitWitness};
use prover_stwo_backend::core::vcs::blake2_hash::Blake2sHasher;
use prover_stwo_backend::params::FieldElement;
use prover_stwo_backend::utils::poseidon;

fn rehash_trace(trace: &CircuitTrace) -> ([u8; 32], [u8; 32]) {
    let mut trace_bytes = Vec::new();
    if let Some(genesis) = trace.trace_data.get("genesis") {
        if let Some(wallet) = genesis.get("wallet_address").and_then(|v| v.as_str()) {
            trace_bytes.extend(wallet.as_bytes());
        }
        if let Some(block) = genesis.get("genesis_block").and_then(|v| v.as_str()) {
            trace_bytes.extend(block.as_bytes());
        }
    }
    if let Some(public_key) = trace
        .trace_data
        .get("wallet_public_key")
        .and_then(|v| v.as_str())
    {
        trace_bytes.extend(public_key.as_bytes());
    }
    if let Some(signature) = trace
        .trace_data
        .get("vote_signature")
        .and_then(|v| v.as_str())
    {
        trace_bytes.extend(signature.as_bytes());
    }

    let trace_commitment = Blake2sHasher::hash(&trace_bytes).0;

    let poseidon_inputs = vec![
        FieldElement::from_bytes(
            trace
                .trace_data
                .get("genesis")
                .and_then(|value| value.get("wallet_address"))
                .and_then(|value| value.as_str())
                .unwrap()
                .as_bytes(),
        ),
        FieldElement::from_bytes(
            trace
                .trace_data
                .get("wallet_public_key")
                .and_then(|value| value.as_str())
                .unwrap()
                .as_bytes(),
        ),
    ];
    let constraint_commitment = poseidon::hash_elements(&poseidon_inputs);
    (trace_commitment, constraint_commitment)
}

#[test]
fn identity_witness_trace_commits_public_inputs() {
    let witness = IdentityWitness::new(
        IdentityGenesis {
            wallet_address: "wallet-123".to_string(),
            genesis_block: "block-abc".to_string(),
        },
        "wallet-pk".to_string(),
        "vote-sig".to_string(),
    );

    assert_eq!(witness.label(), "identity");

    let trace = witness.trace();
    let (rehash_trace_commitment, rehash_constraint_commitment) = rehash_trace(&trace);

    assert_eq!(trace.trace_commitment, rehash_trace_commitment);
    assert_eq!(trace.constraint_commitment, rehash_constraint_commitment);

    let inputs = witness.public_inputs();
    assert_eq!(inputs["wallet"], "wallet-123");
    assert_eq!(inputs["genesis"], "block-abc");
    assert_eq!(trace.trace_data["wallet_public_key"], "wallet-pk");
}

#[test]
fn witness_json_serialisation_is_stable() {
    let witness = IdentityWitness::new(
        IdentityGenesis {
            wallet_address: "wallet-789".to_string(),
            genesis_block: "block-def".to_string(),
        },
        "pub-key".to_string(),
        "sig".to_string(),
    );

    let encoded = witness.to_json();
    assert_eq!(encoded["genesis"]["wallet_address"], "wallet-789");
    assert_eq!(encoded["wallet_public_key"], "pub-key");
    assert_eq!(encoded["vote_signature"], "sig");
}
