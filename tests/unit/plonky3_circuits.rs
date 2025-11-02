#![cfg(feature = "backend-plonky3")]

use rpp_chain::plonky3::circuit::{identity::IdentityWitness, Plonky3CircuitWitness};
use rpp_chain::types::IdentityGenesis;

fn sample_genesis() -> IdentityGenesis {
    IdentityGenesis {
        wallet_address: "wallet-alpha".to_string(),
        genesis_block: "block-0001".to_string(),
    }
}

#[test]
fn identity_witness_reports_circuit_name() {
    let genesis = sample_genesis();
    let witness = IdentityWitness::new(&genesis);
    assert_eq!(witness.circuit(), "identity");
}

#[test]
fn identity_public_inputs_embed_genesis_payload() {
    let genesis = sample_genesis();
    let witness = IdentityWitness::new(&genesis);
    let inputs = witness.public_inputs().expect("public inputs encode");
    let object = inputs.as_object().expect("object inputs");
    let payload = object
        .get("witness")
        .and_then(|value| value.as_object())
        .expect("witness payload");
    assert_eq!(
        payload
            .get("genesis")
            .and_then(|value| value.get("wallet_address"))
            .and_then(|value| value.as_str()),
        Some("wallet-alpha"),
    );
    assert_eq!(
        payload
            .get("genesis")
            .and_then(|value| value.get("genesis_block"))
            .and_then(|value| value.as_str()),
        Some("block-0001"),
    );
    assert!(
        object.get("block_height").is_none(),
        "block height metadata remains optional"
    );
}

#[test]
fn identity_witness_serialisation_is_stable() {
    let genesis = sample_genesis();
    let witness = IdentityWitness::new(&genesis);
    let encoded = serde_json::to_string(&witness).expect("encode witness");
    assert!(encoded.contains("wallet-alpha"));
    assert!(encoded.contains("block-0001"));
    let roundtrip: IdentityWitness = serde_json::from_str(&encoded).expect("decode witness");
    assert_eq!(roundtrip.genesis.wallet_address, "wallet-alpha");
    assert_eq!(roundtrip.genesis.genesis_block, "block-0001");
}
