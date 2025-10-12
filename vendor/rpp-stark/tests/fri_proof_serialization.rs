use insta::assert_snapshot;
use rpp_stark::config::PROFILE_STANDARD_CONFIG;
use rpp_stark::field::FieldElement;
use rpp_stark::fri::{FriProof, FriSecurityLevel};
use rpp_stark::proof::params::canonical_stark_params;

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", byte);
    }
    out
}

#[test]
fn fri_proof_serialization_snapshot() {
    let evaluations: Vec<FieldElement> = (0..128).map(|i| FieldElement(i as u64 + 1)).collect();
    let seed = [1u8; 32];

    let params = canonical_stark_params(&PROFILE_STANDARD_CONFIG);
    let proof =
        FriProof::prove_with_params(FriSecurityLevel::Standard, seed, &evaluations, &params)
            .expect("proof");
    let bytes = proof.to_bytes().expect("serialize");
    assert_snapshot!("fri_proof_v1_bytes", hex_bytes(&bytes));

    let decoded = FriProof::from_bytes(&bytes).expect("deserialize");
    assert_eq!(proof, decoded);
}
