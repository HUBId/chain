#![cfg(feature = "backend-rpp-stark")]

use hex::FromHex;
use std::convert::TryFrom;
use std::fs;
use std::path::{Path, PathBuf};

use prover_backend_interface::TxPublicInputs;
use rpp_chain::zk::rpp_adapter::{compute_public_digest, encode_public_inputs, Digest32, Felt};

const VECTORS_DIR: &str = "vendor/rpp-stark/vectors/stwo/mini";

fn vector_path(name: &str) -> PathBuf {
    Path::new(VECTORS_DIR).join(name)
}

fn load_hex_bytes(name: &str) -> Vec<u8> {
    let contents = fs::read_to_string(vector_path(name)).expect("read hex vector");
    Vec::from_hex(contents.trim()).expect("valid hex payload")
}

fn load_hex_string(name: &str) -> String {
    fs::read_to_string(vector_path(name))
        .expect("read digest vector")
        .trim()
        .to_lowercase()
}

fn sample_public_inputs() -> TxPublicInputs {
    TxPublicInputs {
        utxo_root: [0u8; 32],
        transaction_commitment: {
            let mut commitment = [0u8; 32];
            commitment[0] = 0x03;
            commitment
        },
    }
}

#[test]
fn public_inputs_bytes_match_golden_vector() {
    let expected = load_hex_bytes("public_inputs.bin");
    let encoded = encode_public_inputs(&sample_public_inputs());
    assert_eq!(
        encoded, expected,
        "encoded public inputs mismatch golden vector"
    );
}

#[test]
fn public_digest_matches_header_hex() {
    let bytes = load_hex_bytes("public_inputs.bin");
    let expected_digest = load_hex_string("public_digest.hex");
    let digest = compute_public_digest(&bytes);
    assert_eq!(digest.to_hex(), expected_digest, "public digest mismatch");
}

#[test]
fn digest_roundtrip_hex_bytes_ok() {
    let expected_digest = load_hex_string("public_digest.hex");
    let digest = Digest32::from_hex(&expected_digest).expect("valid digest hex");
    assert_eq!(digest.to_hex(), expected_digest);

    let bytes: [u8; 32] = digest.into();
    let recovered = Digest32::try_from(bytes.as_slice()).expect("32-byte digest");
    assert_eq!(recovered.to_hex(), expected_digest);
}

#[test]
fn felt_passthrough_type_layout_ok() {
    use core::mem::size_of;

    assert_eq!(
        size_of::<Felt>(),
        size_of::<rpp_stark::felt::Felt>(),
        "Felt wrapper must not add padding"
    );
}
