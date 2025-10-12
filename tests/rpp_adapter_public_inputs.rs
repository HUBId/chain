#![cfg(feature = "backend-rpp-stark")]

use hex_literal::hex;
use std::convert::TryFrom;
use prover_backend_interface::TxPublicInputs;
use rpp_chain::zk::rpp_adapter::{
    compute_public_digest, encode_public_inputs, Digest32, Felt,
};

const UTXO_ROOT: [u8; 32] = hex!(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
);
const TRANSACTION_COMMITMENT: [u8; 32] = hex!(
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
);
const PUBLIC_INPUTS_BIN: [u8; 64] = hex!(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
);
const PUBLIC_DIGEST_HEX: &str = "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98";

fn sample_public_inputs() -> TxPublicInputs {
    TxPublicInputs {
        utxo_root: UTXO_ROOT,
        transaction_commitment: TRANSACTION_COMMITMENT,
    }
}

#[test]
fn public_inputs_bytes_match_golden_vector() {
    let encoded = encode_public_inputs(&sample_public_inputs());
    assert_eq!(encoded.as_slice(), &PUBLIC_INPUTS_BIN);
}

#[test]
fn public_digest_matches_header_hex() {
    let digest = compute_public_digest(&PUBLIC_INPUTS_BIN);
    assert_eq!(digest.to_string(), PUBLIC_DIGEST_HEX);
}

#[test]
fn digest_roundtrip_hex_bytes_ok() {
    let digest = Digest32::from_hex(PUBLIC_DIGEST_HEX).expect("valid digest hex");
    assert_eq!(digest.to_string(), PUBLIC_DIGEST_HEX);

    let bytes: [u8; 32] = digest.into();
    let recovered = Digest32::try_from(bytes.as_slice()).expect("32-byte digest");
    assert_eq!(recovered.to_string(), PUBLIC_DIGEST_HEX);
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
