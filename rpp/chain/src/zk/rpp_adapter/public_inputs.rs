#![cfg(feature = "backend-rpp-stark")]

use prover_backend_interface::TxPublicInputs;

use super::digest::Digest32;
use super::hash::RppStarkHasher;

const PUBLIC_INPUT_VERSION_V1: u8 = 1;
const EXECUTION_KIND_CODE: u8 = 0x00;
const TRACE_LENGTH: u32 = 128;
const TRACE_WIDTH: u32 = 1;
const BODY_BYTES: usize = 8;
const PI_DIGEST_PREFIX: &[u8; 9] = b"RPP-PI-V1";

/// Encodes transaction public inputs into the canonical byte representation
/// expected by the `rpp-stark` backend.
#[must_use]
pub fn encode_public_inputs(inputs: &TxPublicInputs) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(1 + 32 + 4 + 4 + 4 + BODY_BYTES);
    bytes.push(PUBLIC_INPUT_VERSION_V1);
    bytes.extend_from_slice(&inputs.utxo_root);
    bytes.extend_from_slice(&TRACE_LENGTH.to_le_bytes());
    bytes.extend_from_slice(&TRACE_WIDTH.to_le_bytes());
    bytes.extend_from_slice(&(BODY_BYTES as u32).to_le_bytes());
    bytes.extend_from_slice(&inputs.transaction_commitment[..BODY_BYTES]);
    bytes
}

/// Computes the public digest over the encoded public input bytes.
#[inline]
#[must_use]
pub fn compute_public_digest(bytes: &[u8]) -> Digest32 {
    let mut hasher = RppStarkHasher::new();
    hasher.update(PI_DIGEST_PREFIX);
    hasher.update(&[EXECUTION_KIND_CODE]);
    hasher.update(bytes);
    hasher.finalize()
}
