#![cfg(feature = "backend-rpp-stark")]

use prover_backend_interface::TxPublicInputs;

use super::digest::Digest32;
use super::hash::hash_bytes;

/// Encodes transaction public inputs into the canonical byte representation
/// expected by the `rpp-stark` backend.
#[must_use]
pub fn encode_public_inputs(inputs: &TxPublicInputs) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&inputs.utxo_root);
    bytes.extend_from_slice(&inputs.transaction_commitment);
    bytes
}

/// Computes the public digest over the encoded public input bytes.
#[inline]
#[must_use]
pub fn compute_public_digest(bytes: &[u8]) -> Digest32 {
    hash_bytes(bytes)
}
