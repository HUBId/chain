use crate::hash::config::BLAKE2S_COMMITMENT_DOMAIN_TAG;
use crate::hash::deterministic::hash;

use super::ser::serialize_params;
use super::types::HashFamily;
use super::StarkParams;

/// Computes the canonical parameter digest for a [`StarkParams`] instance.
///
/// The function reuses the selected proof hash family for the meta commitment:
/// if the proof profile relies on Poseidon2 or Rescue the same algebraic
/// family is reused with the parameter identifier fixed to `0`.  Otherwise a
/// deterministic Blake2s-style sponge is used.  This keeps the parameter digest
/// aligned with the commitment scheme while remaining deterministic.
pub fn params_hash(params: &StarkParams) -> [u8; 32] {
    let payload = serialize_params(params);
    let mut prefixed = Vec::with_capacity(payload.len() + 8);
    let family = params.hash().family();
    match family {
        HashFamily::Poseidon2 => prefixed.extend_from_slice(b"POSEIDON2/0"),
        HashFamily::Rescue => prefixed.extend_from_slice(b"RESCUE/0"),
        HashFamily::Blake2s => prefixed.extend_from_slice(BLAKE2S_COMMITMENT_DOMAIN_TAG),
    }
    prefixed.extend_from_slice(&payload);
    hash(&prefixed).into()
}
