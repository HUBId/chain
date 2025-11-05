use serde_json::Value;

use crate::errors::{ChainError, ChainResult};

pub(crate) fn encode_canonical_json(public_inputs: &Value) -> ChainResult<Vec<u8>> {
    plonky3_backend::encode_canonical_json(public_inputs).map_err(|err| {
        ChainError::Crypto(format!(
            "failed to encode Plonky3 public inputs canonically: {err}"
        ))
    })
}

pub(crate) fn compute_commitment_and_inputs(
    public_inputs: &Value,
) -> ChainResult<(String, [u8; 32], Vec<u8>)> {
    plonky3_backend::compute_commitment_and_inputs(public_inputs).map_err(|err| {
        ChainError::Crypto(format!(
            "failed to encode Plonky3 public inputs for commitment: {err}"
        ))
    })
}

pub fn compute_commitment(public_inputs: &Value) -> ChainResult<String> {
    compute_commitment_and_inputs(public_inputs).map(|(commitment, _, _)| commitment)
}
