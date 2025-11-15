use crate::proof_backend::{ProofBytes, VerifyingKey};
use prover_backend_interface::{BackendError, BackendResult, IdentityPublicInputs, ProofBackend};

/// Attempt to verify a lifecycle proof against the provided inputs.
///
/// Unsupported backends are treated as a no-op to preserve the previous
/// lifecycle behaviour, where verification failures were ignored for mock
/// implementations.
pub fn identity<B: ProofBackend>(
    backend: &B,
    proof: &ProofBytes,
    inputs: &IdentityPublicInputs,
) -> BackendResult<()> {
    match backend.verify_identity(&VerifyingKey(Vec::new()), proof, inputs) {
        Ok(()) => Ok(()),
        Err(BackendError::Unsupported(_)) => Ok(()),
        Err(other) => Err(other),
    }
}
