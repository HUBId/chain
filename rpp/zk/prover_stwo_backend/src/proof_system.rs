use crate::errors::ChainResult;
use crate::types::ChainProof;
use crate::proof_backend::ProofSystemKind;

/// Minimal trait capturing the verification hooks exposed by the blueprint
/// proof backends.  Downstream crates rely on the interface to remain stable
/// regardless of the active proving system.
pub trait ProofVerifier {
    /// Identify the underlying proof system implementation.
    fn system(&self) -> ProofSystemKind;

    /// Verify a transaction proof artifact.
    fn verify_transaction(&self, proof: &ChainProof) -> ChainResult<()>;

    /// Verify an identity proof artifact.
    fn verify_identity(&self, proof: &ChainProof) -> ChainResult<()>;

    /// Verify a state transition proof artifact.
    fn verify_state(&self, proof: &ChainProof) -> ChainResult<()>;

    /// Verify a pruning proof artifact.
    fn verify_pruning(&self, proof: &ChainProof) -> ChainResult<()>;

    /// Verify a recursive aggregation proof artifact.
    fn verify_recursive(&self, proof: &ChainProof) -> ChainResult<()>;

    /// Verify an uptime proof artifact.
    fn verify_uptime(&self, proof: &ChainProof) -> ChainResult<()>;

    /// Verify a consensus proof artifact.
    fn verify_consensus(&self, proof: &ChainProof) -> ChainResult<()>;
}
