use rpp_chain::errors::ChainResult;
use rpp_chain::storage::Storage;
use rpp_chain::types::{ChainProof, SignedTransaction};

#[cfg(feature = "prover-stwo")]
use rpp_chain::{
    proof_system::ProofProver,
    reputation::Tier,
    stwo::{params::StarkParameters, prover::WalletProver, verifier::NodeVerifier},
};

#[cfg(feature = "backend-rpp-stark")]
use rpp_chain::proof_system::ProofVerifierRegistry;

/// Execute the prover path when the STWO feature is enabled and always verify any
/// provided RPP-STARK proof artifacts. The function returns the generated STWO
/// proof so callers can persist or propagate it further up the stack.
pub fn dispatch_transaction_validation(
    storage: &Storage,
    tx: &SignedTransaction,
    rpp_stark_proof: Option<&ChainProof>,
) -> ChainResult<Option<ChainProof>> {
    let mut stwo_proof = None;

    #[cfg(feature = "prover-stwo")]
    {
        let prover = WalletProver::new(storage)
            .with_parameters(StarkParameters::blueprint_default())
            .with_minimum_tier(Tier::Tl1);
        let witness = prover.derive_transaction_witness(tx)?;
        let proof = prover.prove_transaction(witness)?;
        NodeVerifier::new().verify_transaction(&proof)?;
        stwo_proof = Some(proof);
    }

    #[cfg(feature = "backend-rpp-stark")]
    if let Some(proof) = rpp_stark_proof {
        let registry = ProofVerifierRegistry::with_max_proof_size_bytes(4 * 1024 * 1024)?;
        registry.verify_rpp_stark_with_report(proof, "transaction")?;
    }

    Ok(stwo_proof)
}
