use crate::consensus::ConsensusCertificate;
use crate::errors::{ChainError, ChainResult};
use crate::rpp::{GlobalStateCommitments, ProofSystemKind};
use crate::types::{
    BlockProofBundle, ChainProof, IdentityDeclaration, IdentityGenesis, PruningProof,
    SignedTransaction, UptimeClaim,
};

#[cfg(feature = "backend-plonky3")]
use crate::plonky3::verifier::Plonky3Verifier;
use crate::stwo::aggregation::StateCommitmentSnapshot;
use crate::stwo::verifier::NodeVerifier;

/// High-level abstraction for wallet-side proof generation that any backend must satisfy.
pub trait ProofProver {
    type IdentityWitness;
    type TransactionWitness;
    type StateWitness;
    type PruningWitness;
    type RecursiveWitness;
    type UptimeWitness;
    type ConsensusWitness;

    /// Identify the underlying proof system implementation.
    fn system(&self) -> ProofSystemKind;

    /// Construct the witness for an identity declaration proof.
    fn build_identity_witness(
        &self,
        genesis: &IdentityGenesis,
    ) -> ChainResult<Self::IdentityWitness>;

    /// Construct the witness for a signed transaction.
    fn build_transaction_witness(
        &self,
        tx: &SignedTransaction,
    ) -> ChainResult<Self::TransactionWitness>;

    /// Construct the witness for a batched state transition.
    fn build_state_witness(
        &self,
        prev_state_root: &str,
        new_state_root: &str,
        identities: &[IdentityDeclaration],
        transactions: &[SignedTransaction],
    ) -> ChainResult<Self::StateWitness>;

    /// Construct the pruning witness linking prior and current state roots.
    fn build_pruning_witness(
        &self,
        previous_identities: &[IdentityDeclaration],
        previous_txs: &[SignedTransaction],
        pruning: &PruningProof,
        removed: Vec<String>,
    ) -> ChainResult<Self::PruningWitness>;

    /// Construct the recursive witness aggregating all proof commitments.
    fn build_recursive_witness(
        &self,
        previous_recursive: Option<&ChainProof>,
        identity_proofs: &[ChainProof],
        tx_proofs: &[ChainProof],
        uptime_proofs: &[ChainProof],
        consensus_proofs: &[ChainProof],
        state_commitments: &GlobalStateCommitments,
        state_proof: &ChainProof,
        pruning_proof: &ChainProof,
        block_height: u64,
    ) -> ChainResult<Self::RecursiveWitness>;

    /// Construct the witness for an uptime proof.
    fn build_uptime_witness(&self, claim: &UptimeClaim) -> ChainResult<Self::UptimeWitness>;

    /// Construct the witness capturing consensus aggregation for the given block hash.
    fn build_consensus_witness(
        &self,
        block_hash: &str,
        certificate: &ConsensusCertificate,
    ) -> ChainResult<Self::ConsensusWitness>;

    /// Produce a proof attesting to transaction validity.
    fn prove_transaction(&self, witness: Self::TransactionWitness) -> ChainResult<ChainProof>;

    /// Produce a proof validating an identity genesis declaration.
    fn prove_identity(&self, witness: Self::IdentityWitness) -> ChainResult<ChainProof>;

    /// Produce a state transition proof for a batch of identities and transactions.
    fn prove_state_transition(&self, witness: Self::StateWitness) -> ChainResult<ChainProof>;

    /// Prove correctness of pruning decisions relative to prior blocks.
    fn prove_pruning(&self, witness: Self::PruningWitness) -> ChainResult<ChainProof>;

    /// Aggregate individual proofs recursively to extend the block chain.
    fn prove_recursive(&self, witness: Self::RecursiveWitness) -> ChainResult<ChainProof>;

    /// Produce a proof attesting to node uptime within the declared window.
    fn prove_uptime(&self, witness: Self::UptimeWitness) -> ChainResult<ChainProof>;

    /// Produce a proof validating consensus quorum aggregation for the block proposal.
    fn prove_consensus(&self, witness: Self::ConsensusWitness) -> ChainResult<ChainProof>;
}

/// Abstraction for node-side verification of proof artifacts.
pub trait ProofVerifier {
    /// Identify the proof system this verifier handles.
    fn system(&self) -> ProofSystemKind;

    fn verify_transaction(&self, proof: &ChainProof) -> ChainResult<()>;
    fn verify_identity(&self, proof: &ChainProof) -> ChainResult<()>;
    fn verify_state(&self, proof: &ChainProof) -> ChainResult<()>;
    fn verify_pruning(&self, proof: &ChainProof) -> ChainResult<()>;
    fn verify_recursive(&self, proof: &ChainProof) -> ChainResult<()>;
    fn verify_uptime(&self, proof: &ChainProof) -> ChainResult<()>;
    fn verify_consensus(&self, proof: &ChainProof) -> ChainResult<()>;
}

/// Maintains verifier instances for all supported proof backends and provides
/// ergonomic dispatch helpers for consumers that only work with the unified
/// [`ChainProof`] abstraction.
#[derive(Clone)]
pub struct ProofVerifierRegistry {
    stwo: NodeVerifier,
    #[cfg(feature = "backend-plonky3")]
    plonky3: Plonky3Verifier,
}

impl Default for ProofVerifierRegistry {
    fn default() -> Self {
        Self {
            stwo: NodeVerifier::new(),
            #[cfg(feature = "backend-plonky3")]
            plonky3: Plonky3Verifier::default(),
        }
    }
}

impl ProofVerifierRegistry {
    /// Construct a new registry with default verifier instances for each
    /// backend.
    pub fn new() -> Self {
        Self::default()
    }

    fn system_verifier(&self, system: ProofSystemKind) -> ChainResult<&dyn ProofVerifier> {
        match system {
            ProofSystemKind::Stwo => Ok(&self.stwo),
            #[cfg(feature = "backend-plonky3")]
            ProofSystemKind::Plonky3 => Ok(&self.plonky3),
            other => Err(ChainError::Crypto(format!(
                "unsupported proof system {:?} in verifier registry",
                other
            ))),
        }
    }

    fn proof_verifier(&self, proof: &ChainProof) -> ChainResult<&dyn ProofVerifier> {
        self.system_verifier(proof.system())
    }

    fn ensure_bundle_system(
        &self,
        bundle: &BlockProofBundle,
        expected: ProofSystemKind,
    ) -> ChainResult<()> {
        for proof in &bundle.transaction_proofs {
            if proof.system() != expected {
                return Err(ChainError::Crypto(format!(
                    "transaction proof uses {:?} but {:?} bundle expected",
                    proof.system(),
                    expected
                )));
            }
        }
        for proof in [
            &bundle.state_proof,
            &bundle.pruning_proof,
            &bundle.recursive_proof,
        ] {
            if proof.system() != expected {
                return Err(ChainError::Crypto(format!(
                    "block proof uses {:?} but {:?} bundle expected",
                    proof.system(),
                    expected
                )));
            }
        }
        Ok(())
    }

    /// Verify a transaction proof using the appropriate backend.
    pub fn verify_transaction(&self, proof: &ChainProof) -> ChainResult<()> {
        self.proof_verifier(proof)?.verify_transaction(proof)
    }

    /// Verify an identity proof using the appropriate backend.
    pub fn verify_identity(&self, proof: &ChainProof) -> ChainResult<()> {
        self.proof_verifier(proof)?.verify_identity(proof)
    }

    /// Verify a state transition proof using the appropriate backend.
    pub fn verify_state(&self, proof: &ChainProof) -> ChainResult<()> {
        self.proof_verifier(proof)?.verify_state(proof)
    }

    /// Verify a pruning proof using the appropriate backend.
    pub fn verify_pruning(&self, proof: &ChainProof) -> ChainResult<()> {
        self.proof_verifier(proof)?.verify_pruning(proof)
    }

    /// Verify a recursive aggregation proof using the appropriate backend.
    pub fn verify_recursive(&self, proof: &ChainProof) -> ChainResult<()> {
        self.proof_verifier(proof)?.verify_recursive(proof)
    }

    /// Verify an uptime proof using the appropriate backend.
    pub fn verify_uptime(&self, proof: &ChainProof) -> ChainResult<()> {
        self.proof_verifier(proof)?.verify_uptime(proof)
    }

    /// Verify a consensus proof using the appropriate backend.
    pub fn verify_consensus(&self, proof: &ChainProof) -> ChainResult<()> {
        self.proof_verifier(proof)?.verify_consensus(proof)
    }

    /// Verify the collection of proofs tied to a block and ensure they all use
    /// the same backend implementation.
    pub fn verify_block_bundle(
        &self,
        bundle: &BlockProofBundle,
        identity_proofs: &[ChainProof],
        uptime_proofs: &[ChainProof],
        consensus_proofs: &[ChainProof],
        state_commitments: &StateCommitmentSnapshot,
        expected_previous_commitment: Option<&str>,
    ) -> ChainResult<()> {
        match bundle.state_proof.system() {
            ProofSystemKind::Stwo => {
                self.ensure_bundle_system(bundle, ProofSystemKind::Stwo)?;
                self.stwo.verify_bundle(
                    identity_proofs,
                    &bundle.transaction_proofs,
                    uptime_proofs,
                    consensus_proofs,
                    &bundle.state_proof,
                    &bundle.pruning_proof,
                    &bundle.recursive_proof,
                    state_commitments,
                    expected_previous_commitment,
                )?;
                Ok(())
            }
            #[cfg(feature = "backend-plonky3")]
            ProofSystemKind::Plonky3 => {
                self.ensure_bundle_system(bundle, ProofSystemKind::Plonky3)?;
                self.plonky3
                    .verify_bundle(bundle, expected_previous_commitment)?;
                Ok(())
            }
            other => Err(ChainError::Crypto(format!(
                "unsupported proof system {:?} for block bundle",
                other
            ))),
        }
    }
}
