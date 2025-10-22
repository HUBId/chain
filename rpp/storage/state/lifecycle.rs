use hex;

use crate::errors::ChainResult;
use crate::proof_system::{ProofProver, ProofVerifierRegistry};
use crate::storage::{StateTransitionReceipt, Storage};
use crate::stwo::proof::ProofPayload;
use crate::stwo::prover::WalletProver;
use crate::types::{Account, AttestedIdentityRequest, ChainProof, SignedTransaction};

/// Trait capturing the operations required to drive the state lifecycle while
/// remaining agnostic over the backing storage and verifier wiring. It allows
/// callers (and tests) to interact with a uniform interface regardless of the
/// concrete implementation.
pub trait StateLifecycleService {
    /// Apply the account snapshot for the provided block height to Firewood and
    /// return the resulting state transition receipt.
    fn apply_block(&self, height: u64, accounts: &[Account])
    -> ChainResult<StateTransitionReceipt>;

    /// Produce a STWO state transition proof linking the supplied roots and
    /// witness data.
    fn prove_transition(
        &self,
        previous_root: &[u8; 32],
        new_root: &[u8; 32],
        identities: &[AttestedIdentityRequest],
        transactions: &[SignedTransaction],
    ) -> ChainResult<ChainProof>;

    /// Verify that a state transition proof matches the expected roots and
    /// circuit constraints.
    fn verify_transition(
        &self,
        proof: &ChainProof,
        expected_previous: &[u8; 32],
        expected_new: &[u8; 32],
    ) -> ChainResult<()>;

    /// Access the underlying storage handle, primarily for advanced flows and
    /// diagnostics.
    fn storage(&self) -> &Storage;

    /// Access the verifier registry backing this lifecycle helper.
    fn verifier(&self) -> &ProofVerifierRegistry;
}

/// Coordinates the state lifecycle across Firewood storage and STWO proofs.
pub struct StateLifecycle<'a> {
    storage: &'a Storage,
    verifier: ProofVerifierRegistry,
}

impl<'a> StateLifecycle<'a> {
    /// Construct a new lifecycle helper bound to the provided storage backend.
    pub fn new(storage: &'a Storage) -> Self {
        Self {
            storage,
            verifier: ProofVerifierRegistry::new(),
        }
    }

    fn ensure_state_witness(
        proof: &ChainProof,
        expected_previous: &[u8; 32],
        expected_new: &[u8; 32],
    ) -> ChainResult<()> {
        let stwo = proof.expect_stwo()?;
        if let ProofPayload::State(witness) = &stwo.payload {
            let prev_hex = hex::encode(expected_previous);
            let new_hex = hex::encode(expected_new);
            if witness.prev_state_root != prev_hex {
                return Err(crate::errors::ChainError::Crypto(
                    "state proof previous root mismatch".into(),
                ));
            }
            if witness.new_state_root != new_hex {
                return Err(crate::errors::ChainError::Crypto(
                    "state proof new root mismatch".into(),
                ));
            }
            Ok(())
        } else {
            Err(crate::errors::ChainError::Crypto(
                "state proof payload missing state witness".into(),
            ))
        }
    }
}

impl<'a> StateLifecycleService for StateLifecycle<'a> {
    fn apply_block(
        &self,
        height: u64,
        accounts: &[Account],
    ) -> ChainResult<StateTransitionReceipt> {
        self.storage.apply_account_snapshot(Some(height), accounts)
    }

    fn prove_transition(
        &self,
        previous_root: &[u8; 32],
        new_root: &[u8; 32],
        identities: &[AttestedIdentityRequest],
        transactions: &[SignedTransaction],
    ) -> ChainResult<ChainProof> {
        let prover = WalletProver::new(self.storage);
        let prev_hex = hex::encode(previous_root);
        let new_hex = hex::encode(new_root);
        let witness = prover.build_state_witness(&prev_hex, &new_hex, identities, transactions)?;
        prover.prove_state_transition(witness)
    }

    fn verify_transition(
        &self,
        proof: &ChainProof,
        expected_previous: &[u8; 32],
        expected_new: &[u8; 32],
    ) -> ChainResult<()> {
        self.verifier.verify_state(proof)?;
        Self::ensure_state_witness(proof, expected_previous, expected_new)
    }

    fn storage(&self) -> &Storage {
        self.storage
    }

    fn verifier(&self) -> &ProofVerifierRegistry {
        &self.verifier
    }
}

#[cfg(test)]
mod tests {
    use super::StateLifecycle;
    use crate::errors::ChainError;
    use crate::storage::Storage;
    use crate::stwo::circuit::state::StateWitness;
    use crate::stwo::proof::{ProofKind, ProofPayload, StarkProof};
    use crate::types::ChainProof;
    use tempfile::tempdir;

    fn dummy_state_proof(prev: &str, next: &str) -> ChainProof {
        let witness = StateWitness {
            prev_state_root: prev.to_owned(),
            new_state_root: next.to_owned(),
            identities: Vec::new(),
            transactions: Vec::new(),
            accounts_before: Vec::new(),
            accounts_after: Vec::new(),
            required_tier: crate::reputation::Tier::Tl0,
            reputation_weights: crate::reputation::ReputationWeights::default(),
        };
        let proof = StarkProof {
            kind: ProofKind::State,
            commitment: "aa".repeat(32),
            public_inputs: Vec::new(),
            payload: ProofPayload::State(witness),
            trace: crate::stwo::circuit::ExecutionTrace {
                segments: Vec::new(),
            },
            commitment_proof: crate::stwo::proof::CommitmentSchemeProofData::default(),
            fri_proof: crate::stwo::proof::FriProof::default(),
        };
        ChainProof::Stwo(proof)
    }

    fn hex_bytes(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn state_witness_matches_expected_roots() {
        let previous = hex_bytes(0x11);
        let next = hex_bytes(0x22);
        let proof = dummy_state_proof(&hex::encode(previous), &hex::encode(next));
        StateLifecycle::ensure_state_witness(&proof, &previous, &next).expect("roots match");
    }

    #[test]
    fn state_witness_rejects_previous_root_mismatch() {
        let previous = hex_bytes(0x11);
        let next = hex_bytes(0x22);
        let proof = dummy_state_proof(&hex::encode(previous), &hex::encode(next));
        let err = StateLifecycle::ensure_state_witness(&proof, &hex_bytes(0xFF), &next)
            .expect_err("mismatched previous root");
        assert!(matches!(err, ChainError::Crypto(_)));
    }

    #[test]
    fn state_witness_rejects_new_root_mismatch() {
        let previous = hex_bytes(0x11);
        let next = hex_bytes(0x22);
        let proof = dummy_state_proof(&hex::encode(previous), &hex::encode(next));
        let err = StateLifecycle::ensure_state_witness(&proof, &previous, &hex_bytes(0xFF))
            .expect_err("mismatched new root");
        assert!(matches!(err, ChainError::Crypto(_)));
    }

    #[test]
    fn verify_transition_propagates_verifier_errors() {
        let dir = tempdir().expect("tempdir");
        let storage = Storage::open(dir.path()).expect("open storage");
        let lifecycle = StateLifecycle::new(&storage);
        let proof = dummy_state_proof(&"00".repeat(32), &"11".repeat(32));
        let result = lifecycle.verify_transition(&proof, &hex_bytes(0), &hex_bytes(1));
        assert!(result.is_err(), "verifier should reject dummy proof");
    }
}
