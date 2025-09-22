use hex;

use crate::errors::ChainResult;
use crate::proof_system::{ProofProver, ProofVerifierRegistry};
use crate::storage::{StateTransitionReceipt, Storage};
use crate::stwo::proof::ProofPayload;
use crate::stwo::prover::WalletProver;
use crate::types::{Account, ChainProof, IdentityDeclaration, SignedTransaction};

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

    /// Apply the account snapshot for the provided block height to Firewood and
    /// return the resulting state transition receipt.
    pub fn apply_block(
        &self,
        height: u64,
        accounts: &[Account],
    ) -> ChainResult<StateTransitionReceipt> {
        self.storage.apply_account_snapshot(Some(height), accounts)
    }

    /// Produce a STWO state transition proof linking the supplied roots and
    /// witness data.
    pub fn prove_transition(
        &self,
        previous_root: &[u8; 32],
        new_root: &[u8; 32],
        identities: &[IdentityDeclaration],
        transactions: &[SignedTransaction],
    ) -> ChainResult<ChainProof> {
        let prover = WalletProver::new(self.storage);
        let prev_hex = hex::encode(previous_root);
        let new_hex = hex::encode(new_root);
        let witness = prover.build_state_witness(&prev_hex, &new_hex, identities, transactions)?;
        prover.prove_state_transition(witness)
    }

    /// Verify that a state transition proof matches the expected roots and
    /// circuit constraints.
    pub fn verify_transition(
        &self,
        proof: &ChainProof,
        expected_previous: &[u8; 32],
        expected_new: &[u8; 32],
    ) -> ChainResult<()> {
        self.verifier.verify_state(proof)?;
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

    /// Access the underlying storage handle.
    pub fn storage(&self) -> &'a Storage {
        self.storage
    }

    /// Access the verifier registry backing this lifecycle helper.
    pub fn verifier(&self) -> &ProofVerifierRegistry {
        &self.verifier
    }
}
