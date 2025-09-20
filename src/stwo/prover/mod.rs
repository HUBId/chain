//! Prover-side integration for STWO/STARK proofs.

use std::collections::HashMap;

use crate::errors::{ChainError, ChainResult};
use crate::ledger::compute_merkle_root;
use crate::reputation::{ReputationWeights, Tier};
use crate::storage::Storage;
use crate::types::{Account, PruningProof, SignedTransaction, Stake};

use super::aggregation::RecursiveAggregator;
use super::circuit::{
    CircuitError, StarkCircuit,
    pruning::{PruningCircuit, PruningWitness},
    recursive::{RecursiveCircuit, RecursiveWitness},
    state::{StateCircuit, StateWitness},
    transaction::{TransactionCircuit, TransactionWitness},
};
use super::fri::FriProver;
use super::params::{FieldElement, StarkParameters};
use super::proof::{ProofKind, ProofPayload, StarkProof};

/// Trait implemented by STWO proof generators embedded in the wallet.
pub trait StarkProver {
    /// Generates the transaction-level proof for ownership, balance and nonce checks.
    fn prove_transaction(&self, witness: TransactionWitness) -> ChainResult<StarkProof>;

    /// Generates a batched state transition proof for a sequence of transactions.
    fn prove_state_transition(&self, witness: StateWitness) -> ChainResult<StarkProof>;

    /// Generates the pruning proof used to attest correct ledger pruning.
    fn prove_pruning(&self, witness: PruningWitness) -> ChainResult<StarkProof>;

    /// Aggregates individual proofs recursively.
    fn prove_recursive(&self, witness: RecursiveWitness) -> ChainResult<StarkProof>;
}

fn map_circuit_error(err: CircuitError) -> ChainError {
    ChainError::Crypto(err.to_string())
}

fn string_to_field(parameters: &StarkParameters, value: &str) -> FieldElement {
    let bytes = hex::decode(value).unwrap_or_else(|_| value.as_bytes().to_vec());
    parameters.element_from_bytes(&bytes)
}

/// Wallet-integrated prover that derives witnesses from local state.
pub struct WalletProver<'a> {
    pub storage: &'a Storage,
    parameters: StarkParameters,
    reputation_weights: ReputationWeights,
    minimum_tier: Tier,
}

impl<'a> WalletProver<'a> {
    pub fn new(storage: &'a Storage) -> Self {
        Self {
            storage,
            parameters: StarkParameters::blueprint_default(),
            reputation_weights: ReputationWeights::default(),
            minimum_tier: Tier::Tl1,
        }
    }

    pub fn with_minimum_tier(mut self, tier: Tier) -> Self {
        self.minimum_tier = tier;
        self
    }

    pub fn with_parameters(mut self, parameters: StarkParameters) -> Self {
        self.parameters = parameters;
        self
    }

    fn hasher(&self) -> super::params::PoseidonHasher {
        self.parameters.poseidon_hasher()
    }

    pub fn build_transaction_witness(
        &self,
        tx: &SignedTransaction,
    ) -> ChainResult<TransactionWitness> {
        let sender_account = self
            .storage
            .read_account(&tx.payload.from)?
            .ok_or_else(|| ChainError::Transaction("sender account not found".into()))?;
        let receiver_account = self.storage.read_account(&tx.payload.to)?;
        Ok(TransactionWitness {
            signed_tx: tx.clone(),
            sender_account,
            receiver_account,
            required_tier: self.minimum_tier.clone(),
            reputation_weights: self.reputation_weights.clone(),
        })
    }

    pub fn build_state_witness(
        &self,
        prev_state_root: &str,
        new_state_root: &str,
        transactions: &[SignedTransaction],
    ) -> ChainResult<StateWitness> {
        let accounts_before = self.storage.load_accounts()?;
        let mut state: HashMap<_, _> = accounts_before
            .iter()
            .cloned()
            .map(|account| (account.address.clone(), account))
            .collect();
        for tx in transactions {
            let sender = state
                .get_mut(&tx.payload.from)
                .ok_or_else(|| ChainError::Transaction("sender missing from state".into()))?;
            let total = tx
                .payload
                .amount
                .checked_add(tx.payload.fee as u128)
                .ok_or_else(|| ChainError::Transaction("transaction amount overflow".into()))?;
            if sender.balance < total {
                return Err(ChainError::Transaction("insufficient balance".into()));
            }
            sender.balance -= total;
            sender.nonce += 1;
            let recipient = state
                .entry(tx.payload.to.clone())
                .or_insert_with(|| Account::new(tx.payload.to.clone(), 0, Stake::default()));
            recipient.balance = recipient.balance.saturating_add(tx.payload.amount);
            recipient.reputation.recompute_score(
                &self.reputation_weights,
                crate::reputation::current_timestamp(),
            );
        }
        let accounts_after = state.into_values().collect();
        Ok(StateWitness {
            prev_state_root: prev_state_root.to_string(),
            new_state_root: new_state_root.to_string(),
            transactions: transactions.to_vec(),
            accounts_before,
            accounts_after,
            required_tier: self.minimum_tier.clone(),
            reputation_weights: self.reputation_weights.clone(),
        })
    }

    pub fn build_pruning_witness(
        &self,
        previous_txs: &[SignedTransaction],
        pruning: &PruningProof,
        removed: Vec<String>,
    ) -> PruningWitness {
        let mut leaves = previous_txs.iter().map(|tx| tx.hash()).collect::<Vec<_>>();
        let previous_tx_root = hex::encode(compute_merkle_root(&mut leaves));
        let original_transactions = previous_txs
            .iter()
            .map(|tx| hex::encode(tx.hash()))
            .collect();
        PruningWitness {
            previous_tx_root,
            pruned_tx_root: pruning.pruned_tx_root.clone(),
            original_transactions,
            removed_transactions: removed,
        }
    }

    pub fn build_recursive_witness(
        &self,
        previous_recursive: Option<&StarkProof>,
        tx_proofs: &[StarkProof],
        state_proof: &StarkProof,
        pruning_proof: &StarkProof,
        block_height: u64,
    ) -> ChainResult<RecursiveWitness> {
        let aggregator = RecursiveAggregator::new(self.parameters.clone());
        aggregator.build_witness(
            previous_recursive,
            tx_proofs,
            state_proof,
            pruning_proof,
            block_height,
        )
    }
}

impl<'a> StarkProver for WalletProver<'a> {
    fn prove_transaction(&self, witness: TransactionWitness) -> ChainResult<StarkProof> {
        let circuit = TransactionCircuit::new(witness.clone());
        circuit.evaluate_constraints().map_err(map_circuit_error)?;
        let trace = circuit
            .generate_trace(&self.parameters)
            .map_err(map_circuit_error)?;
        circuit
            .verify_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let tx = &witness.signed_tx.payload;
        let inputs = vec![
            string_to_field(&self.parameters, &tx.from),
            string_to_field(&self.parameters, &tx.to),
            self.parameters.element_from_u128(tx.amount),
            self.parameters.element_from_u64(tx.fee as u64),
            self.parameters.element_from_u64(tx.nonce),
        ];
        let hasher = self.hasher();
        let fri_prover = FriProver::new(&self.parameters);
        let fri_proof = fri_prover.prove(&trace, &inputs);
        Ok(StarkProof::new(
            ProofKind::Transaction,
            ProofPayload::Transaction(witness),
            inputs,
            trace,
            fri_proof,
            &hasher,
        ))
    }

    fn prove_state_transition(&self, witness: StateWitness) -> ChainResult<StarkProof> {
        let circuit = StateCircuit::new(witness.clone());
        circuit.evaluate_constraints().map_err(map_circuit_error)?;
        let trace = circuit
            .generate_trace(&self.parameters)
            .map_err(map_circuit_error)?;
        circuit
            .verify_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let inputs = vec![
            string_to_field(&self.parameters, &witness.prev_state_root),
            string_to_field(&self.parameters, &witness.new_state_root),
            self.parameters
                .element_from_u64(witness.transactions.len() as u64),
        ];
        let hasher = self.hasher();
        let fri_prover = FriProver::new(&self.parameters);
        let fri_proof = fri_prover.prove(&trace, &inputs);
        Ok(StarkProof::new(
            ProofKind::State,
            ProofPayload::State(witness),
            inputs,
            trace,
            fri_proof,
            &hasher,
        ))
    }

    fn prove_pruning(&self, witness: PruningWitness) -> ChainResult<StarkProof> {
        let circuit = PruningCircuit::new(witness.clone());
        circuit.evaluate_constraints().map_err(map_circuit_error)?;
        let trace = circuit
            .generate_trace(&self.parameters)
            .map_err(map_circuit_error)?;
        circuit
            .verify_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let inputs = vec![
            string_to_field(&self.parameters, &witness.previous_tx_root),
            string_to_field(&self.parameters, &witness.pruned_tx_root),
            self.parameters
                .element_from_u64(witness.removed_transactions.len() as u64),
        ];
        let hasher = self.hasher();
        let fri_prover = FriProver::new(&self.parameters);
        let fri_proof = fri_prover.prove(&trace, &inputs);
        Ok(StarkProof::new(
            ProofKind::Pruning,
            ProofPayload::Pruning(witness),
            inputs,
            trace,
            fri_proof,
            &hasher,
        ))
    }

    fn prove_recursive(&self, witness: RecursiveWitness) -> ChainResult<StarkProof> {
        let circuit = RecursiveCircuit::new(witness.clone());
        circuit.evaluate_constraints().map_err(map_circuit_error)?;
        let trace = circuit
            .generate_trace(&self.parameters)
            .map_err(map_circuit_error)?;
        circuit
            .verify_air(&self.parameters, &trace)
            .map_err(map_circuit_error)?;
        let prev = witness.previous_commitment.clone().unwrap_or_default();
        let inputs = vec![
            string_to_field(&self.parameters, &prev),
            string_to_field(&self.parameters, &witness.aggregated_commitment),
            self.parameters
                .element_from_u64(witness.tx_commitments.len() as u64),
        ];
        let hasher = self.hasher();
        let fri_prover = FriProver::new(&self.parameters);
        let fri_proof = fri_prover.prove(&trace, &inputs);
        Ok(StarkProof::new(
            ProofKind::Recursive,
            ProofPayload::Recursive(witness),
            inputs,
            trace,
            fri_proof,
            &hasher,
        ))
    }
}
