//! Wallet integration for the Plonky3 backend.

use serde_json::Value;

use crate::consensus::ConsensusCertificate;
use crate::errors::{ChainError, ChainResult};
use crate::proof_system::ProofProver;
use crate::rpp::{GlobalStateCommitments, ProofSystemKind};
use crate::types::{
    ChainProof, IdentityDeclaration, IdentityGenesis, PruningProof, SignedTransaction, UptimeClaim,
};

use super::aggregation::RecursiveAggregator;
use super::circuit::consensus::{ConsensusWitness, VotePower};
use super::circuit::identity::IdentityWitness;
use super::circuit::pruning::PruningWitness;
use super::circuit::recursive::RecursiveWitness;
use super::circuit::state::StateWitness;
use super::circuit::transaction::TransactionWitness;
use super::circuit::uptime::UptimeWitness;
use super::params::Plonky3Parameters;
use super::proof::Plonky3Proof;

/// Wallet-facing prover stub for Plonky3. The structure mirrors the STWO
/// implementation so the surrounding plumbing can be developed in parallel.
#[derive(Clone, Debug)]
pub struct Plonky3Prover {
    pub params: Plonky3Parameters,
}

impl Plonky3Prover {
    pub fn new() -> Self {
        Self {
            params: Plonky3Parameters::default(),
        }
    }

    fn encode_placeholder<T: serde::Serialize>(
        &self,
        circuit: &str,
        witness: &T,
        block_height: Option<u64>,
    ) -> ChainResult<ChainProof> {
        let witness_value = serde_json::to_value(witness).map_err(|err| {
            ChainError::Crypto(format!(
                "failed to serialize {circuit} witness for Plonky3 placeholder: {err}"
            ))
        })?;
        let proof = match block_height {
            Some(height) => Plonky3Proof::placeholder(circuit, witness_value, height),
            None => Plonky3Proof::from_parts(
                circuit,
                witness_value,
                Value::String("pending-implementation".into()),
            ),
        };
        proof.into_value().map(ChainProof::Plonky3)
    }
}

impl ProofProver for Plonky3Prover {
    type IdentityWitness = IdentityWitness;
    type TransactionWitness = TransactionWitness;
    type StateWitness = StateWitness;
    type PruningWitness = PruningWitness;
    type RecursiveWitness = RecursiveWitness;
    type UptimeWitness = UptimeWitness;
    type ConsensusWitness = ConsensusWitness;

    fn system(&self) -> ProofSystemKind {
        ProofSystemKind::Plonky3
    }

    fn build_identity_witness(
        &self,
        genesis: &IdentityGenesis,
    ) -> ChainResult<Self::IdentityWitness> {
        Ok(IdentityWitness::new(genesis))
    }

    fn build_transaction_witness(
        &self,
        tx: &SignedTransaction,
    ) -> ChainResult<Self::TransactionWitness> {
        Ok(TransactionWitness::new(tx))
    }

    fn build_state_witness(
        &self,
        prev_state_root: &str,
        new_state_root: &str,
        identities: &[IdentityDeclaration],
        transactions: &[SignedTransaction],
    ) -> ChainResult<Self::StateWitness> {
        Ok(StateWitness::new(
            prev_state_root,
            new_state_root,
            identities,
            transactions,
        ))
    }

    fn build_pruning_witness(
        &self,
        previous_identities: &[IdentityDeclaration],
        previous_txs: &[SignedTransaction],
        pruning: &PruningProof,
        removed: Vec<String>,
    ) -> ChainResult<Self::PruningWitness> {
        Ok(PruningWitness::new(
            previous_identities,
            previous_txs,
            pruning,
            removed,
        ))
    }

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
    ) -> ChainResult<Self::RecursiveWitness> {
        Ok(RecursiveWitness::new(
            previous_recursive.cloned(),
            identity_proofs,
            tx_proofs,
            uptime_proofs,
            consensus_proofs,
            state_commitments,
            state_proof,
            pruning_proof,
            block_height,
        ))
    }

    fn build_uptime_witness(&self, claim: &UptimeClaim) -> ChainResult<Self::UptimeWitness> {
        Ok(UptimeWitness::new(
            &claim.wallet_address,
            claim.node_clock,
            claim.epoch,
            &claim.head_hash,
            claim.window_start,
            claim.window_end,
            claim.commitment(),
        ))
    }

    fn build_consensus_witness(
        &self,
        block_hash: &str,
        certificate: &ConsensusCertificate,
    ) -> ChainResult<Self::ConsensusWitness> {
        let parse_weight = |weight: &str| weight.parse::<u64>().unwrap_or(0);
        let pre_votes = certificate
            .pre_votes
            .iter()
            .map(|record| VotePower {
                voter: record.vote.vote.voter.clone(),
                weight: parse_weight(&record.weight),
            })
            .collect();
        let pre_commits = certificate
            .pre_commits
            .iter()
            .map(|record| VotePower {
                voter: record.vote.vote.voter.clone(),
                weight: parse_weight(&record.weight),
            })
            .collect::<Vec<_>>();
        let commit_votes = pre_commits.clone();
        let quorum = certificate.quorum_threshold.parse::<u64>().unwrap_or(0);
        Ok(ConsensusWitness::new(
            block_hash,
            certificate.round,
            block_hash,
            quorum,
            pre_votes,
            pre_commits,
            commit_votes,
        ))
    }

    fn prove_transaction(&self, witness: Self::TransactionWitness) -> ChainResult<ChainProof> {
        self.encode_placeholder("transaction", &witness, None)
    }

    fn prove_identity(&self, witness: Self::IdentityWitness) -> ChainResult<ChainProof> {
        self.encode_placeholder("identity", &witness, None)
    }

    fn prove_state_transition(&self, witness: Self::StateWitness) -> ChainResult<ChainProof> {
        self.encode_placeholder("state", &witness, None)
    }

    fn prove_pruning(&self, witness: Self::PruningWitness) -> ChainResult<ChainProof> {
        self.encode_placeholder("pruning", &witness, None)
    }

    fn prove_recursive(&self, witness: Self::RecursiveWitness) -> ChainResult<ChainProof> {
        let mut commitments = Vec::new();
        if let Some(previous) = witness.previous_recursive.clone() {
            commitments.push(previous);
        }
        commitments.extend(witness.identity_proofs.clone());
        commitments.extend(witness.transaction_proofs.clone());
        commitments.extend(witness.uptime_proofs.clone());
        commitments.extend(witness.consensus_proofs.clone());
        commitments.push(witness.state_proof.clone());
        commitments.push(witness.pruning_proof.clone());
        let aggregator = RecursiveAggregator::new(witness.block_height, commitments);
        let proof = aggregator.finalize()?;
        proof.into_value().map(ChainProof::Plonky3)
    }

    fn prove_uptime(&self, witness: Self::UptimeWitness) -> ChainResult<ChainProof> {
        self.encode_placeholder("uptime", &witness, None)
    }

    fn prove_consensus(&self, witness: Self::ConsensusWitness) -> ChainResult<ChainProof> {
        self.encode_placeholder("consensus", &witness, Some(witness.round))
    }
}
