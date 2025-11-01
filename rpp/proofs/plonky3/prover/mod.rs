//! Wallet integration for the Plonky3 backend.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use parking_lot::Mutex;
use serde_json::Value;

use plonky3_backend::Circuit as BackendCircuit;

use crate::consensus::ConsensusCertificate;
use crate::errors::{ChainError, ChainResult};
use crate::proof_system::ProofProver;
use crate::rpp::{GlobalStateCommitments, ProofSystemKind};
use crate::types::{
    AttestedIdentityRequest, ChainProof, IdentityGenesis, SignedTransaction, UptimeClaim,
};
use rpp_pruning::Envelope;

use super::aggregation::RecursiveAggregator;
use super::circuit::consensus::{ConsensusWitness, VotePower};
use super::circuit::identity::IdentityWitness;
use super::circuit::pruning::PruningWitness;
use super::circuit::recursive::RecursiveWitness;
use super::circuit::state::StateWitness;
use super::circuit::transaction::TransactionWitness;
use super::circuit::uptime::UptimeWitness;
use super::circuit::Plonky3CircuitWitness;
use super::crypto;
use super::params::Plonky3Parameters;
use super::proof::Plonky3Proof;

#[derive(Clone, Debug, Eq)]
struct CircuitCacheKey {
    circuit: String,
    security_bits: u32,
    use_gpu: bool,
}

impl PartialEq for CircuitCacheKey {
    fn eq(&self, other: &Self) -> bool {
        self.circuit == other.circuit
            && self.security_bits == other.security_bits
            && self.use_gpu == other.use_gpu
    }
}

impl Hash for CircuitCacheKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.circuit.hash(state);
        self.security_bits.hash(state);
        self.use_gpu.hash(state);
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct Plonky3Backend {
    compiled: Arc<Mutex<HashMap<CircuitCacheKey, BackendCircuit>>>,
}

impl Plonky3Backend {
    fn ensure_compiled(
        &self,
        params: &Plonky3Parameters,
        circuit: &str,
    ) -> ChainResult<BackendCircuit> {
        let key = CircuitCacheKey {
            circuit: circuit.to_string(),
            security_bits: params.security_bits,
            use_gpu: params.use_gpu_acceleration,
        };
        if let Some(compiled) = self.compiled.lock().get(&key).cloned() {
            return Ok(compiled);
        }

        let (verifying_key, proving_key) = crypto::circuit_keys(circuit)?;
        let compiled = BackendCircuit::keygen(
            circuit.to_string(),
            verifying_key,
            proving_key,
            params.security_bits,
            params.use_gpu_acceleration,
        )
        .map_err(|err| {
            ChainError::Crypto(format!(
                "failed to prepare Plonky3 {circuit} circuit for proving: {err}"
            ))
        })?;

        let mut guard = self.compiled.lock();
        guard.insert(key, compiled.clone());
        Ok(compiled)
    }

    fn prove<W: Plonky3CircuitWitness>(
        &self,
        params: &Plonky3Parameters,
        witness: &W,
    ) -> ChainResult<Plonky3Proof> {
        let circuit = witness.circuit();
        let compiled = self.ensure_compiled(params, circuit)?;
        let public_inputs = witness.public_inputs()?;
        let (commitment, encoded_inputs) = crypto::canonical_public_inputs(&public_inputs)?;
        let proof_bytes = compiled
            .prove(&commitment, &encoded_inputs)
            .map_err(|err| {
                ChainError::Crypto(format!("failed to generate Plonky3 {circuit} proof: {err}"))
            })?;
        Ok(Plonky3Proof {
            circuit: circuit.to_string(),
            commitment,
            public_inputs,
            proof: proof_bytes,
            verifying_key: compiled.verifying_key().to_vec(),
        })
    }
}

/// Wallet-facing prover stub for Plonky3. The structure mirrors the STWO
/// implementation so the surrounding plumbing can be developed in parallel.
#[derive(Clone, Debug)]
pub struct Plonky3Prover {
    pub params: Plonky3Parameters,
    backend: Plonky3Backend,
}

impl Plonky3Prover {
    pub fn new() -> Self {
        if let Err(err) = crate::plonky3::experimental::require_acknowledgement() {
            panic!("{err}");
        }
        Self {
            params: Plonky3Parameters::default(),
            backend: Plonky3Backend::default(),
        }
    }

    fn prove_with_backend<W>(&self, witness: &W) -> ChainResult<ChainProof>
    where
        W: Plonky3CircuitWitness,
    {
        let proof = self.backend.prove(&self.params, witness)?;
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
        identities: &[AttestedIdentityRequest],
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
        expected_previous_state_root: Option<&str>,
        previous_identities: &[AttestedIdentityRequest],
        previous_txs: &[SignedTransaction],
        pruning: &Envelope,
        removed: Vec<String>,
    ) -> ChainResult<Self::PruningWitness> {
        let snapshot_state_root = hex::encode(pruning.snapshot().state_commitment().digest());
        if let Some(expected) = expected_previous_state_root {
            if expected != snapshot_state_root {
                return Err(ChainError::Crypto(format!(
                    "pruning envelope snapshot root mismatch: expected {expected}, envelope {snapshot_state_root}",
                )));
            }
        }
        if pruning.segments().is_empty() {
            return Err(ChainError::Crypto(
                "pruning envelope missing transaction segment".into(),
            ));
        }
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
        _pruning_envelope: &Envelope,
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
            certificate.metadata.vrf_outputs.clone(),
            certificate.metadata.witness_commitments.clone(),
            certificate.metadata.reputation_roots.clone(),
        ))
    }

    fn prove_transaction(&self, witness: Self::TransactionWitness) -> ChainResult<ChainProof> {
        self.prove_with_backend(&witness)
    }

    fn prove_identity(&self, witness: Self::IdentityWitness) -> ChainResult<ChainProof> {
        self.prove_with_backend(&witness)
    }

    fn prove_state_transition(&self, witness: Self::StateWitness) -> ChainResult<ChainProof> {
        self.prove_with_backend(&witness)
    }

    fn prove_pruning(&self, witness: Self::PruningWitness) -> ChainResult<ChainProof> {
        self.prove_with_backend(&witness)
    }

    fn prove_recursive(&self, witness: Self::RecursiveWitness) -> ChainResult<ChainProof> {
        let aggregator = RecursiveAggregator::new(self.params.clone(), self.backend.clone());
        let proof = aggregator.finalize(&witness)?;
        proof.into_value().map(ChainProof::Plonky3)
    }

    fn prove_uptime(&self, witness: Self::UptimeWitness) -> ChainResult<ChainProof> {
        self.prove_with_backend(&witness)
    }

    fn prove_consensus(&self, witness: Self::ConsensusWitness) -> ChainResult<ChainProof> {
        self.prove_with_backend(&witness)
    }
}
