//! Wallet integration for the Plonky3 backend.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use serde_json::Value;

use plonky3_backend::ProverContext as BackendProverContext;

use crate::consensus::ConsensusCertificate;
use crate::errors::{ChainError, ChainResult};
use crate::proof_system::ProofProver;
use crate::rpp::{GlobalStateCommitments, ProofSystemKind};
use crate::types::{
    AttestedIdentityRequest, ChainProof, IdentityGenesis, SignedTransaction, UptimeClaim,
};
use rpp_crypto_vrf::VRF_PROOF_LENGTH;
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

#[derive(Clone, Debug, Serialize)]
pub struct Plonky3BackendError {
    pub message: String,
    pub at_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Plonky3BackendHealth {
    pub cached_circuits: usize,
    pub proofs_generated: u64,
    pub failed_proofs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<Plonky3BackendError>,
}

#[derive(Default)]
struct Plonky3Telemetry {
    cached_circuits: AtomicUsize,
    proofs_generated: AtomicU64,
    failed_proofs: AtomicU64,
    last_success_ms: AtomicU64,
    last_error: RwLock<Option<Plonky3BackendError>>,
}

static PLONKY3_TELEMETRY: Lazy<Plonky3Telemetry> = Lazy::new(Plonky3Telemetry::default);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

impl Plonky3Telemetry {
    fn record_cache_size(&self, size: usize) {
        self.cached_circuits.store(size, Ordering::SeqCst);
    }

    fn record_success(&self) {
        self.proofs_generated.fetch_add(1, Ordering::SeqCst);
        self.last_success_ms.store(now_ms(), Ordering::SeqCst);
        let mut guard = self.last_error.write();
        guard.take();
    }

    fn record_failure(&self, message: String) {
        self.failed_proofs.fetch_add(1, Ordering::SeqCst);
        *self.last_error.write() = Some(Plonky3BackendError {
            message,
            at_ms: now_ms(),
        });
    }

    fn snapshot(&self) -> Plonky3BackendHealth {
        let cached_circuits = self.cached_circuits.load(Ordering::SeqCst);
        let proofs_generated = self.proofs_generated.load(Ordering::SeqCst);
        let failed_proofs = self.failed_proofs.load(Ordering::SeqCst);
        let last_success_raw = self.last_success_ms.load(Ordering::SeqCst);
        let last_success_ms = if last_success_raw == 0 {
            None
        } else {
            Some(last_success_raw)
        };
        let last_error = self.last_error.read().clone();
        Plonky3BackendHealth {
            cached_circuits,
            proofs_generated,
            failed_proofs,
            last_success_ms,
            last_error,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(super) struct Plonky3Backend {
    compiled: Arc<Mutex<HashMap<CircuitCacheKey, BackendProverContext>>>,
}

impl Plonky3Backend {
    fn ensure_compiled(
        &self,
        params: &Plonky3Parameters,
        circuit: &str,
    ) -> ChainResult<BackendProverContext> {
        let key = CircuitCacheKey {
            circuit: circuit.to_string(),
            security_bits: params.security_bits,
            use_gpu: params.use_gpu_acceleration,
        };
        {
            let guard = self.compiled.lock();
            if let Some(compiled) = guard.get(&key).cloned() {
                PLONKY3_TELEMETRY.record_cache_size(guard.len());
                return Ok(compiled);
            }
        }

        let (verifying_key, proving_key) = crypto::circuit_keys(circuit)?;
        let compiled = BackendProverContext::new(
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
        PLONKY3_TELEMETRY.record_cache_size(guard.len());
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
        let backend_proof = compiled
            .prove(&commitment, &encoded_inputs)
            .map_err(|err| {
                let message = format!("failed to generate Plonky3 {circuit} proof: {err}");
                PLONKY3_TELEMETRY.record_failure(message.clone());
                ChainError::Crypto(message)
            })?;
        let proof = Plonky3Proof::from_backend(
            circuit.to_string(),
            commitment,
            public_inputs,
            backend_proof,
        )?;
        PLONKY3_TELEMETRY.record_success();
        Ok(proof)
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

pub fn telemetry_snapshot() -> Plonky3BackendHealth {
    PLONKY3_TELEMETRY.snapshot()
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
        let ensure_digest = |label: &str, value: &str| -> ChainResult<()> {
            let bytes = hex::decode(value).map_err(|err| {
                ChainError::Crypto(format!("invalid {label} encoding '{value}': {err}"))
            })?;
            if bytes.len() != 32 {
                return Err(ChainError::Crypto(format!("{label} must encode 32 bytes")));
            }
            Ok(())
        };

        ensure_digest(
            "quorum bitmap root",
            &certificate.metadata.quorum_bitmap_root,
        )?;
        ensure_digest(
            "quorum signature root",
            &certificate.metadata.quorum_signature_root,
        )?;

        if certificate.metadata.vrf_outputs.is_empty() {
            return Err(ChainError::Crypto(
                "consensus certificate missing VRF outputs".into(),
            ));
        }
        if certificate.metadata.vrf_proofs.is_empty() {
            return Err(ChainError::Crypto(
                "consensus certificate missing VRF proofs".into(),
            ));
        }
        if certificate.metadata.vrf_outputs.len() != certificate.metadata.vrf_proofs.len() {
            return Err(ChainError::Crypto(
                "consensus certificate VRF output/proof count mismatch".into(),
            ));
        }
        if certificate.metadata.witness_commitments.is_empty() {
            return Err(ChainError::Crypto(
                "consensus certificate missing witness commitments".into(),
            ));
        }
        if certificate.metadata.reputation_roots.is_empty() {
            return Err(ChainError::Crypto(
                "consensus certificate missing reputation roots".into(),
            ));
        }

        for (index, proof) in certificate.metadata.vrf_proofs.iter().enumerate() {
            let bytes = hex::decode(proof).map_err(|err| {
                ChainError::Crypto(format!("invalid vrf proof #{index} encoding: {err}"))
            })?;
            if bytes.len() != VRF_PROOF_LENGTH {
                return Err(ChainError::Crypto(format!(
                    "vrf proof #{index} must encode {VRF_PROOF_LENGTH} bytes"
                )));
            }
        }

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
            certificate.metadata.epoch,
            certificate.metadata.slot,
            block_hash,
            quorum,
            pre_votes,
            pre_commits,
            commit_votes,
            certificate.metadata.quorum_bitmap_root.clone(),
            certificate.metadata.quorum_signature_root.clone(),
            certificate.metadata.vrf_outputs.clone(),
            certificate.metadata.vrf_proofs.clone(),
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
