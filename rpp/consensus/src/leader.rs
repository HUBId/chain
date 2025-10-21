use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::messages::{Block, ConsensusProof, Proposal};
use crate::proof_backend::{ProofBackend, ProofSystemKind};
use crate::state::ConsensusState;
use crate::validator::{Validator, ValidatorSet};

#[derive(Clone, Debug)]
pub struct LeaderContext {
    pub epoch: u64,
    pub round: u64,
}

#[derive(Clone, Debug)]
pub struct Leader {
    pub validator: Validator,
}

impl Leader {
    pub fn new(validator: Validator) -> Self {
        Self { validator }
    }

    pub fn build_proposal(
        &self,
        state: &ConsensusState,
        context: LeaderContext,
    ) -> Option<Proposal> {
        let block = Block {
            height: state.block_height + 1,
            epoch: context.epoch,
            payload: json!({
                "pending_proofs": state.pending_proofs.len(),
                "reputation_root": state.reputation_root,
            }),
            timestamp: current_timestamp(),
        };

        let certificate = state.consensus_certificate().clone();
        let system = proof_system_from_backend(state.proof_backend.as_ref());
        let witness = certificate.encode_witness(system).ok()?;
        let (proof_bytes, verifying_key, circuit) =
            state.proof_backend.prove_consensus(&witness).ok()?;
        let public_inputs = certificate.consensus_public_inputs().ok()?;
        let proof = ConsensusProof::from_backend_artifacts(
            proof_bytes,
            verifying_key,
            circuit,
            public_inputs,
        );

        Some(Proposal {
            block,
            proof,
            certificate,
            leader_id: self.validator.id.clone(),
        })
    }
}

fn proof_system_from_backend(backend: &dyn ProofBackend) -> ProofSystemKind {
    match backend.name() {
        "mock" => ProofSystemKind::Mock,
        "stwo" => ProofSystemKind::Stwo,
        "plonky3" => ProofSystemKind::Plonky3,
        "plonky2" => ProofSystemKind::Plonky2,
        "halo2" => ProofSystemKind::Halo2,
        "rpp-stark" => ProofSystemKind::RppStark,
        _ => ProofSystemKind::Mock,
    }
}

pub fn elect_leader(validators: &ValidatorSet, _context: LeaderContext) -> Option<Leader> {
    validators
        .validators
        .iter()
        .cloned()
        .max_by(|a, b| {
            a.reputation_tier
                .cmp(&b.reputation_tier)
                .then_with(|| a.timetoken_balance.cmp(&b.timetoken_balance))
                .then_with(|| a.vrf_output.cmp(&b.vrf_output))
                .then_with(|| a.id.cmp(&b.id))
        })
        .map(Leader::new)
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}
