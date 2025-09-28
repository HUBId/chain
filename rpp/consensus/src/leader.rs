use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::messages::{Block, ConsensusProof, Proposal};
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

    pub fn build_proposal(&self, state: &ConsensusState, context: LeaderContext) -> Proposal {
        let block = Block {
            height: state.block_height + 1,
            epoch: context.epoch,
            payload: json!({
                "pending_proofs": state.pending_proofs.len(),
                "reputation_root": state.reputation_root,
            }),
            timestamp: current_timestamp(),
        };

        let inherited_commitments = state
            .pending_proofs
            .iter()
            .map(|proof| proof.commitment.clone())
            .collect();

        let proof = ConsensusProof::new(
            format!("stwo-commitment-{}", block.height),
            format!("stwo-witness-{}", block.height),
            state.pending_proofs.len() as u32,
            inherited_commitments,
        );

        Proposal {
            block,
            proof,
            leader_id: self.validator.id.clone(),
        }
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
