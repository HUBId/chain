//! BFT consensus circuit enforcing quorum aggregation for block proposals.

use std::collections::HashSet;

use crate::stwo::air::{AirColumn, AirConstraint, AirDefinition, AirExpression, ConstraintDomain};
use crate::stwo::params::StarkParameters;

use super::{CircuitError, ExecutionTrace, StarkCircuit, TraceSegment, string_to_field};

/// Vote weight associated with a consensus participant.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct VotePower {
    pub voter: String,
    pub weight: u64,
}

impl VotePower {
    fn ensure_valid(&self) -> Result<(), CircuitError> {
        if self.weight == 0 {
            return Err(CircuitError::ConstraintViolation(
                "vote weight must be non-zero".into(),
            ));
        }
        if self.voter.is_empty() {
            return Err(CircuitError::ConstraintViolation(
                "vote must include voter address".into(),
            ));
        }
        Ok(())
    }
}

/// Witness describing aggregated consensus votes for a block proposal.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ConsensusWitness {
    pub block_hash: String,
    pub round: u64,
    pub leader_proposal: String,
    pub quorum_threshold: u64,
    pub pre_votes: Vec<VotePower>,
    pub pre_commits: Vec<VotePower>,
    pub commit_votes: Vec<VotePower>,
}

impl ConsensusWitness {
    fn ensure_hex(hash: &str) -> Result<(), CircuitError> {
        let bytes = hex::decode(hash)
            .map_err(|err| CircuitError::InvalidWitness(format!("invalid hash encoding: {err}")))?;
        if bytes.len() != 32 {
            return Err(CircuitError::ConstraintViolation(
                "hash must encode 32 bytes".into(),
            ));
        }
        Ok(())
    }

    fn ensure_votes(&self, votes: &[VotePower], label: &str) -> Result<u128, CircuitError> {
        if votes.is_empty() {
            return Err(CircuitError::ConstraintViolation(format!(
                "consensus witness missing {label} votes"
            )));
        }
        let mut seen = HashSet::new();
        let mut total: u128 = 0;
        for vote in votes {
            vote.ensure_valid()?;
            if !seen.insert(vote.voter.clone()) {
                return Err(CircuitError::ConstraintViolation(format!(
                    "validator '{}' submitted duplicate {label} vote",
                    vote.voter
                )));
            }
            total = total
                .checked_add(vote.weight as u128)
                .ok_or_else(|| CircuitError::ConstraintViolation("vote weight overflow".into()))?;
        }
        Ok(total)
    }

    fn verify_quorum(&self, total: u128, label: &str) -> Result<(), CircuitError> {
        if total < self.quorum_threshold as u128 {
            return Err(CircuitError::ConstraintViolation(format!(
                "insufficient {label} voting power for quorum"
            )));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct ConsensusCircuit {
    pub witness: ConsensusWitness,
}

impl ConsensusCircuit {
    pub fn new(witness: ConsensusWitness) -> Self {
        Self { witness }
    }

    fn build_vote_segment(
        parameters: &StarkParameters,
        name: &str,
        votes: &[VotePower],
    ) -> Result<TraceSegment, CircuitError> {
        let mut rows = Vec::with_capacity(votes.len());
        let mut cumulative: u128 = 0;
        for vote in votes {
            cumulative += vote.weight as u128;
            rows.push(vec![
                string_to_field(parameters, &vote.voter),
                parameters.element_from_u64(vote.weight),
                parameters.element_from_u128(cumulative),
            ]);
        }
        TraceSegment::new(
            name,
            vec![
                "voter".to_string(),
                "weight".to_string(),
                "cumulative".to_string(),
            ],
            rows,
        )
    }
}

impl StarkCircuit for ConsensusCircuit {
    fn name(&self) -> &'static str {
        "consensus"
    }

    fn evaluate_constraints(&self) -> Result<(), CircuitError> {
        ConsensusWitness::ensure_hex(&self.witness.block_hash)?;
        ConsensusWitness::ensure_hex(&self.witness.leader_proposal)?;
        if self.witness.leader_proposal != self.witness.block_hash {
            return Err(CircuitError::ConstraintViolation(
                "leader proposal must match block hash".into(),
            ));
        }
        if self.witness.quorum_threshold == 0 {
            return Err(CircuitError::ConstraintViolation(
                "quorum threshold must be positive".into(),
            ));
        }
        let pre_vote_total = self
            .witness
            .ensure_votes(&self.witness.pre_votes, "pre-vote")?;
        let pre_commit_total = self
            .witness
            .ensure_votes(&self.witness.pre_commits, "pre-commit")?;
        let commit_total = self
            .witness
            .ensure_votes(&self.witness.commit_votes, "commit")?;

        self.witness.verify_quorum(pre_vote_total, "pre-vote")?;
        self.witness.verify_quorum(pre_commit_total, "pre-commit")?;
        self.witness.verify_quorum(commit_total, "commit")?;

        if commit_total < pre_commit_total {
            return Err(CircuitError::ConstraintViolation(
                "commit weight cannot fall below pre-commit weight".into(),
            ));
        }

        Ok(())
    }

    fn generate_trace(&self, parameters: &StarkParameters) -> Result<ExecutionTrace, CircuitError> {
        let pre_votes = Self::build_vote_segment(parameters, "pre_votes", &self.witness.pre_votes)?;
        let pre_commits =
            Self::build_vote_segment(parameters, "pre_commits", &self.witness.pre_commits)?;
        let commits = Self::build_vote_segment(parameters, "commits", &self.witness.commit_votes)?;

        let pre_vote_total: u128 = self
            .witness
            .pre_votes
            .iter()
            .map(|vote| vote.weight as u128)
            .sum();
        let pre_commit_total: u128 = self
            .witness
            .pre_commits
            .iter()
            .map(|vote| vote.weight as u128)
            .sum();
        let commit_total: u128 = self
            .witness
            .commit_votes
            .iter()
            .map(|vote| vote.weight as u128)
            .sum();

        let summary = TraceSegment::new(
            "summary",
            vec![
                "block_hash".to_string(),
                "round".to_string(),
                "quorum".to_string(),
                "pre_vote_total".to_string(),
                "pre_commit_total".to_string(),
                "commit_total".to_string(),
            ],
            vec![vec![
                string_to_field(parameters, &self.witness.block_hash),
                parameters.element_from_u64(self.witness.round),
                parameters.element_from_u64(self.witness.quorum_threshold),
                parameters.element_from_u128(pre_vote_total),
                parameters.element_from_u128(pre_commit_total),
                parameters.element_from_u128(commit_total),
            ]],
        )?;

        ExecutionTrace::from_segments(vec![pre_votes, pre_commits, commits, summary])
    }

    fn define_air(
        &self,
        _parameters: &StarkParameters,
        _trace: &ExecutionTrace,
    ) -> Result<AirDefinition, CircuitError> {
        let mut constraints = Vec::new();

        let segments = ["pre_votes", "pre_commits", "commits"];
        for segment in segments {
            let weight = AirColumn::new(segment, "weight");
            let cumulative = AirColumn::new(segment, "cumulative");
            constraints.push(AirConstraint::new(
                &format!("{segment}_initial"),
                segment,
                ConstraintDomain::FirstRow,
                AirExpression::difference(cumulative.expr(), weight.expr()),
            ));
            constraints.push(AirConstraint::new(
                &format!("{segment}_running_sum"),
                segment,
                ConstraintDomain::Range {
                    start: 1,
                    end: None,
                },
                AirExpression::difference(
                    cumulative.expr(),
                    AirExpression::sum(vec![cumulative.shifted(-1), weight.expr()]),
                ),
            ));
        }

        Ok(AirDefinition::new(constraints))
    }
}
