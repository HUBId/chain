//! BFT consensus circuit enforcing quorum aggregation for block proposals.

use std::collections::HashSet;

use crate::official::air::{
    AirColumn, AirConstraint, AirDefinition, AirExpression, ConstraintDomain,
};
use crate::official::params::{FieldElement, StarkParameters};

use super::{string_to_field, CircuitError, ExecutionTrace, StarkCircuit, TraceSegment};

/// Number of public inputs emitted by the consensus circuit.
pub const CONSENSUS_PUBLIC_INPUT_WIDTH: usize = 15;

const SUMMARY_COLUMNS: [&str; CONSENSUS_PUBLIC_INPUT_WIDTH] = [
    "block_hash",
    "round",
    "leader_proposal",
    "epoch",
    "slot",
    "quorum",
    "quorum_bitmap_root",
    "quorum_signature_root",
    "pre_vote_total",
    "pre_commit_total",
    "commit_total",
    "vrf_output_count",
    "vrf_proof_count",
    "witness_commitment_count",
    "reputation_root_count",
];

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
    pub epoch: u64,
    pub slot: u64,
    pub leader_proposal: String,
    pub quorum_threshold: u64,
    pub pre_votes: Vec<VotePower>,
    pub pre_commits: Vec<VotePower>,
    pub commit_votes: Vec<VotePower>,
    pub quorum_bitmap_root: String,
    pub quorum_signature_root: String,
    #[serde(default)]
    pub vrf_outputs: Vec<String>,
    #[serde(default)]
    pub vrf_proofs: Vec<String>,
    #[serde(default)]
    pub witness_commitments: Vec<String>,
    #[serde(default)]
    pub reputation_roots: Vec<String>,
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

    fn ensure_digest_set(&self, label: &str, values: &[String]) -> Result<(), CircuitError> {
        if values.is_empty() {
            return Err(CircuitError::ConstraintViolation(format!(
                "{label} set cannot be empty"
            )));
        }
        for value in values {
            Self::ensure_hex(value).map_err(|err| match err {
                CircuitError::InvalidWitness(message) => {
                    CircuitError::InvalidWitness(format!("{label}: {message}"))
                }
                CircuitError::ConstraintViolation(message) => {
                    CircuitError::ConstraintViolation(format!("{label}: {message}"))
                }
                other => other,
            })?;
        }
        Ok(())
    }

    fn ensure_vrf_proofs(&self) -> Result<(), CircuitError> {
        if self.vrf_outputs.is_empty() {
            return Err(CircuitError::ConstraintViolation(
                "consensus witness missing VRF outputs".into(),
            ));
        }
        if self.vrf_proofs.is_empty() {
            return Err(CircuitError::ConstraintViolation(
                "consensus witness missing VRF proofs".into(),
            ));
        }
        if self.vrf_outputs.len() != self.vrf_proofs.len() {
            return Err(CircuitError::ConstraintViolation(
                "vrf output/proof count mismatch".into(),
            ));
        }
        for (index, proof) in self.vrf_proofs.iter().enumerate() {
            let bytes = hex::decode(proof).map_err(|err| {
                CircuitError::InvalidWitness(format!("invalid vrf proof #{index} encoding: {err}"))
            })?;
            if bytes.len() != crate::vrf::VRF_PROOF_LENGTH {
                return Err(CircuitError::ConstraintViolation(format!(
                    "vrf proof #{index} must encode {} bytes",
                    crate::vrf::VRF_PROOF_LENGTH
                )));
            }
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

    fn compute_vote_totals(witness: &ConsensusWitness) -> (u128, u128, u128) {
        let pre_vote_total = witness
            .pre_votes
            .iter()
            .map(|vote| vote.weight as u128)
            .sum();
        let pre_commit_total = witness
            .pre_commits
            .iter()
            .map(|vote| vote.weight as u128)
            .sum();
        let commit_total = witness
            .commit_votes
            .iter()
            .map(|vote| vote.weight as u128)
            .sum();
        (pre_vote_total, pre_commit_total, commit_total)
    }

    pub fn public_inputs(
        parameters: &StarkParameters,
        witness: &ConsensusWitness,
    ) -> Vec<FieldElement> {
        let (pre_vote_total, pre_commit_total, commit_total) = Self::compute_vote_totals(witness);
        vec![
            string_to_field(parameters, &witness.block_hash),
            parameters.element_from_u64(witness.round),
            string_to_field(parameters, &witness.leader_proposal),
            parameters.element_from_u64(witness.epoch),
            parameters.element_from_u64(witness.slot),
            parameters.element_from_u64(witness.quorum_threshold),
            string_to_field(parameters, &witness.quorum_bitmap_root),
            string_to_field(parameters, &witness.quorum_signature_root),
            parameters.element_from_u128(pre_vote_total),
            parameters.element_from_u128(pre_commit_total),
            parameters.element_from_u128(commit_total),
            parameters.element_from_u64(witness.vrf_outputs.len() as u64),
            parameters.element_from_u64(witness.vrf_proofs.len() as u64),
            parameters.element_from_u64(witness.witness_commitments.len() as u64),
            parameters.element_from_u64(witness.reputation_roots.len() as u64),
        ]
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
        ConsensusWitness::ensure_hex(&self.witness.quorum_bitmap_root)?;
        ConsensusWitness::ensure_hex(&self.witness.quorum_signature_root)?;
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
        self.witness
            .ensure_digest_set("vrf output", &self.witness.vrf_outputs)?;
        self.witness.ensure_vrf_proofs()?;
        self.witness
            .ensure_digest_set("witness commitment", &self.witness.witness_commitments)?;
        self.witness
            .ensure_digest_set("reputation root", &self.witness.reputation_roots)?;

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

        let (pre_vote_total, pre_commit_total, commit_total) =
            Self::compute_vote_totals(&self.witness);

        let vrf_outputs = TraceSegment::new(
            "vrf_outputs",
            vec!["digest".to_string()],
            self.witness
                .vrf_outputs
                .iter()
                .map(|value| vec![string_to_field(parameters, value)])
                .collect(),
        )?;
        let vrf_proofs = TraceSegment::new(
            "vrf_proofs",
            vec!["proof".to_string()],
            self.witness
                .vrf_proofs
                .iter()
                .map(|value| vec![string_to_field(parameters, value)])
                .collect(),
        )?;
        let witness_commitments = TraceSegment::new(
            "witness_commitments",
            vec!["commitment".to_string()],
            self.witness
                .witness_commitments
                .iter()
                .map(|value| vec![string_to_field(parameters, value)])
                .collect(),
        )?;
        let reputation_roots = TraceSegment::new(
            "reputation_roots",
            vec!["root".to_string()],
            self.witness
                .reputation_roots
                .iter()
                .map(|value| vec![string_to_field(parameters, value)])
                .collect(),
        )?;

        let summary = TraceSegment::new(
            "summary",
            SUMMARY_COLUMNS
                .iter()
                .map(|column| column.to_string())
                .collect(),
            vec![Self::public_inputs(parameters, &self.witness)],
        )?;

        ExecutionTrace::from_segments(vec![
            pre_votes,
            pre_commits,
            commits,
            vrf_outputs,
            vrf_proofs,
            witness_commitments,
            reputation_roots,
            summary,
        ])
    }

    fn define_air(
        &self,
        parameters: &StarkParameters,
        trace: &ExecutionTrace,
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

        let summary_segment = "summary";
        let summary_vrf_output = AirColumn::new(summary_segment, "vrf_output_count");
        let summary_vrf_proof = AirColumn::new(summary_segment, "vrf_proof_count");
        let summary_witness_commitment =
            AirColumn::new(summary_segment, "witness_commitment_count");
        let summary_reputation_root = AirColumn::new(summary_segment, "reputation_root_count");

        let vrf_output_len = trace
            .segments
            .iter()
            .find(|segment| segment.name == "vrf_outputs")
            .map(|segment| segment.rows.len())
            .unwrap_or_default();
        let vrf_proof_len = trace
            .segments
            .iter()
            .find(|segment| segment.name == "vrf_proofs")
            .map(|segment| segment.rows.len())
            .unwrap_or_default();
        let witness_commitment_len = trace
            .segments
            .iter()
            .find(|segment| segment.name == "witness_commitments")
            .map(|segment| segment.rows.len())
            .unwrap_or_default();
        let reputation_root_len = trace
            .segments
            .iter()
            .find(|segment| segment.name == "reputation_roots")
            .map(|segment| segment.rows.len())
            .unwrap_or_default();

        let expected_counts = [
            (
                "summary_vrf_output_count",
                &summary_vrf_output,
                vrf_output_len as u64,
            ),
            (
                "summary_vrf_proof_count",
                &summary_vrf_proof,
                vrf_proof_len as u64,
            ),
            (
                "summary_witness_commitment_count",
                &summary_witness_commitment,
                witness_commitment_len as u64,
            ),
            (
                "summary_reputation_root_count",
                &summary_reputation_root,
                reputation_root_len as u64,
            ),
        ];

        for (name, column, value) in expected_counts {
            constraints.push(AirConstraint::new(
                name,
                summary_segment,
                ConstraintDomain::FirstRow,
                AirExpression::difference(
                    column.expr(),
                    AirExpression::constant(parameters.element_from_u64(value)),
                ),
            ));
        }

        constraints.push(AirConstraint::new(
            "summary_vrf_counts_match",
            summary_segment,
            ConstraintDomain::FirstRow,
            AirExpression::difference(summary_vrf_output.expr(), summary_vrf_proof.expr()),
        ));

        Ok(AirDefinition::new(constraints))
    }
}
