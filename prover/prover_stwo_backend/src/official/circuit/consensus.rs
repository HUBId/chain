//! BFT consensus circuit enforcing quorum aggregation for block proposals.

use std::collections::HashSet;

use crate::official::air::{
    AirColumn, AirConstraint, AirDefinition, AirExpression, ConstraintDomain,
};
use crate::official::params::{FieldElement, PoseidonHasher, StarkParameters};
use crate::vrf::{VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH};

use super::{string_to_field, CircuitError, ExecutionTrace, StarkCircuit, TraceSegment};

/// Poseidon VRF tuple captured within each consensus witness entry.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ConsensusVrfPoseidonInput {
    pub last_block_header: String,
    pub epoch: u64,
    pub tier_seed: String,
}

/// Full VRF witness information associated with a single validator.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ConsensusVrfWitnessEntry {
    pub randomness: String,
    pub pre_output: String,
    pub proof: String,
    pub public_key: String,
    pub input: ConsensusVrfPoseidonInput,
}

/// Column headers for the consensus summary segment. The first eight entries map
/// directly to fixed public inputs (block metadata and quorum digests) while the
/// remaining names enumerate the VRF outputs, proofs, witness commitments, and
/// reputation tree roots that are exposed as individual public inputs. The four
/// trailing columns track the respective list lengths so the AIR can bind the
/// per-segment multiplicities.
fn summary_columns(witness: &ConsensusWitness) -> Vec<String> {
    let mut columns = vec![
        "block_hash".to_string(),
        "round".to_string(),
        "leader_proposal".to_string(),
        "epoch".to_string(),
        "slot".to_string(),
        "quorum".to_string(),
        "quorum_bitmap_root".to_string(),
        "quorum_signature_root".to_string(),
    ];

    let mut extend_with = |prefix: &str, len: usize| {
        for index in 0..len {
            columns.push(format!("{prefix}_{index}"));
        }
    };

    extend_with("vrf_randomness", witness.vrf_entries.len());
    extend_with("vrf_pre_output", witness.vrf_entries.len());
    extend_with("vrf_proof", witness.vrf_entries.len());
    extend_with("vrf_public_key", witness.vrf_entries.len());
    extend_with("vrf_input_last_block_header", witness.vrf_entries.len());
    extend_with("vrf_input_epoch", witness.vrf_entries.len());
    extend_with("vrf_input_tier_seed", witness.vrf_entries.len());
    extend_with("witness_commitment", witness.witness_commitments.len());
    extend_with("reputation_root", witness.reputation_roots.len());

    columns.push("vrf_output_count".to_string());
    columns.push("vrf_pre_output_count".to_string());
    columns.push("vrf_proof_count".to_string());
    columns.push("vrf_public_key_count".to_string());
    columns.push("vrf_input_count".to_string());
    columns.push("witness_commitment_count".to_string());
    columns.push("reputation_root_count".to_string());
    columns.push("vrf_output_binding".to_string());
    columns.push("vrf_proof_binding".to_string());
    columns.push("witness_commitment_binding".to_string());
    columns.push("reputation_root_binding".to_string());
    columns.push("quorum_bitmap_binding".to_string());
    columns.push("quorum_signature_binding".to_string());

    columns
}

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
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
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
    pub vrf_entries: Vec<ConsensusVrfWitnessEntry>,
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

    fn ensure_hex_with_length(
        value: &str,
        expected_len: usize,
        label: &str,
    ) -> Result<(), CircuitError> {
        let bytes = hex::decode(value).map_err(|err| {
            CircuitError::InvalidWitness(format!("invalid {label} encoding: {err}"))
        })?;
        if bytes.len() != expected_len {
            return Err(CircuitError::ConstraintViolation(format!(
                "{label} must encode {expected_len} bytes"
            )));
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

    fn ensure_vrf_entries(&self) -> Result<(), CircuitError> {
        if self.vrf_entries.is_empty() {
            return Err(CircuitError::ConstraintViolation(
                "consensus witness missing VRF entries".into(),
            ));
        }

        for (index, entry) in self.vrf_entries.iter().enumerate() {
            Self::ensure_hex_with_length(
                &entry.randomness,
                32,
                &format!("vrf entry #{index} randomness"),
            )?;
            Self::ensure_hex_with_length(
                &entry.pre_output,
                VRF_PREOUTPUT_LENGTH,
                &format!("vrf entry #{index} pre-output"),
            )?;
            Self::ensure_hex_with_length(
                &entry.public_key,
                32,
                &format!("vrf entry #{index} public key"),
            )?;
            Self::ensure_hex_with_length(
                &entry.input.last_block_header,
                32,
                &format!("vrf entry #{index} poseidon last block header"),
            )?;
            Self::ensure_hex_with_length(
                &entry.input.tier_seed,
                32,
                &format!("vrf entry #{index} poseidon tier seed"),
            )?;

            let proof_label = format!("vrf entry #{index} proof");
            let proof_bytes = hex::decode(&entry.proof).map_err(|err| {
                CircuitError::InvalidWitness(format!("invalid {proof_label} encoding: {err}"))
            })?;
            if proof_bytes.len() != VRF_PROOF_LENGTH {
                return Err(CircuitError::ConstraintViolation(format!(
                    "{proof_label} must encode {VRF_PROOF_LENGTH} bytes"
                )));
            }

            if entry.input.last_block_header.to_ascii_lowercase()
                != self.block_hash.to_ascii_lowercase()
            {
                return Err(CircuitError::ConstraintViolation(format!(
                    "vrf entry #{index} poseidon last block header must match block hash"
                )));
            }
            if entry.input.epoch != self.epoch {
                return Err(CircuitError::ConstraintViolation(format!(
                    "vrf entry #{index} poseidon epoch mismatch"
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

    /// Materialise the public inputs that the consensus circuit exposes. The
    /// layout matches the backend interface: block metadata, quorum digests,
    /// every VRF output/proof pair, each witness commitment, each reputation
    /// tree root, and finally the counts for those variable-length vectors so
    /// the AIR can cross-check them against the trace segments.
    pub fn public_inputs(
        parameters: &StarkParameters,
        witness: &ConsensusWitness,
    ) -> Vec<FieldElement> {
        let block_hash = string_to_field(parameters, &witness.block_hash);
        let leader_proposal = string_to_field(parameters, &witness.leader_proposal);
        let quorum_bitmap_root = string_to_field(parameters, &witness.quorum_bitmap_root);
        let quorum_signature_root = string_to_field(parameters, &witness.quorum_signature_root);
        let mut inputs = vec![
            block_hash.clone(),
            parameters.element_from_u64(witness.round),
            leader_proposal,
            parameters.element_from_u64(witness.epoch),
            parameters.element_from_u64(witness.slot),
            parameters.element_from_u64(witness.quorum_threshold),
            quorum_bitmap_root.clone(),
            quorum_signature_root.clone(),
        ];

        let mut extend_with = |values: &[String]| {
            for value in values {
                inputs.push(string_to_field(parameters, value));
            }
        };

        for entry in &witness.vrf_entries {
            inputs.push(string_to_field(parameters, &entry.randomness));
        }
        for entry in &witness.vrf_entries {
            inputs.push(string_to_field(parameters, &entry.pre_output));
        }
        for entry in &witness.vrf_entries {
            inputs.push(string_to_field(parameters, &entry.proof));
        }
        for entry in &witness.vrf_entries {
            inputs.push(string_to_field(parameters, &entry.public_key));
        }
        for entry in &witness.vrf_entries {
            inputs.push(string_to_field(parameters, &entry.input.last_block_header));
            inputs.push(parameters.element_from_u64(entry.input.epoch));
            inputs.push(string_to_field(parameters, &entry.input.tier_seed));
        }
        extend_with(&witness.witness_commitments);
        extend_with(&witness.reputation_roots);

        let entry_len = witness.vrf_entries.len() as u64;
        inputs.push(parameters.element_from_u64(entry_len));
        inputs.push(parameters.element_from_u64(entry_len));
        inputs.push(parameters.element_from_u64(entry_len));
        inputs.push(parameters.element_from_u64(entry_len));
        inputs.push(parameters.element_from_u64(entry_len));
        inputs.push(parameters.element_from_u64(witness.witness_commitments.len() as u64));
        inputs.push(parameters.element_from_u64(witness.reputation_roots.len() as u64));

        let hasher = parameters.poseidon_hasher();
        let bindings =
            ConsensusCircuit::compute_binding_values(parameters, &hasher, &block_hash, witness);

        inputs.push(bindings.vrf_output);
        inputs.push(bindings.vrf_proof);
        inputs.push(bindings.witness_commitment);
        inputs.push(bindings.reputation_root);
        inputs.push(bindings.quorum_bitmap);
        inputs.push(bindings.quorum_signature);

        inputs
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
        self.witness.ensure_vrf_entries()?;
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

        let hasher = parameters.poseidon_hasher();
        let block_hash = string_to_field(parameters, &self.witness.block_hash);
        let (vrf_outputs, _vrf_output_binding) = Self::build_binding_segment(
            parameters,
            &hasher,
            &block_hash,
            self.witness
                .vrf_entries
                .iter()
                .map(|entry| entry.randomness.as_str()),
            "vrf_outputs",
            "randomness",
        )?;
        let (vrf_proofs, _vrf_proof_binding) = Self::build_binding_segment(
            parameters,
            &hasher,
            &block_hash,
            self.witness
                .vrf_entries
                .iter()
                .map(|entry| entry.proof.as_str()),
            "vrf_proofs",
            "proof",
        )?;
        let (witness_commitments, _witness_commitment_binding) = Self::build_binding_segment(
            parameters,
            &hasher,
            &block_hash,
            self.witness
                .witness_commitments
                .iter()
                .map(|value| value.as_str()),
            "witness_commitments",
            "commitment",
        )?;
        let (reputation_roots, _reputation_root_binding) = Self::build_binding_segment(
            parameters,
            &hasher,
            &block_hash,
            self.witness
                .reputation_roots
                .iter()
                .map(|value| value.as_str()),
            "reputation_roots",
            "root",
        )?;
        let (quorum_bitmap_binding, _bitmap_final) = Self::build_binding_segment(
            parameters,
            &hasher,
            &block_hash,
            std::iter::once(self.witness.quorum_bitmap_root.as_str()),
            "quorum_bitmap_binding",
            "root",
        )?;
        let (quorum_signature_binding, _signature_final) = Self::build_binding_segment(
            parameters,
            &hasher,
            &block_hash,
            std::iter::once(self.witness.quorum_signature_root.as_str()),
            "quorum_signature_binding",
            "root",
        )?;

        let summary_columns = summary_columns(&self.witness);
        let summary_values = Self::public_inputs(parameters, &self.witness);
        let summary = TraceSegment::new("summary", summary_columns, vec![summary_values])?;

        ExecutionTrace::from_segments(vec![
            pre_votes,
            pre_commits,
            commits,
            vrf_outputs,
            vrf_proofs,
            witness_commitments,
            reputation_roots,
            quorum_bitmap_binding,
            quorum_signature_binding,
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
        let summary_block_hash = AirColumn::new(summary_segment, "block_hash");
        let summary_vrf_output = AirColumn::new(summary_segment, "vrf_output_count");
        let summary_vrf_pre_output = AirColumn::new(summary_segment, "vrf_pre_output_count");
        let summary_vrf_proof = AirColumn::new(summary_segment, "vrf_proof_count");
        let summary_vrf_public_key = AirColumn::new(summary_segment, "vrf_public_key_count");
        let summary_vrf_input = AirColumn::new(summary_segment, "vrf_input_count");
        let summary_witness_commitment =
            AirColumn::new(summary_segment, "witness_commitment_count");
        let summary_reputation_root = AirColumn::new(summary_segment, "reputation_root_count");
        let summary_vrf_output_binding = AirColumn::new(summary_segment, "vrf_output_binding");
        let summary_vrf_proof_binding = AirColumn::new(summary_segment, "vrf_proof_binding");
        let summary_witness_commitment_binding =
            AirColumn::new(summary_segment, "witness_commitment_binding");
        let summary_reputation_root_binding =
            AirColumn::new(summary_segment, "reputation_root_binding");
        let summary_quorum_bitmap_root = AirColumn::new(summary_segment, "quorum_bitmap_root");
        let summary_quorum_signature_root =
            AirColumn::new(summary_segment, "quorum_signature_root");
        let summary_quorum_bitmap_binding =
            AirColumn::new(summary_segment, "quorum_bitmap_binding");
        let summary_quorum_signature_binding =
            AirColumn::new(summary_segment, "quorum_signature_binding");

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
                "summary_vrf_pre_output_count",
                &summary_vrf_pre_output,
                vrf_output_len as u64,
            ),
            (
                "summary_vrf_proof_count",
                &summary_vrf_proof,
                vrf_proof_len as u64,
            ),
            (
                "summary_vrf_public_key_count",
                &summary_vrf_public_key,
                vrf_output_len as u64,
            ),
            (
                "summary_vrf_input_count",
                &summary_vrf_input,
                vrf_output_len as u64,
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

        let count_pairs = [
            (
                "summary_vrf_output_pre_output_count_match",
                &summary_vrf_output,
                &summary_vrf_pre_output,
            ),
            (
                "summary_vrf_output_proof_count_match",
                &summary_vrf_output,
                &summary_vrf_proof,
            ),
            (
                "summary_vrf_output_public_key_count_match",
                &summary_vrf_output,
                &summary_vrf_public_key,
            ),
            (
                "summary_vrf_output_input_count_match",
                &summary_vrf_output,
                &summary_vrf_input,
            ),
        ];
        for (name, left, right) in count_pairs {
            constraints.push(AirConstraint::new(
                name,
                summary_segment,
                ConstraintDomain::FirstRow,
                AirExpression::difference(left.expr(), right.expr()),
            ));
        }

        let mut add_binding_constraints = |segment: &str, summary_binding: &AirColumn| {
            let binding_in = AirColumn::new(segment, "binding_in");
            let binding_out = AirColumn::new(segment, "binding_out");
            constraints.push(AirConstraint::new(
                &format!("{segment}_binding_initial"),
                segment,
                ConstraintDomain::FirstRow,
                AirExpression::difference(binding_in.expr(), summary_block_hash.expr()),
            ));
            constraints.push(AirConstraint::new(
                &format!("{segment}_binding_links"),
                segment,
                ConstraintDomain::Range {
                    start: 1,
                    end: None,
                },
                AirExpression::difference(binding_in.expr(), binding_out.shifted(-1)),
            ));
            constraints.push(AirConstraint::new(
                &format!("{segment}_binding_summary"),
                segment,
                ConstraintDomain::LastRow,
                AirExpression::difference(binding_out.expr(), summary_binding.expr()),
            ));
        };

        add_binding_constraints("vrf_outputs", &summary_vrf_output_binding);
        add_binding_constraints("vrf_proofs", &summary_vrf_proof_binding);
        add_binding_constraints("witness_commitments", &summary_witness_commitment_binding);
        add_binding_constraints("reputation_roots", &summary_reputation_root_binding);

        for (segment, summary_root, summary_binding) in [
            (
                "quorum_bitmap_binding",
                &summary_quorum_bitmap_root,
                &summary_quorum_bitmap_binding,
            ),
            (
                "quorum_signature_binding",
                &summary_quorum_signature_root,
                &summary_quorum_signature_binding,
            ),
        ] {
            let root_column = AirColumn::new(segment, "root");
            let binding_in = AirColumn::new(segment, "binding_in");
            let binding_out = AirColumn::new(segment, "binding_out");
            constraints.push(AirConstraint::new(
                &format!("{segment}_root_matches"),
                segment,
                ConstraintDomain::AllRows,
                AirExpression::difference(root_column.expr(), summary_root.expr()),
            ));
            constraints.push(AirConstraint::new(
                &format!("{segment}_binding_initial"),
                segment,
                ConstraintDomain::FirstRow,
                AirExpression::difference(binding_in.expr(), summary_block_hash.expr()),
            ));
            constraints.push(AirConstraint::new(
                &format!("{segment}_binding_summary"),
                segment,
                ConstraintDomain::LastRow,
                AirExpression::difference(binding_out.expr(), summary_binding.expr()),
            ));
        }

        Ok(AirDefinition::new(constraints))
    }
}

pub(crate) struct ConsensusBindingValues {
    pub(crate) vrf_output: FieldElement,
    pub(crate) vrf_proof: FieldElement,
    pub(crate) witness_commitment: FieldElement,
    pub(crate) reputation_root: FieldElement,
    pub(crate) quorum_bitmap: FieldElement,
    pub(crate) quorum_signature: FieldElement,
}

impl ConsensusCircuit {
    pub(crate) fn compute_binding_values(
        parameters: &StarkParameters,
        hasher: &PoseidonHasher,
        block_hash: &FieldElement,
        witness: &ConsensusWitness,
    ) -> ConsensusBindingValues {
        let vrf_output = Self::fold_binding(
            parameters,
            hasher,
            block_hash,
            witness
                .vrf_entries
                .iter()
                .map(|entry| entry.randomness.as_str()),
        );
        let vrf_proof = Self::fold_binding(
            parameters,
            hasher,
            block_hash,
            witness.vrf_entries.iter().map(|entry| entry.proof.as_str()),
        );
        let witness_commitment = Self::fold_binding(
            parameters,
            hasher,
            block_hash,
            witness
                .witness_commitments
                .iter()
                .map(|value| value.as_str()),
        );
        let reputation_root = Self::fold_binding(
            parameters,
            hasher,
            block_hash,
            witness.reputation_roots.iter().map(|value| value.as_str()),
        );
        let quorum_bitmap = Self::fold_binding(
            parameters,
            hasher,
            block_hash,
            std::iter::once(witness.quorum_bitmap_root.as_str()),
        );
        let quorum_signature = Self::fold_binding(
            parameters,
            hasher,
            block_hash,
            std::iter::once(witness.quorum_signature_root.as_str()),
        );

        ConsensusBindingValues {
            vrf_output,
            vrf_proof,
            witness_commitment,
            reputation_root,
            quorum_bitmap,
            quorum_signature,
        }
    }

    fn fold_binding<'a, I>(
        parameters: &StarkParameters,
        hasher: &PoseidonHasher,
        block_hash: &FieldElement,
        values: I,
    ) -> FieldElement
    where
        I: IntoIterator<Item = &'a str>,
    {
        let zero = FieldElement::zero(parameters.modulus());
        let mut accumulator = block_hash.clone();
        for value in values {
            let element = string_to_field(parameters, value);
            accumulator = hasher.hash(&[accumulator, element, zero.clone()]);
        }
        accumulator
    }

    fn build_binding_segment<'a, I>(
        parameters: &StarkParameters,
        hasher: &PoseidonHasher,
        block_hash: &FieldElement,
        values: I,
        name: &str,
        value_column: &str,
    ) -> Result<(TraceSegment, FieldElement), CircuitError>
    where
        I: IntoIterator<Item = &'a str>,
    {
        let zero = FieldElement::zero(parameters.modulus());
        let mut accumulator = block_hash.clone();
        let mut rows = Vec::new();
        for value in values {
            let element = string_to_field(parameters, value);
            let next = hasher.hash(&[accumulator.clone(), element.clone(), zero.clone()]);
            rows.push(vec![element, accumulator.clone(), next.clone()]);
            accumulator = next;
        }
        let segment = TraceSegment::new(
            name,
            vec![
                value_column.to_string(),
                "binding_in".to_string(),
                "binding_out".to_string(),
            ],
            rows,
        )?;
        Ok((segment, accumulator))
    }
}

#[cfg(test)]
mod tests {
    use super::{ConsensusVrfPoseidonInput, ConsensusVrfWitnessEntry, ConsensusWitness, VotePower};
    use crate::official::circuit::CircuitError;
    use crate::vrf::{VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH};

    fn sample_vote() -> VotePower {
        VotePower {
            voter: "validator".into(),
            weight: 1,
        }
    }

    fn sample_vrf_entry() -> ConsensusVrfWitnessEntry {
        ConsensusVrfWitnessEntry {
            randomness: "aa".repeat(32),
            pre_output: "bb".repeat(VRF_PREOUTPUT_LENGTH),
            proof: "cc".repeat(VRF_PROOF_LENGTH),
            public_key: "dd".repeat(32),
            input: ConsensusVrfPoseidonInput {
                last_block_header: "11".repeat(32),
                epoch: 7,
                tier_seed: "ee".repeat(32),
            },
        }
    }

    fn sample_witness() -> ConsensusWitness {
        ConsensusWitness {
            block_hash: "11".repeat(32),
            round: 0,
            epoch: 7,
            slot: 3,
            leader_proposal: "11".repeat(32),
            quorum_threshold: 1,
            pre_votes: vec![sample_vote()],
            pre_commits: vec![sample_vote()],
            commit_votes: vec![sample_vote()],
            quorum_bitmap_root: "22".repeat(32),
            quorum_signature_root: "33".repeat(32),
            vrf_entries: vec![sample_vrf_entry()],
            witness_commitments: vec!["44".repeat(32)],
            reputation_roots: vec!["55".repeat(32)],
        }
    }

    #[test]
    fn vrf_entries_validate_on_happy_path() {
        let witness = sample_witness();
        assert!(witness.ensure_vrf_entries().is_ok());
    }

    #[test]
    fn vrf_entries_reject_invalid_randomness_length() {
        let mut witness = sample_witness();
        witness.vrf_entries[0].randomness = "aa".repeat(31);
        assert!(matches!(
            witness.ensure_vrf_entries(),
            Err(CircuitError::ConstraintViolation(message))
                if message.contains("randomness")
        ));
    }

    #[test]
    fn vrf_entries_reject_epoch_mismatch() {
        let mut witness = sample_witness();
        witness.vrf_entries[0].input.epoch = witness.epoch + 1;
        assert!(matches!(
            witness.ensure_vrf_entries(),
            Err(CircuitError::ConstraintViolation(message))
                if message.contains("epoch mismatch")
        ));
    }

    #[test]
    fn vrf_entries_reject_proof_length() {
        let mut witness = sample_witness();
        witness.vrf_entries[0].proof = "cc".repeat(VRF_PROOF_LENGTH - 1);
        assert!(matches!(
            witness.ensure_vrf_entries(),
            Err(CircuitError::ConstraintViolation(message))
                if message.contains("proof")
        ));
    }

    #[test]
    fn vrf_entries_reject_block_hash_mismatch() {
        let mut witness = sample_witness();
        witness.vrf_entries[0].input.last_block_header = "ff".repeat(32);
        assert!(matches!(
            witness.ensure_vrf_entries(),
            Err(CircuitError::ConstraintViolation(message))
                if message.contains("block hash")
        ));
    }

    #[test]
    fn vrf_entries_reject_pre_output_length() {
        let mut witness = sample_witness();
        witness.vrf_entries[0].pre_output = "bb".repeat(VRF_PREOUTPUT_LENGTH - 1);
        assert!(matches!(
            witness.ensure_vrf_entries(),
            Err(CircuitError::ConstraintViolation(message))
                if message.contains("pre-output")
        ));
    }

    #[test]
    fn vrf_entries_reject_public_key_length() {
        let mut witness = sample_witness();
        witness.vrf_entries[0].public_key = "dd".repeat(31);
        assert!(matches!(
            witness.ensure_vrf_entries(),
            Err(CircuitError::ConstraintViolation(message))
                if message.contains("public key")
        ));
    }
}
