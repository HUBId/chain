//! BFT consensus circuit enforcing quorum aggregation for block proposals.

use std::{
    cell::{Ref, RefCell},
    collections::HashSet,
    convert::{TryFrom, TryInto},
};

use rpp_crypto_vrf::{PoseidonVrfInput, VrfOutput, VrfPublicKey, POSEIDON_VRF_DOMAIN};
use schnorrkel::{
    context::signing_context,
    vrf::{VRFPreOut, VRFProof},
};

use crate::official::air::{
    AirColumn, AirConstraint, AirDefinition, AirExpression, ConstraintDomain,
};
use crate::official::params::{FieldElement, PoseidonHasher, StarkParameters};
use crate::vrf::{VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH};

use super::{string_to_field, CircuitError, ExecutionTrace, StarkCircuit, TraceSegment};

const VRF_RANDOMNESS_CONTEXT: &[u8] = b"chain.vrf.randomness";

#[derive(Clone, Debug)]
pub(crate) struct ConsensusVerifiedVrfOutput {
    pub(crate) output: VrfOutput,
    pub(crate) derived_randomness: [u8; 32],
    pub(crate) poseidon_digest: [u8; 32],
}

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
/// reputation tree roots that are exposed as individual public inputs. The final
/// columns track the respective list lengths and Poseidon bindings so the AIR can
/// bind the per-segment multiplicities.
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

    for index in 0..witness.vrf_entries.len() {
        columns.push(format!("vrf_randomness_{index}"));
        columns.push(format!("vrf_randomness_derived_{index}"));
        columns.push(format!("vrf_preoutput_{index}"));
        columns.push(format!("vrf_proof_{index}"));
        columns.push(format!("vrf_public_key_{index}"));
        columns.push(format!("vrf_poseidon_digest_{index}"));
        columns.push(format!("vrf_input_last_block_{index}"));
        columns.push(format!("vrf_input_epoch_{index}"));
        columns.push(format!("vrf_input_tier_seed_{index}"));
    }

    let mut extend_with = |prefix: &str, len: usize| {
        for index in 0..len {
            columns.push(format!("{prefix}_{index}"));
        }
    };

    extend_with("witness_commitment", witness.witness_commitments.len());
    extend_with("reputation_root", witness.reputation_roots.len());

    columns.push("vrf_entry_count".to_string());
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

    pub(crate) fn ensure_vrf_entries(&self) -> Result<(), CircuitError> {
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

pub(crate) fn parse_vrf_entries(
    witness: &ConsensusWitness,
) -> Result<Vec<ConsensusVerifiedVrfOutput>, CircuitError> {
    if witness.vrf_entries.is_empty() {
        return Err(CircuitError::ConstraintViolation(
            "consensus witness missing VRF entries".into(),
        ));
    }

    let block_hash_lower = witness.block_hash.to_ascii_lowercase();
    let mut outputs = Vec::with_capacity(witness.vrf_entries.len());

    for (index, entry) in witness.vrf_entries.iter().enumerate() {
        let randomness_bytes = hex::decode(&entry.randomness).map_err(|err| {
            CircuitError::InvalidWitness(format!(
                "invalid vrf entry #{index} randomness encoding: {err}"
            ))
        })?;
        if randomness_bytes.len() != 32 {
            return Err(CircuitError::ConstraintViolation(format!(
                "vrf entry #{index} randomness must encode 32 bytes"
            )));
        }
        let randomness: [u8; 32] = randomness_bytes.as_slice().try_into().map_err(|_| {
            CircuitError::ConstraintViolation(format!(
                "vrf entry #{index} randomness must encode 32 bytes"
            ))
        })?;

        let pre_output_bytes = hex::decode(&entry.pre_output).map_err(|err| {
            CircuitError::InvalidWitness(format!(
                "invalid vrf entry #{index} pre-output encoding: {err}"
            ))
        })?;
        if pre_output_bytes.len() != VRF_PREOUTPUT_LENGTH {
            return Err(CircuitError::ConstraintViolation(format!(
                "vrf entry #{index} pre-output must encode {VRF_PREOUTPUT_LENGTH} bytes"
            )));
        }
        let pre_output_array = {
            let array: [u8; VRF_PREOUTPUT_LENGTH] =
                pre_output_bytes.as_slice().try_into().map_err(|_| {
                    CircuitError::ConstraintViolation(format!(
                        "vrf entry #{index} pre-output must encode {VRF_PREOUTPUT_LENGTH} bytes"
                    ))
                })?;
            let pre_output = VRFPreOut(array);
            let VRFPreOut(array) = pre_output;
            array
        };

        let proof_bytes = hex::decode(&entry.proof).map_err(|err| {
            CircuitError::InvalidWitness(format!(
                "invalid vrf entry #{index} proof encoding: {err}"
            ))
        })?;
        if proof_bytes.len() != VRF_PROOF_LENGTH {
            return Err(CircuitError::ConstraintViolation(format!(
                "vrf entry #{index} proof must encode {VRF_PROOF_LENGTH} bytes"
            )));
        }
        let proof_array: [u8; VRF_PROOF_LENGTH] =
            proof_bytes.as_slice().try_into().map_err(|_| {
                CircuitError::ConstraintViolation(format!(
                    "vrf entry #{index} proof must encode {VRF_PROOF_LENGTH} bytes"
                ))
            })?;
        let proof = VRFProof::from_bytes(&proof_array).map_err(|err| {
            CircuitError::ConstraintViolation(format!("vrf entry #{index} proof is invalid: {err}"))
        })?;

        let public_key_bytes = hex::decode(&entry.public_key).map_err(|err| {
            CircuitError::InvalidWitness(format!(
                "invalid vrf entry #{index} public key encoding: {err}"
            ))
        })?;
        if public_key_bytes.len() != 32 {
            return Err(CircuitError::ConstraintViolation(format!(
                "vrf entry #{index} public key must encode 32 bytes"
            )));
        }
        let public_key_array: [u8; 32] = public_key_bytes.as_slice().try_into().map_err(|_| {
            CircuitError::ConstraintViolation(format!(
                "vrf entry #{index} public key must encode 32 bytes"
            ))
        })?;
        let public_key = VrfPublicKey::try_from(public_key_array).map_err(|err| {
            CircuitError::ConstraintViolation(format!(
                "vrf entry #{index} public key bytes are invalid: {err}"
            ))
        })?;

        let last_block_bytes = hex::decode(&entry.input.last_block_header).map_err(|err| {
            CircuitError::InvalidWitness(format!(
                "invalid vrf entry #{index} poseidon last block header encoding: {err}"
            ))
        })?;
        if last_block_bytes.len() != 32 {
            return Err(CircuitError::ConstraintViolation(format!(
                "vrf entry #{index} poseidon last block header must encode 32 bytes"
            )));
        }
        if entry.input.last_block_header.to_ascii_lowercase() != block_hash_lower {
            return Err(CircuitError::ConstraintViolation(format!(
                "vrf entry #{index} poseidon last block header must match block hash"
            )));
        }
        let last_block_header: [u8; 32] = last_block_bytes.as_slice().try_into().map_err(|_| {
            CircuitError::ConstraintViolation(format!(
                "vrf entry #{index} poseidon last block header must encode 32 bytes"
            ))
        })?;

        if entry.input.epoch != witness.epoch {
            return Err(CircuitError::ConstraintViolation(format!(
                "vrf entry #{index} poseidon epoch mismatch"
            )));
        }

        let tier_seed_bytes = hex::decode(&entry.input.tier_seed).map_err(|err| {
            CircuitError::InvalidWitness(format!(
                "invalid vrf entry #{index} poseidon tier seed encoding: {err}"
            ))
        })?;
        if tier_seed_bytes.len() != 32 {
            return Err(CircuitError::ConstraintViolation(format!(
                "vrf entry #{index} poseidon tier seed must encode 32 bytes"
            )));
        }
        let tier_seed: [u8; 32] = tier_seed_bytes.as_slice().try_into().map_err(|_| {
            CircuitError::ConstraintViolation(format!(
                "vrf entry #{index} poseidon tier seed must encode 32 bytes"
            ))
        })?;

        let poseidon_input = PoseidonVrfInput::new(last_block_header, entry.input.epoch, tier_seed);
        let digest = poseidon_input.poseidon_digest_bytes();
        let context = signing_context(POSEIDON_VRF_DOMAIN);
        let pre_output = VRFPreOut(pre_output_array);
        let (inout, _) = public_key
            .as_public_key()
            .vrf_verify(context.bytes(&digest), &pre_output, &proof)
            .map_err(|err| {
                CircuitError::ConstraintViolation(format!(
                    "vrf entry #{index} verification backend error: {err}"
                ))
            })?;
        let derived_randomness = inout.make_bytes(VRF_RANDOMNESS_CONTEXT);
        if derived_randomness != randomness {
            return Err(CircuitError::ConstraintViolation(format!(
                "vrf entry #{index} randomness mismatch"
            )));
        }
        let VRFPreOut(pre_output_array) = pre_output;

        let output = VrfOutput {
            randomness,
            preoutput: pre_output_array,
            proof: proof_array,
        };

        outputs.push(ConsensusVerifiedVrfOutput {
            output,
            derived_randomness,
            poseidon_digest: digest,
        });
    }

    Ok(outputs)
}

#[derive(Debug)]
pub struct ConsensusCircuit {
    pub witness: ConsensusWitness,
    verified_outputs: RefCell<Vec<ConsensusVerifiedVrfOutput>>,
}

impl ConsensusCircuit {
    pub fn new(witness: ConsensusWitness) -> Self {
        Self {
            witness,
            verified_outputs: RefCell::new(Vec::new()),
        }
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
    ) -> Result<Vec<FieldElement>, CircuitError> {
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

        let verified_outputs = parse_vrf_entries(witness)?;
        if witness.vrf_entries.len() != verified_outputs.len() {
            return Err(CircuitError::ConstraintViolation(
                "witness VRF entries and verified outputs differ".into(),
            ));
        }

        let mut extend_with = |values: &[String]| {
            for value in values {
                inputs.push(string_to_field(parameters, value));
            }
        };

        for (entry, output) in witness.vrf_entries.iter().zip(verified_outputs.iter()) {
            inputs.push(parameters.element_from_bytes(&output.output.randomness));
            inputs.push(parameters.element_from_bytes(&output.derived_randomness));
            inputs.push(parameters.element_from_bytes(&output.output.preoutput));
            inputs.push(parameters.element_from_bytes(&output.output.proof));
            let public_key_field = string_to_field(parameters, &entry.public_key);
            let last_block_field = string_to_field(parameters, &entry.input.last_block_header);
            let epoch_field = parameters.element_from_u64(entry.input.epoch);
            let tier_seed_field = string_to_field(parameters, &entry.input.tier_seed);

            inputs.push(public_key_field);
            inputs.push(parameters.element_from_bytes(&output.poseidon_digest));
            inputs.push(last_block_field);
            inputs.push(epoch_field);
            inputs.push(tier_seed_field);
        }
        extend_with(&witness.witness_commitments);
        extend_with(&witness.reputation_roots);

        let entry_len = witness.vrf_entries.len() as u64;
        inputs.push(parameters.element_from_u64(entry_len));
        inputs.push(parameters.element_from_u64(witness.witness_commitments.len() as u64));
        inputs.push(parameters.element_from_u64(witness.reputation_roots.len() as u64));

        let binding_hasher = parameters.poseidon_hasher();
        let bindings = ConsensusCircuit::compute_binding_values(
            parameters,
            &binding_hasher,
            &block_hash,
            witness,
            &verified_outputs,
        )?;

        inputs.push(bindings.vrf_output);
        inputs.push(bindings.vrf_proof);
        inputs.push(bindings.witness_commitment);
        inputs.push(bindings.reputation_root);
        inputs.push(bindings.quorum_bitmap);
        inputs.push(bindings.quorum_signature);

        Ok(inputs)
    }

    pub fn verified_vrf_outputs(
        &self,
    ) -> Result<Ref<Vec<ConsensusVerifiedVrfOutput>>, CircuitError> {
        let cache = self.verified_outputs.borrow();
        if cache.is_empty() {
            return Err(CircuitError::ConstraintViolation(
                "VRF outputs unavailable – run evaluate_constraints first".into(),
            ));
        }
        Ok(cache)
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
        {
            self.verified_outputs.borrow_mut().clear();
        }
        let verified_outputs = parse_vrf_entries(&self.witness)?;
        {
            let mut cache = self.verified_outputs.borrow_mut();
            *cache = verified_outputs;
        }
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
        let verified_outputs = self.verified_vrf_outputs()?;
        let mut randomness_rows = Vec::with_capacity(verified_outputs.len());
        let mut proof_rows = Vec::with_capacity(verified_outputs.len());
        let mut transcript_rows = Vec::with_capacity(verified_outputs.len());
        for (entry, output) in self.witness.vrf_entries.iter().zip(verified_outputs.iter()) {
            randomness_rows.push(vec![
                parameters.element_from_bytes(&output.output.randomness),
                parameters.element_from_bytes(&output.derived_randomness),
            ]);
            proof_rows.push(vec![parameters.element_from_bytes(&output.output.proof)]);
            transcript_rows.push(vec![
                parameters.element_from_bytes(&output.output.preoutput),
                string_to_field(parameters, &entry.public_key),
                parameters.element_from_bytes(&output.poseidon_digest),
                string_to_field(parameters, &entry.input.last_block_header),
                parameters.element_from_u64(entry.input.epoch),
                string_to_field(parameters, &entry.input.tier_seed),
            ]);
        }
        let (vrf_outputs, _vrf_output_binding) = Self::build_binding_segment(
            parameters,
            &hasher,
            &block_hash,
            "vrf_outputs",
            vec!["randomness".to_string(), "derived_randomness".to_string()],
            randomness_rows,
        )?;
        let (vrf_proofs, _vrf_proof_binding) = Self::build_binding_segment(
            parameters,
            &hasher,
            &block_hash,
            "vrf_proofs",
            vec!["proof".to_string()],
            proof_rows,
        )?;
        let vrf_transcripts = TraceSegment::new(
            "vrf_transcripts",
            vec![
                "pre_output".to_string(),
                "public_key".to_string(),
                "poseidon_digest".to_string(),
                "poseidon_last_block".to_string(),
                "poseidon_epoch".to_string(),
                "poseidon_tier_seed".to_string(),
            ],
            transcript_rows,
        )?;
        drop(verified_outputs);
        let witness_commitment_rows = self
            .witness
            .witness_commitments
            .iter()
            .map(|value| vec![string_to_field(parameters, value)])
            .collect();
        let (witness_commitments, _witness_commitment_binding) = Self::build_binding_segment(
            parameters,
            &hasher,
            &block_hash,
            "witness_commitments",
            vec!["commitment".to_string()],
            witness_commitment_rows,
        )?;
        let reputation_root_rows = self
            .witness
            .reputation_roots
            .iter()
            .map(|value| vec![string_to_field(parameters, value)])
            .collect();
        let (reputation_roots, _reputation_root_binding) = Self::build_binding_segment(
            parameters,
            &hasher,
            &block_hash,
            "reputation_roots",
            vec!["root".to_string()],
            reputation_root_rows,
        )?;
        let quorum_bitmap_rows = vec![vec![string_to_field(
            parameters,
            &self.witness.quorum_bitmap_root,
        )]];
        let (quorum_bitmap_binding, _bitmap_final) = Self::build_binding_segment(
            parameters,
            &hasher,
            &block_hash,
            "quorum_bitmap_binding",
            vec!["root".to_string()],
            quorum_bitmap_rows,
        )?;
        let quorum_signature_rows = vec![vec![string_to_field(
            parameters,
            &self.witness.quorum_signature_root,
        )]];
        let (quorum_signature_binding, _signature_final) = Self::build_binding_segment(
            parameters,
            &hasher,
            &block_hash,
            "quorum_signature_binding",
            vec!["root".to_string()],
            quorum_signature_rows,
        )?;

        let summary_columns = summary_columns(&self.witness);
        let summary_values = Self::public_inputs(parameters, &self.witness)?;
        let summary = TraceSegment::new("summary", summary_columns, vec![summary_values])?;

        ExecutionTrace::from_segments(vec![
            pre_votes,
            pre_commits,
            commits,
            vrf_outputs,
            vrf_proofs,
            vrf_transcripts,
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
        let summary_vrf_entry_count = AirColumn::new(summary_segment, "vrf_entry_count");
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
        let vrf_transcript_len = trace
            .segments
            .iter()
            .find(|segment| segment.name == "vrf_transcripts")
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
                "summary_vrf_entry_count",
                &summary_vrf_entry_count,
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
            (
                "summary_vrf_transcript_count",
                &summary_vrf_entry_count,
                vrf_transcript_len as u64,
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
            "summary_vrf_entry_proof_count_match",
            summary_segment,
            ConstraintDomain::FirstRow,
            AirExpression::difference(
                summary_vrf_entry_count.expr(),
                AirExpression::constant(parameters.element_from_u64(vrf_proof_len as u64)),
            ),
        ));

        for index in 0..vrf_output_len {
            let offset = index as isize;
            let summary_randomness =
                AirColumn::new(summary_segment, format!("vrf_randomness_{index}"));
            let summary_randomness_derived =
                AirColumn::new(summary_segment, format!("vrf_randomness_derived_{index}"));
            let summary_preoutput =
                AirColumn::new(summary_segment, format!("vrf_preoutput_{index}"));
            let summary_proof = AirColumn::new(summary_segment, format!("vrf_proof_{index}"));
            let summary_public_key =
                AirColumn::new(summary_segment, format!("vrf_public_key_{index}"));
            let summary_digest =
                AirColumn::new(summary_segment, format!("vrf_poseidon_digest_{index}"));
            let summary_last_block =
                AirColumn::new(summary_segment, format!("vrf_input_last_block_{index}"));
            let summary_epoch = AirColumn::new(summary_segment, format!("vrf_input_epoch_{index}"));
            let summary_tier_seed =
                AirColumn::new(summary_segment, format!("vrf_input_tier_seed_{index}"));

            let vrf_randomness = AirColumn::new("vrf_outputs", "randomness");
            let vrf_randomness_derived = AirColumn::new("vrf_outputs", "derived_randomness");
            let vrf_preoutput = AirColumn::new("vrf_transcripts", "pre_output");
            let vrf_proof = AirColumn::new("vrf_proofs", "proof");
            let vrf_public_key = AirColumn::new("vrf_transcripts", "public_key");
            let vrf_digest = AirColumn::new("vrf_transcripts", "poseidon_digest");
            let vrf_last_block = AirColumn::new("vrf_transcripts", "poseidon_last_block");
            let vrf_epoch = AirColumn::new("vrf_transcripts", "poseidon_epoch");
            let vrf_tier_seed = AirColumn::new("vrf_transcripts", "poseidon_tier_seed");

            let mut add_summary_match = |name: &str, summary: AirColumn, trace: AirColumn| {
                constraints.push(AirConstraint::new(
                    &format!("summary_{name}_{index}_matches_trace"),
                    summary_segment,
                    ConstraintDomain::FirstRow,
                    AirExpression::difference(summary.expr(), trace.shifted(offset)),
                ));
            };

            add_summary_match("vrf_randomness", summary_randomness, vrf_randomness.clone());
            add_summary_match(
                "vrf_randomness_derived",
                summary_randomness_derived,
                vrf_randomness_derived.clone(),
            );
            add_summary_match("vrf_preoutput", summary_preoutput, vrf_preoutput.clone());
            add_summary_match("vrf_proof", summary_proof, vrf_proof.clone());
            add_summary_match("vrf_public_key", summary_public_key, vrf_public_key.clone());
            add_summary_match("vrf_digest", summary_digest, vrf_digest.clone());
            add_summary_match("vrf_last_block", summary_last_block, vrf_last_block.clone());
            add_summary_match("vrf_epoch", summary_epoch, vrf_epoch.clone());
            add_summary_match("vrf_tier_seed", summary_tier_seed, vrf_tier_seed.clone());
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

        let vrf_randomness = AirColumn::new("vrf_outputs", "randomness");
        let vrf_randomness_derived = AirColumn::new("vrf_outputs", "derived_randomness");
        constraints.push(AirConstraint::new(
            "vrf_randomness_matches_derived",
            "vrf_outputs",
            ConstraintDomain::AllRows,
            AirExpression::difference(vrf_randomness.expr(), vrf_randomness_derived.expr()),
        ));

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
        verified_outputs: &[ConsensusVerifiedVrfOutput],
    ) -> Result<ConsensusBindingValues, CircuitError> {
        if witness.vrf_entries.len() != verified_outputs.len() {
            return Err(CircuitError::ConstraintViolation(
                "witness VRF entries and verified outputs differ".into(),
            ));
        }
        let mut randomness_fields = Vec::with_capacity(verified_outputs.len() * 2);
        let mut proof_fields = Vec::with_capacity(verified_outputs.len());
        for output in verified_outputs {
            randomness_fields.push(parameters.element_from_bytes(&output.output.randomness));
            randomness_fields.push(parameters.element_from_bytes(&output.derived_randomness));
            proof_fields.push(parameters.element_from_bytes(&output.output.proof));
        }
        let vrf_output = Self::fold_binding(parameters, hasher, block_hash, randomness_fields);
        let vrf_proof = Self::fold_binding(parameters, hasher, block_hash, proof_fields);
        let witness_commitment = Self::fold_binding(
            parameters,
            hasher,
            block_hash,
            witness
                .witness_commitments
                .iter()
                .map(|value| string_to_field(parameters, value)),
        );
        let reputation_root = Self::fold_binding(
            parameters,
            hasher,
            block_hash,
            witness
                .reputation_roots
                .iter()
                .map(|value| string_to_field(parameters, value)),
        );
        let quorum_bitmap = Self::fold_binding(
            parameters,
            hasher,
            block_hash,
            std::iter::once(string_to_field(parameters, &witness.quorum_bitmap_root)),
        );
        let quorum_signature = Self::fold_binding(
            parameters,
            hasher,
            block_hash,
            std::iter::once(string_to_field(parameters, &witness.quorum_signature_root)),
        );

        Ok(ConsensusBindingValues {
            vrf_output,
            vrf_proof,
            witness_commitment,
            reputation_root,
            quorum_bitmap,
            quorum_signature,
        })
    }

    fn fold_binding<I>(
        parameters: &StarkParameters,
        hasher: &PoseidonHasher,
        block_hash: &FieldElement,
        values: I,
    ) -> FieldElement
    where
        I: IntoIterator<Item = FieldElement>,
    {
        let zero = FieldElement::zero(parameters.modulus());
        let mut accumulator = block_hash.clone();
        for value in values {
            accumulator = hasher.hash(&[accumulator, value, zero.clone()]);
        }
        accumulator
    }

    fn build_binding_segment(
        parameters: &StarkParameters,
        hasher: &PoseidonHasher,
        block_hash: &FieldElement,
        name: &str,
        mut value_columns: Vec<String>,
        rows: Vec<Vec<FieldElement>>,
    ) -> Result<(TraceSegment, FieldElement), CircuitError> {
        let zero = FieldElement::zero(parameters.modulus());
        let mut accumulator = block_hash.clone();
        let mut segment_rows = Vec::with_capacity(rows.len());
        for mut values in rows {
            if values.len() != value_columns.len() {
                return Err(CircuitError::ConstraintViolation(format!(
                    "{name} row has {} values but expected {}",
                    values.len(),
                    value_columns.len()
                )));
            }
            let binding_in = accumulator.clone();
            for value in &values {
                accumulator = hasher.hash(&[accumulator.clone(), value.clone(), zero.clone()]);
            }
            values.push(binding_in);
            values.push(accumulator.clone());
            segment_rows.push(values);
        }
        value_columns.push("binding_in".to_string());
        value_columns.push("binding_out".to_string());
        let segment = TraceSegment::new(name, value_columns, segment_rows)?;
        Ok((segment, accumulator))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        parse_vrf_entries, string_to_field, summary_columns, ConsensusCircuit,
        ConsensusVrfPoseidonInput, ConsensusVrfWitnessEntry, ConsensusWitness, VotePower,
    };
    use crate::official::circuit::CircuitError;
    use crate::official::params::StarkParameters;
    use crate::vrf::{VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH};
    use rpp_crypto_vrf::{generate_vrf, PoseidonVrfInput, VrfSecretKey, POSEIDON_VRF_DOMAIN};
    use serde_json::{from_value, to_value};
    use std::convert::{TryFrom, TryInto};

    const TEST_SECRET_KEY_BYTES: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x20,
    ];

    fn test_secret_key() -> VrfSecretKey {
        VrfSecretKey::try_from(TEST_SECRET_KEY_BYTES).expect("valid VRF secret key")
    }

    fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
        let bytes = hex::decode(value).expect("decode hex");
        let array: [u8; N] = bytes.as_slice().try_into().expect("hex length");
        array
    }

    fn sample_vote() -> VotePower {
        VotePower {
            voter: "validator".into(),
            weight: 1,
        }
    }

    fn sample_vrf_entry() -> ConsensusVrfWitnessEntry {
        let block_hash = "11".repeat(32);
        let epoch = 7;
        let tier_seed = "22".repeat(32);
        let input = PoseidonVrfInput::new(
            decode_hex::<32>(&block_hash),
            epoch,
            decode_hex::<32>(&tier_seed),
        );
        let secret = test_secret_key();
        let public_key = secret.derive_public();
        let output = generate_vrf(&input, &secret).expect("generate vrf output");

        ConsensusVrfWitnessEntry {
            randomness: hex::encode(output.randomness),
            pre_output: hex::encode(output.preoutput),
            proof: hex::encode(output.proof),
            public_key: hex::encode(public_key.to_bytes()),
            input: ConsensusVrfPoseidonInput {
                last_block_header: block_hash,
                epoch,
                tier_seed,
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
        assert!(parse_vrf_entries(&witness).is_ok());
    }

    #[test]
    fn public_inputs_include_poseidon_digest_column() {
        let witness = sample_witness();
        let parameters = StarkParameters::blueprint_default();
        let inputs = ConsensusCircuit::public_inputs(&parameters, &witness)
            .expect("consensus public inputs");
        let columns = summary_columns(&witness);
        let digest_column = "vrf_poseidon_digest_0".to_string();
        let digest_index = columns
            .iter()
            .position(|column| column == &digest_column)
            .expect("digest column present");

        let poseidon_hasher = parameters.poseidon_hasher();
        let domain = parameters.element_from_bytes(POSEIDON_VRF_DOMAIN);
        let entry = &witness.vrf_entries[0];
        let last_block_field = string_to_field(&parameters, &entry.input.last_block_header);
        let epoch_field = parameters.element_from_u64(entry.input.epoch);
        let tier_seed_field = string_to_field(&parameters, &entry.input.tier_seed);
        let digest_inputs = vec![
            domain,
            last_block_field.clone(),
            epoch_field.clone(),
            tier_seed_field.clone(),
        ];
        let expected_digest = poseidon_hasher.hash(&digest_inputs);

        assert_eq!(inputs[digest_index], expected_digest);
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
    fn parse_vrf_entries_reject_invalid_randomness_hex() {
        let mut witness = sample_witness();
        witness.vrf_entries[0].randomness = "zz".into();
        assert!(matches!(
            parse_vrf_entries(&witness),
            Err(CircuitError::InvalidWitness(message))
                if message.contains("randomness encoding")
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
    fn parse_vrf_entries_rejects_malformed_proof_bytes() {
        let mut witness = sample_witness();
        witness.vrf_entries[0].proof = "00".repeat(VRF_PROOF_LENGTH);
        assert!(matches!(
            parse_vrf_entries(&witness),
            Err(CircuitError::ConstraintViolation(message))
                if message.contains("proof is invalid")
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

    #[test]
    fn parse_vrf_entries_rejects_randomness_mismatch() {
        let mut witness = sample_witness();
        let mut randomness_bytes = hex::decode(&witness.vrf_entries[0].randomness).unwrap();
        randomness_bytes[0] ^= 0xFF;
        witness.vrf_entries[0].randomness = hex::encode(randomness_bytes);
        assert!(matches!(
            parse_vrf_entries(&witness),
            Err(CircuitError::ConstraintViolation(message))
                if message.contains("randomness mismatch")
        ));
    }

    #[test]
    fn witness_roundtrips_nested_vrf_entries_in_json() {
        let witness = sample_witness();
        let json = to_value(&witness).expect("serialize witness");

        let first_entry = json
            .get("vrf_entries")
            .and_then(|value| value.as_array())
            .and_then(|entries| entries.first())
            .expect("vrf entries array present")
            .clone();

        assert_eq!(
            first_entry
                .get("input")
                .and_then(|value| value.get("epoch"))
                .and_then(|value| value.as_u64()),
            Some(witness.epoch),
        );
        assert_eq!(
            first_entry
                .get("input")
                .and_then(|value| value.get("last_block_header"))
                .and_then(|value| value.as_str()),
            Some(witness.block_hash.as_str()),
        );

        let decoded: ConsensusWitness = from_value(json).expect("deserialize witness");
        assert_eq!(decoded, witness);
    }
}
