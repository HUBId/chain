use std::collections::HashSet;
use std::convert::TryInto;
use std::ops::Range;

use blake3::Hasher;
use p3_baby_bear::BabyBear;
use p3_field::QuotientMap;
use p3_uni_stark::config::{StarkGenericConfig, Val};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{BackendError, BackendResult};

pub const VRF_PROOF_LENGTH: usize = 80;
pub const VRF_PREOUTPUT_LENGTH: usize = 32;

const CIRCUIT_NAME: &str = "consensus";

fn invalid_witness(message: impl Into<String>) -> BackendError {
    BackendError::InvalidWitness {
        circuit: CIRCUIT_NAME.to_string(),
        message: message.into(),
    }
}

fn invalid_public_inputs(message: impl Into<String>) -> BackendError {
    BackendError::InvalidPublicInputs {
        circuit: CIRCUIT_NAME.to_string(),
        message: message.into(),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VotePower {
    pub voter: String,
    pub weight: u64,
}

impl VotePower {
    fn ensure_valid(&self) -> BackendResult<()> {
        if self.weight == 0 {
            return Err(invalid_witness("vote weight must be non-zero"));
        }
        if self.voter.is_empty() {
            return Err(invalid_witness("vote must include voter address"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ConsensusVrfPoseidonInput {
    pub digest: String,
    pub last_block_header: String,
    pub epoch: String,
    pub tier_seed: String,
}

impl Default for ConsensusVrfPoseidonInput {
    fn default() -> Self {
        let zero_digest = "00".repeat(32);
        Self {
            digest: zero_digest.clone(),
            last_block_header: zero_digest.clone(),
            epoch: "0".to_string(),
            tier_seed: zero_digest,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ConsensusVrfEntry {
    pub randomness: String,
    pub pre_output: String,
    pub proof: String,
    pub public_key: String,
    pub poseidon: ConsensusVrfPoseidonInput,
}

impl Default for ConsensusVrfEntry {
    fn default() -> Self {
        let zero_hex_32 = "00".repeat(32);
        Self {
            randomness: zero_hex_32.clone(),
            pre_output: zero_hex_32.clone(),
            proof: "00".repeat(VRF_PROOF_LENGTH),
            public_key: zero_hex_32,
            poseidon: ConsensusVrfPoseidonInput::default(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusVrfPublicEntry {
    pub randomness: [u8; 32],
    #[serde(default)]
    pub derived_randomness: [u8; 32],
    pub pre_output: [u8; VRF_PREOUTPUT_LENGTH],
    pub proof: Vec<u8>,
    pub public_key: [u8; 32],
    pub poseidon_digest: [u8; 32],
    pub poseidon_last_block_header: [u8; 32],
    pub poseidon_epoch: u64,
    pub poseidon_tier_seed: [u8; 32],
}

#[derive(Clone, Debug)]
pub(crate) struct SanitizedVrfEntry {
    randomness: [u8; 32],
    pre_output: [u8; VRF_PREOUTPUT_LENGTH],
    proof: [u8; VRF_PROOF_LENGTH],
    public_key: [u8; 32],
    poseidon_digest: [u8; 32],
    poseidon_last_block_header: [u8; 32],
    poseidon_epoch: u64,
    poseidon_tier_seed: [u8; 32],
}

impl SanitizedVrfEntry {
    fn randomness_hex(&self) -> String {
        hex::encode(self.randomness)
    }

    fn proof_hex(&self) -> String {
        hex::encode(self.proof)
    }

    fn to_public_entry(&self) -> ConsensusVrfPublicEntry {
        ConsensusVrfPublicEntry {
            randomness: self.randomness,
            derived_randomness: self.randomness,
            pre_output: self.pre_output,
            proof: self.proof.to_vec(),
            public_key: self.public_key,
            poseidon_digest: self.poseidon_digest,
            poseidon_last_block_header: self.poseidon_last_block_header,
            poseidon_epoch: self.poseidon_epoch,
            poseidon_tier_seed: self.poseidon_tier_seed,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
    pub vrf_entries: Vec<ConsensusVrfEntry>,
    #[serde(default)]
    pub witness_commitments: Vec<String>,
    #[serde(default)]
    pub reputation_roots: Vec<String>,
}

impl ConsensusWitness {
    fn ensure_digest(label: &str, value: &str) -> BackendResult<Vec<u8>> {
        let bytes = hex::decode(value)
            .map_err(|err| invalid_witness(format!("invalid {label} encoding '{value}': {err}")))?;
        if bytes.len() != 32 {
            return Err(invalid_witness(format!("{label} must encode 32 bytes")));
        }
        Ok(bytes)
    }

    fn sanitize_vrf_field<const N: usize>(
        index: usize,
        label: &str,
        value: &str,
    ) -> BackendResult<[u8; N]> {
        if value.trim().is_empty() {
            return Err(invalid_witness(format!(
                "consensus witness vrf entry #{index} missing {label}"
            )));
        }
        let bytes = hex::decode(value).map_err(|err| {
            invalid_witness(format!(
                "invalid vrf entry #{index} {label} encoding: {err}"
            ))
        })?;
        if bytes.len() != N {
            return Err(invalid_witness(format!(
                "vrf entry #{index} {label} must encode {N} bytes"
            )));
        }
        Ok(bytes.try_into().map_err(|_| {
            invalid_witness(format!("vrf entry #{index} {label} must encode {N} bytes"))
        })?)
    }

    fn sanitize_vrf_epoch(index: usize, value: &str) -> BackendResult<u64> {
        let epoch = value.trim();
        if epoch.is_empty() {
            return Err(invalid_witness(format!(
                "consensus witness vrf entry #{index} missing poseidon epoch"
            )));
        }
        epoch.parse::<u64>().map_err(|err| {
            invalid_witness(format!(
                "invalid vrf entry #{index} poseidon epoch '{epoch}': {err}"
            ))
        })
    }

    fn ensure_votes(&self, votes: &[VotePower], label: &str) -> BackendResult<u128> {
        if votes.is_empty() {
            return Err(invalid_witness(format!(
                "consensus witness missing {label} votes"
            )));
        }
        let mut seen = HashSet::new();
        let mut total = 0u128;
        for vote in votes {
            vote.ensure_valid()?;
            if !seen.insert(vote.voter.clone()) {
                return Err(invalid_witness(format!(
                    "validator '{}' submitted duplicate {label} vote",
                    vote.voter
                )));
            }
            total = total
                .checked_add(vote.weight as u128)
                .ok_or_else(|| invalid_witness("vote weight overflow"))?;
        }
        Ok(total)
    }

    fn verify_quorum(&self, total: u128, label: &str) -> BackendResult<()> {
        if total < self.quorum_threshold as u128 {
            return Err(invalid_witness(format!(
                "insufficient {label} voting power for quorum"
            )));
        }
        Ok(())
    }

    fn ensure_digest_set(&self, label: &str, values: &[String]) -> BackendResult<()> {
        if values.is_empty() {
            return Err(invalid_witness(format!("{label} set cannot be empty")));
        }
        for value in values {
            Self::ensure_digest(label, value)?;
        }
        Ok(())
    }

    fn sanitized_vrf_entries(&self) -> BackendResult<Vec<SanitizedVrfEntry>> {
        if self.vrf_entries.is_empty() {
            return Err(invalid_witness("consensus witness missing VRF entries"));
        }

        let block_hash_vec = Self::ensure_digest("block hash", &self.block_hash)?;
        let block_hash: [u8; 32] = block_hash_vec
            .as_slice()
            .try_into()
            .map_err(|_| invalid_witness("block hash must encode 32 bytes"))?;

        let mut sanitized = Vec::with_capacity(self.vrf_entries.len());
        for (index, entry) in self.vrf_entries.iter().enumerate() {
            let randomness =
                Self::sanitize_vrf_field::<32>(index, "randomness", &entry.randomness)?;
            let pre_output = Self::sanitize_vrf_field::<VRF_PREOUTPUT_LENGTH>(
                index,
                "pre-output",
                &entry.pre_output,
            )?;
            let proof = Self::sanitize_vrf_field::<VRF_PROOF_LENGTH>(index, "proof", &entry.proof)?;
            let public_key =
                Self::sanitize_vrf_field::<32>(index, "public key", &entry.public_key)?;
            let poseidon_digest =
                Self::sanitize_vrf_field::<32>(index, "poseidon digest", &entry.poseidon.digest)?;
            let poseidon_last_block_header = Self::sanitize_vrf_field::<32>(
                index,
                "poseidon last block header",
                &entry.poseidon.last_block_header,
            )?;
            if poseidon_last_block_header != block_hash {
                return Err(invalid_witness(format!(
                    "vrf entry #{index} poseidon last block header must match block hash"
                )));
            }
            let poseidon_tier_seed = Self::sanitize_vrf_field::<32>(
                index,
                "poseidon tier seed",
                &entry.poseidon.tier_seed,
            )?;
            let poseidon_epoch = Self::sanitize_vrf_epoch(index, &entry.poseidon.epoch)?;
            if poseidon_epoch != self.epoch {
                return Err(invalid_witness(format!(
                    "vrf entry #{index} poseidon epoch must match consensus epoch"
                )));
            }

            sanitized.push(SanitizedVrfEntry {
                randomness,
                pre_output,
                proof,
                public_key,
                poseidon_digest,
                poseidon_last_block_header,
                poseidon_epoch,
                poseidon_tier_seed,
            });
        }

        Ok(sanitized)
    }

    fn ensure_vrf_metadata(&self) -> BackendResult<()> {
        self.sanitized_vrf_entries().map(|_| ())
    }

    pub fn validate(&self) -> BackendResult<()> {
        if self.quorum_threshold == 0 {
            return Err(invalid_witness("quorum threshold must be positive"));
        }

        Self::ensure_digest("block hash", &self.block_hash)?;
        Self::ensure_digest("leader proposal", &self.leader_proposal)?;
        Self::ensure_digest("quorum bitmap root", &self.quorum_bitmap_root)?;
        Self::ensure_digest("quorum signature root", &self.quorum_signature_root)?;
        self.ensure_digest_set("witness commitment", &self.witness_commitments)?;
        self.ensure_digest_set("reputation root", &self.reputation_roots)?;
        self.ensure_vrf_metadata()?;

        let pre_vote_total = self.ensure_votes(&self.pre_votes, "pre-vote")?;
        let pre_commit_total = self.ensure_votes(&self.pre_commits, "pre-commit")?;
        let commit_total = self.ensure_votes(&self.commit_votes, "commit")?;

        self.verify_quorum(pre_vote_total, "pre-vote")?;
        self.verify_quorum(pre_commit_total, "pre-commit")?;
        self.verify_quorum(commit_total, "commit")?;

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusBindings {
    pub vrf_outputs: String,
    pub vrf_proofs: String,
    pub witness_commitments: String,
    pub reputation_roots: String,
    pub quorum_bitmap: String,
    pub quorum_signature: String,
}

impl ConsensusBindings {
    fn from_witness(
        witness: &ConsensusWitness,
        vrf_entries: &[SanitizedVrfEntry],
    ) -> BackendResult<Self> {
        let block_hash = ConsensusWitness::ensure_digest("block hash", &witness.block_hash)?;

        let vrf_randomness: Vec<String> = vrf_entries
            .iter()
            .flat_map(|entry| {
                let randomness = entry.randomness_hex();
                std::iter::once(randomness.clone()).chain(std::iter::once(randomness))
            })
            .collect();
        let vrf_proofs_hex: Vec<String> = vrf_entries
            .iter()
            .map(SanitizedVrfEntry::proof_hex)
            .collect();

        let vrf_outputs = binding_digest(
            &block_hash,
            |value| ConsensusWitness::ensure_digest("vrf randomness", value),
            &vrf_randomness,
        )?;
        let vrf_proofs = binding_digest(
            &block_hash,
            |value| {
                let bytes = hex::decode(value)
                    .map_err(|err| invalid_witness(format!("invalid vrf proof encoding: {err}")))?;
                if bytes.len() != VRF_PROOF_LENGTH {
                    return Err(invalid_witness(format!(
                        "vrf proof must encode {VRF_PROOF_LENGTH} bytes"
                    )));
                }
                Ok(bytes)
            },
            &vrf_proofs_hex,
        )?;
        let witness_commitments = binding_digest(
            &block_hash,
            |value| ConsensusWitness::ensure_digest("witness commitment", value),
            &witness.witness_commitments,
        )?;
        let reputation_roots = binding_digest(
            &block_hash,
            |value| ConsensusWitness::ensure_digest("reputation root", value),
            &witness.reputation_roots,
        )?;
        let quorum_bitmap = binding_digest(
            &block_hash,
            |value| ConsensusWitness::ensure_digest("quorum bitmap root", value),
            std::slice::from_ref(&witness.quorum_bitmap_root),
        )?;
        let quorum_signature = binding_digest(
            &block_hash,
            |value| ConsensusWitness::ensure_digest("quorum signature root", value),
            std::slice::from_ref(&witness.quorum_signature_root),
        )?;

        Ok(Self {
            vrf_outputs,
            vrf_proofs,
            witness_commitments,
            reputation_roots,
            quorum_bitmap,
            quorum_signature,
        })
    }
}

fn binding_digest(
    seed: &[u8],
    decode: impl Fn(&str) -> BackendResult<Vec<u8>>,
    values: &[String],
) -> BackendResult<String> {
    let mut accumulator = seed.to_vec();
    for value in values {
        let bytes = decode(value)?;
        let mut hasher = Hasher::new();
        hasher.update(&accumulator);
        hasher.update(&bytes);
        accumulator = hasher.finalize().as_bytes().to_vec();
    }
    Ok(hex::encode(accumulator))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusPublicInputs {
    pub witness: ConsensusWitness,
    pub bindings: ConsensusBindings,
    #[serde(default)]
    pub vrf_entries: Vec<ConsensusVrfPublicEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct ConsensusCircuit {
    witness: ConsensusWitness,
    bindings: ConsensusBindings,
    cached_sanitized_vrf_entries: Vec<SanitizedVrfEntry>,
    vrf_public_entries: Vec<ConsensusVrfPublicEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusPublicInputLayout {
    pub block_hash: Range<usize>,
    pub round: usize,
    pub leader_proposal: Range<usize>,
    pub epoch: usize,
    pub slot: usize,
    pub quorum_threshold: usize,
    pub quorum_bitmap_root: Range<usize>,
    pub quorum_signature_root: Range<usize>,
    pub vrf_entry_count: usize,
    pub vrf_entries: Vec<ConsensusVrfEntryLayout>,
    pub witness_commitment_count: usize,
    pub witness_commitments: Vec<Range<usize>>,
    pub reputation_root_count: usize,
    pub reputation_roots: Vec<Range<usize>>,
    pub bindings: ConsensusBindingLayout,
    pub block_height: Option<usize>,
    pub total_values: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusVrfEntryLayout {
    pub randomness: Range<usize>,
    pub derived_randomness: Range<usize>,
    pub pre_output: Range<usize>,
    pub proof: Range<usize>,
    pub public_key: Range<usize>,
    pub poseidon_digest: Range<usize>,
    pub poseidon_last_block_header: Range<usize>,
    pub poseidon_epoch: usize,
    pub poseidon_tier_seed: Range<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusBindingLayout {
    pub vrf_outputs: Range<usize>,
    pub vrf_proofs: Range<usize>,
    pub witness_commitments: Range<usize>,
    pub reputation_roots: Range<usize>,
    pub quorum_bitmap: Range<usize>,
    pub quorum_signature: Range<usize>,
}

impl ConsensusCircuit {
    pub fn new(witness: ConsensusWitness) -> BackendResult<Self> {
        witness.validate()?;
        let sanitized_vrf_entries = witness.sanitized_vrf_entries()?;
        let bindings = ConsensusBindings::from_witness(&witness, &sanitized_vrf_entries)?;
        let vrf_public_entries = sanitized_vrf_entries
            .iter()
            .map(SanitizedVrfEntry::to_public_entry)
            .collect();
        Ok(Self {
            witness,
            bindings,
            cached_sanitized_vrf_entries: sanitized_vrf_entries,
            vrf_public_entries,
        })
    }

    pub fn from_public_inputs_value(value: &Value) -> BackendResult<Self> {
        let parsed: ConsensusPublicInputs =
            serde_json::from_value(value.clone()).map_err(|err| {
                invalid_public_inputs(format!("invalid consensus public inputs payload: {err}"))
            })?;
        let ConsensusPublicInputs {
            witness: parsed_witness,
            bindings: parsed_bindings,
            block_height,
            vrf_entries: parsed_vrf_entries,
        } = parsed;
        let circuit = Self::new(parsed_witness)?;
        if let Some(block_height) = block_height {
            if block_height != circuit.witness.round {
                return Err(invalid_public_inputs(format!(
                    "block height {block_height} does not match consensus round {}",
                    circuit.witness.round
                )));
            }
        }
        if parsed_bindings != circuit.bindings {
            return Err(invalid_public_inputs(
                "consensus binding digests mismatch public inputs",
            ));
        }
        if parsed_vrf_entries != circuit.vrf_public_entries {
            return Err(invalid_public_inputs(
                "consensus VRF entries mismatch public inputs",
            ));
        }
        Ok(circuit)
    }

    pub fn witness(&self) -> &ConsensusWitness {
        &self.witness
    }

    pub fn bindings(&self) -> &ConsensusBindings {
        &self.bindings
    }

    pub fn vrf_entries(&self) -> &[ConsensusVrfPublicEntry] {
        &self.vrf_public_entries
    }

    pub(crate) fn sanitized_vrf_entries(&self) -> &[SanitizedVrfEntry] {
        &self.cached_sanitized_vrf_entries
    }

    pub fn public_inputs_value(&self) -> BackendResult<Value> {
        serde_json::to_value(ConsensusPublicInputs {
            witness: self.witness.clone(),
            bindings: self.bindings.clone(),
            vrf_entries: self.vrf_public_entries.clone(),
            block_height: Some(self.witness.round),
        })
        .map_err(|err| {
            invalid_public_inputs(format!("failed to encode consensus public inputs: {err}"))
        })
    }

    pub fn into_public_inputs(self) -> BackendResult<Value> {
        self.public_inputs_value()
    }

    pub fn flatten_public_inputs_babybear(
        &self,
    ) -> BackendResult<(Vec<BabyBear>, ConsensusPublicInputLayout)> {
        self.flatten_public_inputs_field()
    }

    pub fn flatten_public_inputs_for_config<SC: StarkGenericConfig>(
        &self,
    ) -> BackendResult<(Vec<Val<SC>>, ConsensusPublicInputLayout)> {
        self.flatten_public_inputs_field()
    }

    fn flatten_public_inputs_field<F>(&self) -> BackendResult<(Vec<F>, ConsensusPublicInputLayout)>
    where
        F: Copy + QuotientMap<u8> + QuotientMap<u64>,
    {
        let mut values = Vec::new();

        let mut push_bytes = |bytes: &[u8]| {
            let start = values.len();
            for &byte in bytes {
                values.push(<F as QuotientMap<u8>>::from_int(byte));
            }
            start..values.len()
        };

        let mut push_u64 = |value: u64| {
            let index = values.len();
            values.push(<F as QuotientMap<u64>>::from_int(value));
            index
        };

        let block_hash_bytes = self
            .cached_sanitized_vrf_entries
            .first()
            .map(|entry| entry.poseidon_last_block_header.to_vec())
            .ok_or_else(|| invalid_witness("consensus witness missing VRF entries"))?;
        let block_hash = push_bytes(&block_hash_bytes);

        let round = push_u64(self.witness.round);

        let leader_proposal_bytes =
            ConsensusWitness::ensure_digest("leader proposal", &self.witness.leader_proposal)?;
        let leader_proposal = push_bytes(&leader_proposal_bytes);

        let epoch = push_u64(self.witness.epoch);
        let slot = push_u64(self.witness.slot);
        let quorum_threshold = push_u64(self.witness.quorum_threshold);

        let quorum_bitmap_root_bytes = ConsensusWitness::ensure_digest(
            "quorum bitmap root",
            &self.witness.quorum_bitmap_root,
        )?;
        let quorum_bitmap_root = push_bytes(&quorum_bitmap_root_bytes);
        let quorum_signature_root_bytes = ConsensusWitness::ensure_digest(
            "quorum signature root",
            &self.witness.quorum_signature_root,
        )?;
        let quorum_signature_root = push_bytes(&quorum_signature_root_bytes);

        let vrf_entry_count = push_u64(self.vrf_public_entries.len() as u64);
        let mut vrf_layouts = Vec::with_capacity(self.vrf_public_entries.len());
        for entry in &self.vrf_public_entries {
            let randomness = push_bytes(&entry.randomness);
            let derived_randomness = push_bytes(&entry.derived_randomness);
            let pre_output = push_bytes(&entry.pre_output);
            let proof = push_bytes(&entry.proof);
            let public_key = push_bytes(&entry.public_key);
            let poseidon_digest = push_bytes(&entry.poseidon_digest);
            let poseidon_last_block_header = push_bytes(&entry.poseidon_last_block_header);
            let poseidon_epoch = push_u64(entry.poseidon_epoch);
            let poseidon_tier_seed = push_bytes(&entry.poseidon_tier_seed);

            vrf_layouts.push(ConsensusVrfEntryLayout {
                randomness,
                derived_randomness,
                pre_output,
                proof,
                public_key,
                poseidon_digest,
                poseidon_last_block_header,
                poseidon_epoch,
                poseidon_tier_seed,
            });
        }

        let witness_commitment_count = push_u64(self.witness.witness_commitments.len() as u64);
        let mut witness_commitments = Vec::with_capacity(self.witness.witness_commitments.len());
        for commitment in &self.witness.witness_commitments {
            let digest = ConsensusWitness::ensure_digest("witness commitment", commitment)?;
            witness_commitments.push(push_bytes(&digest));
        }

        let reputation_root_count = push_u64(self.witness.reputation_roots.len() as u64);
        let mut reputation_roots = Vec::with_capacity(self.witness.reputation_roots.len());
        for root in &self.witness.reputation_roots {
            let digest = ConsensusWitness::ensure_digest("reputation root", root)?;
            reputation_roots.push(push_bytes(&digest));
        }

        let vrf_output_binding =
            ConsensusWitness::ensure_digest("vrf output binding", &self.bindings.vrf_outputs)?;
        let vrf_proof_binding =
            ConsensusWitness::ensure_digest("vrf proof binding", &self.bindings.vrf_proofs)?;
        let witness_commitment_binding = ConsensusWitness::ensure_digest(
            "witness commitment binding",
            &self.bindings.witness_commitments,
        )?;
        let reputation_root_binding = ConsensusWitness::ensure_digest(
            "reputation root binding",
            &self.bindings.reputation_roots,
        )?;
        let quorum_bitmap_binding =
            ConsensusWitness::ensure_digest("quorum bitmap binding", &self.bindings.quorum_bitmap)?;
        let quorum_signature_binding = ConsensusWitness::ensure_digest(
            "quorum signature binding",
            &self.bindings.quorum_signature,
        )?;

        let bindings = ConsensusBindingLayout {
            vrf_outputs: push_bytes(&vrf_output_binding),
            vrf_proofs: push_bytes(&vrf_proof_binding),
            witness_commitments: push_bytes(&witness_commitment_binding),
            reputation_roots: push_bytes(&reputation_root_binding),
            quorum_bitmap: push_bytes(&quorum_bitmap_binding),
            quorum_signature: push_bytes(&quorum_signature_binding),
        };

        let block_height = Some(push_u64(self.witness.round));

        let layout = ConsensusPublicInputLayout {
            block_hash,
            round,
            leader_proposal,
            epoch,
            slot,
            quorum_threshold,
            quorum_bitmap_root,
            quorum_signature_root,
            vrf_entry_count,
            vrf_entries: vrf_layouts,
            witness_commitment_count,
            witness_commitments,
            reputation_root_count,
            reputation_roots,
            bindings,
            block_height,
            total_values: values.len(),
        };

        Ok((values, layout))
    }
}

pub fn encode_consensus_public_inputs(witness: ConsensusWitness) -> BackendResult<Value> {
    ConsensusCircuit::new(witness)?.public_inputs_value()
}

pub fn validate_consensus_public_inputs(value: &Value) -> BackendResult<()> {
    ConsensusCircuit::from_public_inputs_value(value).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CircuitStarkConfig;
    use p3_field::{PrimeField32, PrimeField64};

    fn sample_vote(label: &str, weight: u64) -> VotePower {
        VotePower {
            voter: label.to_string(),
            weight,
        }
    }

    fn sample_witness() -> ConsensusWitness {
        let block_hash = "11".repeat(32);
        ConsensusWitness {
            block_hash: block_hash.clone(),
            round: 7,
            epoch: 3,
            slot: 9,
            leader_proposal: "22".repeat(32),
            quorum_threshold: 2,
            pre_votes: vec![sample_vote("validator-a", 2)],
            pre_commits: vec![sample_vote("validator-a", 2)],
            commit_votes: vec![sample_vote("validator-a", 2)],
            quorum_bitmap_root: "33".repeat(32),
            quorum_signature_root: "44".repeat(32),
            vrf_entries: vec![ConsensusVrfEntry {
                randomness: "55".repeat(32),
                pre_output: "66".repeat(VRF_PREOUTPUT_LENGTH),
                proof: "77".repeat(VRF_PROOF_LENGTH),
                public_key: "88".repeat(32),
                poseidon: ConsensusVrfPoseidonInput {
                    digest: "99".repeat(32),
                    last_block_header: block_hash,
                    epoch: "3".to_string(),
                    tier_seed: "aa".repeat(32),
                },
            }],
            witness_commitments: vec!["bb".repeat(32)],
            reputation_roots: vec!["cc".repeat(32)],
        }
    }

    #[test]
    fn flatten_public_inputs_babybear_layout_matches_witness() {
        let circuit = ConsensusCircuit::new(sample_witness()).expect("consensus circuit");
        let (values, layout) = circuit
            .flatten_public_inputs_babybear()
            .expect("flattened values");

        assert_eq!(layout.total_values, values.len());
        assert_eq!(layout.vrf_entries.len(), circuit.vrf_entries().len());
        assert_eq!(
            layout.witness_commitments.len(),
            circuit.witness().witness_commitments.len()
        );
        assert_eq!(
            layout.reputation_roots.len(),
            circuit.witness().reputation_roots.len()
        );

        let expected_block_hash = circuit.sanitized_vrf_entries()[0].poseidon_last_block_header;
        let actual_block_hash: Vec<u8> = layout
            .block_hash
            .clone()
            .map(|index| values[index].as_canonical_u32() as u8)
            .collect();
        assert_eq!(actual_block_hash, expected_block_hash.to_vec());

        assert_eq!(
            values[layout.round].as_canonical_u64(),
            circuit.witness().round
        );
        assert_eq!(
            values[layout.epoch].as_canonical_u64(),
            circuit.witness().epoch
        );
        assert_eq!(
            values[layout.slot].as_canonical_u64(),
            circuit.witness().slot
        );

        let vrf_count = values[layout.vrf_entry_count].as_canonical_u64() as usize;
        assert_eq!(vrf_count, circuit.vrf_entries().len());
        let vrf_layout = &layout.vrf_entries[0];
        let vrf_entry = &circuit.vrf_entries()[0];
        let randomness: Vec<u8> = vrf_layout
            .randomness
            .clone()
            .map(|index| values[index].as_canonical_u32() as u8)
            .collect();
        assert_eq!(randomness, vrf_entry.randomness.to_vec());
        let proof: Vec<u8> = vrf_layout
            .proof
            .clone()
            .map(|index| values[index].as_canonical_u32() as u8)
            .collect();
        assert_eq!(proof.len(), VRF_PROOF_LENGTH);
        assert_eq!(proof, vrf_entry.proof);
        assert_eq!(
            values[vrf_layout.poseidon_epoch].as_canonical_u64(),
            vrf_entry.poseidon_epoch,
        );

        let witness_commitment_count =
            values[layout.witness_commitment_count].as_canonical_u64() as usize;
        assert_eq!(
            witness_commitment_count,
            circuit.witness().witness_commitments.len(),
        );
        let reputation_root_count =
            values[layout.reputation_root_count].as_canonical_u64() as usize;
        assert_eq!(
            reputation_root_count,
            circuit.witness().reputation_roots.len(),
        );

        let binding_randomness: Vec<u8> = layout
            .bindings
            .vrf_outputs
            .clone()
            .map(|index| values[index].as_canonical_u32() as u8)
            .collect();
        assert_eq!(binding_randomness.len(), 32);

        let block_height_index = layout.block_height.expect("block height index");
        assert_eq!(
            values[block_height_index].as_canonical_u64(),
            circuit.witness().round,
        );
    }

    #[test]
    fn flatten_public_inputs_generic_matches_babybear() {
        let circuit = ConsensusCircuit::new(sample_witness()).expect("consensus circuit");
        let (babybear_values, babybear_layout) = circuit
            .flatten_public_inputs_babybear()
            .expect("babybear values");
        let (generic_values, generic_layout) = circuit
            .flatten_public_inputs_for_config::<CircuitStarkConfig>()
            .expect("generic values");

        assert_eq!(babybear_layout, generic_layout);
        assert_eq!(babybear_values.len(), generic_values.len());
        for (expected, actual) in babybear_values.iter().zip(generic_values.iter()) {
            assert_eq!(expected.as_canonical_u64(), actual.as_canonical_u64());
        }
    }
}
