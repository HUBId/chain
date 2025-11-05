use std::collections::HashSet;
use std::convert::TryInto;

use blake3::Hasher;
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
}

pub fn encode_consensus_public_inputs(witness: ConsensusWitness) -> BackendResult<Value> {
    ConsensusCircuit::new(witness)?.public_inputs_value()
}

pub fn validate_consensus_public_inputs(value: &Value) -> BackendResult<()> {
    ConsensusCircuit::from_public_inputs_value(value).map(|_| ())
}
