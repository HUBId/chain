use std::collections::HashSet;

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{BackendError, BackendResult};

pub const VRF_PROOF_LENGTH: usize = 80;

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
    fn ensure_digest(label: &str, value: &str) -> BackendResult<Vec<u8>> {
        let bytes = hex::decode(value)
            .map_err(|err| invalid_witness(format!("invalid {label} encoding '{value}': {err}")))?;
        if bytes.len() != 32 {
            return Err(invalid_witness(format!("{label} must encode 32 bytes")));
        }
        Ok(bytes)
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

    fn ensure_vrf_metadata(&self) -> BackendResult<()> {
        if self.vrf_outputs.is_empty() {
            return Err(invalid_witness("consensus witness missing VRF outputs"));
        }
        if self.vrf_proofs.is_empty() {
            return Err(invalid_witness("consensus witness missing VRF proofs"));
        }
        if self.vrf_outputs.len() != self.vrf_proofs.len() {
            return Err(invalid_witness("vrf output/proof count mismatch"));
        }
        for (index, proof) in self.vrf_proofs.iter().enumerate() {
            let bytes = hex::decode(proof).map_err(|err| {
                invalid_witness(format!("invalid vrf proof #{index} encoding: {err}"))
            })?;
            if bytes.len() != VRF_PROOF_LENGTH {
                return Err(invalid_witness(format!(
                    "vrf proof #{index} must encode {VRF_PROOF_LENGTH} bytes"
                )));
            }
        }
        Ok(())
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
    fn from_witness(witness: &ConsensusWitness) -> BackendResult<Self> {
        let block_hash = ConsensusWitness::ensure_digest("block hash", &witness.block_hash)?;

        let vrf_outputs = binding_digest(
            &block_hash,
            |value| ConsensusWitness::ensure_digest("vrf output", value),
            &witness.vrf_outputs,
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
            &witness.vrf_proofs,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct ConsensusCircuit {
    witness: ConsensusWitness,
    bindings: ConsensusBindings,
}

impl ConsensusCircuit {
    pub fn new(witness: ConsensusWitness) -> BackendResult<Self> {
        witness.validate()?;
        let bindings = ConsensusBindings::from_witness(&witness)?;
        Ok(Self { witness, bindings })
    }

    pub fn from_public_inputs_value(value: &Value) -> BackendResult<Self> {
        let parsed: ConsensusPublicInputs =
            serde_json::from_value(value.clone()).map_err(|err| {
                invalid_public_inputs(format!("invalid consensus public inputs payload: {err}"))
            })?;
        let circuit = Self::new(parsed.witness)?;
        if let Some(block_height) = parsed.block_height {
            if block_height != circuit.witness.round {
                return Err(invalid_public_inputs(format!(
                    "block height {block_height} does not match consensus round {}",
                    circuit.witness.round
                )));
            }
        }
        if parsed.bindings != circuit.bindings {
            return Err(invalid_public_inputs(
                "consensus binding digests mismatch public inputs",
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

    pub fn public_inputs_value(&self) -> BackendResult<Value> {
        serde_json::to_value(ConsensusPublicInputs {
            witness: self.witness.clone(),
            bindings: self.bindings.clone(),
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
