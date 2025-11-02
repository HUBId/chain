use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

use crate::errors::{ChainError, ChainResult};

use super::Plonky3CircuitWitness;
use rpp_crypto_vrf::VRF_PROOF_LENGTH;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VotePower {
    pub voter: String,
    pub weight: u64,
}

/// Witness representation for the BFT consensus circuit.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    pub vrf_outputs: Vec<String>,
    pub vrf_proofs: Vec<String>,
    pub witness_commitments: Vec<String>,
    pub reputation_roots: Vec<String>,
}

impl ConsensusWitness {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        block_hash: impl Into<String>,
        round: u64,
        epoch: u64,
        slot: u64,
        leader_proposal: impl Into<String>,
        quorum_threshold: u64,
        pre_votes: Vec<VotePower>,
        pre_commits: Vec<VotePower>,
        commit_votes: Vec<VotePower>,
        quorum_bitmap_root: impl Into<String>,
        quorum_signature_root: impl Into<String>,
        vrf_outputs: Vec<String>,
        vrf_proofs: Vec<String>,
        witness_commitments: Vec<String>,
        reputation_roots: Vec<String>,
    ) -> Self {
        Self {
            block_hash: block_hash.into(),
            round,
            epoch,
            slot,
            leader_proposal: leader_proposal.into(),
            quorum_threshold,
            pre_votes,
            pre_commits,
            commit_votes,
            quorum_bitmap_root: quorum_bitmap_root.into(),
            quorum_signature_root: quorum_signature_root.into(),
            vrf_outputs,
            vrf_proofs,
            witness_commitments,
            reputation_roots,
        }
    }

    fn ensure_digest(label: &str, value: &str) -> ChainResult<()> {
        let bytes = hex::decode(value).map_err(|err| {
            ChainError::Crypto(format!("invalid {label} encoding '{value}': {err}"))
        })?;
        if bytes.len() != 32 {
            return Err(ChainError::Crypto(format!("{label} must encode 32 bytes")));
        }
        Ok(())
    }

    fn ensure_non_empty(label: &str, values: &[String]) -> ChainResult<()> {
        if values.is_empty() {
            return Err(ChainError::Crypto(format!(
                "consensus certificate missing {label}"
            )));
        }
        Ok(())
    }

    fn ensure_vrf_metadata(&self) -> ChainResult<()> {
        Self::ensure_non_empty("VRF outputs", &self.vrf_outputs)?;
        Self::ensure_non_empty("VRF proofs", &self.vrf_proofs)?;
        if self.vrf_outputs.len() != self.vrf_proofs.len() {
            return Err(ChainError::Crypto(
                "consensus certificate VRF output/proof count mismatch".into(),
            ));
        }
        for (index, proof) in self.vrf_proofs.iter().enumerate() {
            let bytes = hex::decode(proof).map_err(|err| {
                ChainError::Crypto(format!("invalid vrf proof #{index} encoding: {err}"))
            })?;
            if bytes.len() != VRF_PROOF_LENGTH {
                return Err(ChainError::Crypto(format!(
                    "vrf proof #{index} must encode {VRF_PROOF_LENGTH} bytes"
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_metadata(&self) -> ChainResult<()> {
        Self::ensure_digest("quorum bitmap root", &self.quorum_bitmap_root)?;
        Self::ensure_digest("quorum signature root", &self.quorum_signature_root)?;
        Self::ensure_non_empty("witness commitments", &self.witness_commitments)?;
        Self::ensure_non_empty("reputation roots", &self.reputation_roots)?;
        Self::ensure_vrf_metadata()
    }
}

impl Plonky3CircuitWitness for ConsensusWitness {
    fn circuit(&self) -> &'static str {
        "consensus"
    }

    fn block_height(&self) -> Option<u64> {
        Some(self.round)
    }

    fn public_inputs(&self) -> ChainResult<Value> {
        self.validate_metadata()?;

        let mut object = Map::new();
        let witness_value = serde_json::to_value(self).map_err(|err| {
            ChainError::Crypto(format!(
                "failed to serialize {} witness for Plonky3 public inputs: {err}",
                self.circuit()
            ))
        })?;
        object.insert("witness".into(), witness_value);
        if let Some(height) = self.block_height() {
            object.insert("block_height".into(), Value::Number(Number::from(height)));
        }
        Ok(Value::Object(object))
    }
}
