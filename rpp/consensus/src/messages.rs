use blake3::Hasher;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;
use std::fmt;

use crate::validator::ValidatorId;

const PROOF_MAC_KEY: [u8; 32] = *b"rpp-consensus-proof-mac-key-0000";

mod peer_id_serde {
    use libp2p::PeerId;
    use serde::{Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub fn serialize<S>(peer_id: &PeerId, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&peer_id.to_base58())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PeerId, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        PeerId::from_str(&value).map_err(|err| serde::de::Error::custom(err.to_string()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BlockId(pub String);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub height: u64,
    pub epoch: u64,
    pub payload: Value,
    pub timestamp: u64,
}

impl Block {
    pub fn hash(&self) -> BlockId {
        let mut hasher = Hasher::new();
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        let payload = serde_json::to_vec(&self.payload).unwrap_or_default();
        hasher.update(&payload);
        BlockId(hasher.finalize().to_hex().to_string())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusProof {
    pub commitment: String,
    pub witness_hash: String,
    pub recursion_depth: u32,
    pub commitments: Vec<String>,
    pub aggregated_signature: Vec<u8>,
    pub hmac: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofVerificationError {
    MissingCommitment,
    MissingWitnessHash,
    InvalidRecursionDepth,
    InvalidAggregationSignature,
    InvalidMac,
}

impl fmt::Display for ProofVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofVerificationError::MissingCommitment => write!(f, "missing commitment"),
            ProofVerificationError::MissingWitnessHash => write!(f, "missing witness hash"),
            ProofVerificationError::InvalidRecursionDepth => {
                write!(f, "recursion depth does not cover commitments")
            }
            ProofVerificationError::InvalidAggregationSignature => {
                write!(f, "aggregated signature mismatch")
            }
            ProofVerificationError::InvalidMac => write!(f, "proof HMAC mismatch"),
        }
    }
}

impl Error for ProofVerificationError {}

impl ConsensusProof {
    pub fn new(
        commitment: String,
        witness_hash: String,
        recursion_depth: u32,
        commitments: Vec<String>,
    ) -> Self {
        let aggregated_signature = Self::compute_aggregated_signature(
            &commitment,
            &witness_hash,
            recursion_depth,
            &commitments,
        );
        let hmac = Self::compute_hmac(&commitment, &aggregated_signature);
        Self {
            commitment,
            witness_hash,
            recursion_depth,
            commitments,
            aggregated_signature,
            hmac,
        }
    }

    fn compute_aggregated_signature(
        commitment: &str,
        witness_hash: &str,
        recursion_depth: u32,
        commitments: &[String],
    ) -> Vec<u8> {
        let mut hasher = Hasher::new();
        hasher.update(commitment.as_bytes());
        hasher.update(witness_hash.as_bytes());
        hasher.update(&recursion_depth.to_le_bytes());
        for commitment in commitments {
            hasher.update(commitment.as_bytes());
        }
        hasher.finalize().as_bytes().to_vec()
    }

    fn compute_hmac(commitment: &str, aggregated_signature: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(commitment.as_bytes());
        data.extend_from_slice(aggregated_signature);
        blake3::keyed_hash(&PROOF_MAC_KEY, &data)
            .as_bytes()
            .to_vec()
    }

    pub fn verify(&self) -> Result<(), ProofVerificationError> {
        if self.commitment.is_empty() {
            return Err(ProofVerificationError::MissingCommitment);
        }
        if self.witness_hash.is_empty() {
            return Err(ProofVerificationError::MissingWitnessHash);
        }
        if self.recursion_depth < self.commitments.len() as u32 {
            return Err(ProofVerificationError::InvalidRecursionDepth);
        }

        let expected_signature = Self::compute_aggregated_signature(
            &self.commitment,
            &self.witness_hash,
            self.recursion_depth,
            &self.commitments,
        );
        if self.aggregated_signature != expected_signature {
            return Err(ProofVerificationError::InvalidAggregationSignature);
        }

        let expected_hmac = Self::compute_hmac(&self.commitment, &self.aggregated_signature);
        if self.hmac != expected_hmac {
            return Err(ProofVerificationError::InvalidMac);
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub block: Block,
    pub proof: ConsensusProof,
    pub leader_id: ValidatorId,
}

impl Proposal {
    pub fn block_hash(&self) -> BlockId {
        self.block.hash()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreVote {
    pub block_hash: BlockId,
    pub proof_valid: bool,
    pub validator_id: ValidatorId,
    #[serde(with = "peer_id_serde")]
    pub peer_id: PeerId,
    pub signature: Vec<u8>,
    pub height: u64,
    pub round: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreCommit {
    pub block_hash: BlockId,
    pub validator_id: ValidatorId,
    #[serde(with = "peer_id_serde")]
    pub peer_id: PeerId,
    pub signature: Vec<u8>,
    pub height: u64,
    pub round: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub validator_id: ValidatorId,
    #[serde(with = "peer_id_serde")]
    pub peer_id: PeerId,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commit {
    pub block: Block,
    pub proof: ConsensusProof,
    pub signatures: Vec<Signature>,
}
