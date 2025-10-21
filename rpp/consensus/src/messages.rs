use blake3::Hasher;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;
use std::fmt;

use crate::proof_backend::{ConsensusCircuitDef, ProofBackend, ProofBytes, VerifyingKey};
use crate::validator::ValidatorId;

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
    pub proof_bytes: ProofBytes,
    pub verifying_key: VerifyingKey,
    pub circuit: ConsensusCircuitDef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofVerificationError {
    Backend(String),
}

impl fmt::Display for ProofVerificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofVerificationError::Backend(message) => write!(f, "backend error: {message}"),
        }
    }
}

impl Error for ProofVerificationError {}

impl ConsensusProof {
    pub fn new(
        proof_bytes: ProofBytes,
        verifying_key: VerifyingKey,
        circuit: ConsensusCircuitDef,
    ) -> Self {
        Self {
            proof_bytes,
            verifying_key,
            circuit,
        }
    }

    pub fn from_backend_artifacts(
        proof_bytes: ProofBytes,
        verifying_key: VerifyingKey,
        circuit: ConsensusCircuitDef,
    ) -> Self {
        Self::new(proof_bytes, verifying_key, circuit)
    }

    pub fn proof_bytes(&self) -> &ProofBytes {
        &self.proof_bytes
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    pub fn circuit(&self) -> &ConsensusCircuitDef {
        &self.circuit
    }

    pub fn into_backend_artifacts(self) -> (ProofBytes, VerifyingKey, ConsensusCircuitDef) {
        (self.proof_bytes, self.verifying_key, self.circuit)
    }

    pub fn verify<B: ProofBackend>(&self, backend: &B) -> Result<(), ProofVerificationError> {
        backend
            .verify_consensus(&self.verifying_key, &self.proof_bytes, &self.circuit)
            .map_err(|err| ProofVerificationError::Backend(err.to_string()))
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
