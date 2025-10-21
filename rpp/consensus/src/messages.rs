use blake3::Hasher;
use hex;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;
use std::fmt;

use crate::proof_backend::{
    BackendResult, ConsensusCircuitDef, ConsensusPublicInputs, ProofBackend, ProofBytes,
    ProofSystemKind, VerifyingKey, WitnessBytes, WitnessHeader,
};
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
    #[serde(default)]
    pub public_inputs: ConsensusPublicInputs,
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
        public_inputs: ConsensusPublicInputs,
    ) -> Self {
        Self {
            proof_bytes,
            verifying_key,
            circuit,
            public_inputs,
        }
    }

    pub fn from_backend_artifacts(
        proof_bytes: ProofBytes,
        verifying_key: VerifyingKey,
        circuit: ConsensusCircuitDef,
        public_inputs: ConsensusPublicInputs,
    ) -> Self {
        Self::new(proof_bytes, verifying_key, circuit, public_inputs)
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

    pub fn public_inputs(&self) -> &ConsensusPublicInputs {
        &self.public_inputs
    }

    pub fn into_backend_artifacts(
        self,
    ) -> (ProofBytes, VerifyingKey, ConsensusCircuitDef, ConsensusPublicInputs) {
        (
            self.proof_bytes,
            self.verifying_key,
            self.circuit,
            self.public_inputs,
        )
    }

    pub fn verify<B: ProofBackend>(&self, backend: &B) -> Result<(), ProofVerificationError> {
        backend
            .verify_consensus(
                &self.verifying_key,
                &self.proof_bytes,
                &self.circuit,
                &self.public_inputs,
            )
            .map_err(|err| ProofVerificationError::Backend(err.to_string()))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub block: Block,
    pub proof: ConsensusProof,
    pub certificate: ConsensusCertificate,
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
    pub certificate: ConsensusCertificate,
    pub signatures: Vec<Signature>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TalliedVote {
    pub validator_id: ValidatorId,
    #[serde(with = "peer_id_serde")]
    pub peer_id: PeerId,
    pub signature: Vec<u8>,
    pub voting_power: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusCertificate {
    pub block_hash: BlockId,
    pub height: u64,
    pub round: u64,
    pub total_power: u64,
    pub quorum_threshold: u64,
    pub prevote_power: u64,
    pub precommit_power: u64,
    pub commit_power: u64,
    pub prevotes: Vec<TalliedVote>,
    pub precommits: Vec<TalliedVote>,
}

impl ConsensusCertificate {
    pub fn genesis() -> Self {
        Self {
            block_hash: BlockId("genesis".into()),
            height: 0,
            round: 0,
            total_power: 0,
            quorum_threshold: 0,
            prevote_power: 0,
            precommit_power: 0,
            commit_power: 0,
            prevotes: Vec::new(),
            precommits: Vec::new(),
        }
    }

    pub fn circuit_identifier(&self) -> String {
        format!("consensus-{}-{}", self.height, self.block_hash.0)
    }

    pub fn encode_witness(&self, backend: ProofSystemKind) -> BackendResult<WitnessBytes> {
        let header = WitnessHeader::new(backend, self.circuit_identifier());
        WitnessBytes::encode(&header, self)
    }

    pub fn consensus_public_inputs(&self) -> BackendResult<ConsensusPublicInputs> {
        fn decode_hash(label: &str, value: &str) -> BackendResult<[u8; 32]> {
            let bytes = hex::decode(value).map_err(|err| {
                BackendError::Failure(format!("invalid {label} encoding: {err}"))
            })?;
            if bytes.len() != 32 {
                return Err(BackendError::Failure(format!(
                    "{label} must encode 32 bytes"
                )));
            }
            let mut array = [0u8; 32];
            array.copy_from_slice(&bytes);
            Ok(array)
        }

        let block_hash = decode_hash("block hash", &self.block_hash.0)?;
        let leader_proposal = block_hash;
        Ok(ConsensusPublicInputs {
            block_hash,
            round: self.round,
            leader_proposal,
            quorum_threshold: self.quorum_threshold,
        })
    }
}
