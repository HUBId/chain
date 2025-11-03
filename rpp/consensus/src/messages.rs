use blake3::Hasher;
use hex;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;
use std::fmt;

use crate::proof_backend::{
    BackendError, BackendResult, ConsensusCircuitDef, ConsensusPublicInputs,
    ConsensusVrfPublicEntry, ProofBackend, ProofBytes, ProofSystemKind, VerifyingKey, WitnessBytes,
    WitnessHeader,
};
use crate::validator::ValidatorId;
use rpp_chain::stwo::params::StarkParameters;
use rpp_chain::stwo::FieldElement;
use rpp_crypto_vrf::{VRF_PREOUTPUT_LENGTH, VRF_PROOF_LENGTH};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusVrfPoseidonInput {
    #[serde(default)]
    pub digest: String,
    #[serde(default)]
    pub last_block_header: String,
    #[serde(default)]
    pub epoch: String,
    #[serde(default)]
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
    #[serde(default)]
    pub randomness: String,
    #[serde(default)]
    pub pre_output: String,
    #[serde(default)]
    pub proof: String,
    #[serde(default)]
    pub public_key: String,
    #[serde(default)]
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
    pub public_inputs: ConsensusPublicInputs,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsensusBindingDigests {
    pub vrf_output: [u8; 32],
    pub vrf_proof: [u8; 32],
    pub witness_commitment: [u8; 32],
    pub reputation_root: [u8; 32],
    pub quorum_bitmap: [u8; 32],
    pub quorum_signature: [u8; 32],
}

fn field_to_array(value: &FieldElement) -> [u8; 32] {
    let repr = value.to_bytes();
    let mut bytes = [0u8; 32];
    let offset = bytes.len().saturating_sub(repr.len());
    bytes[offset..offset + repr.len()].copy_from_slice(&repr);
    bytes
}

fn binding_from_bytes<I>(
    parameters: &StarkParameters,
    hasher: &rpp_chain::stwo::params::PoseidonHasher,
    block_hash: &FieldElement,
    values: I,
) -> FieldElement
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    let zero = FieldElement::zero(parameters.modulus());
    let mut accumulator = block_hash.clone();
    for value in values {
        let element = parameters.element_from_bytes(value.as_ref());
        accumulator = hasher.hash(&[accumulator.clone(), element, zero.clone()]);
    }
    accumulator
}

const VRF_PUBLIC_KEY_LENGTH: usize = 32;

fn decode_hex_array<const N: usize>(label: &str, value: &str) -> BackendResult<[u8; N]> {
    let bytes = hex::decode(value)
        .map_err(|err| BackendError::Failure(format!("invalid {label} encoding: {err}")))?;
    if bytes.len() != N {
        return Err(BackendError::Failure(format!(
            "{label} must encode {N} bytes"
        )));
    }
    let mut array = [0u8; N];
    array.copy_from_slice(&bytes);
    Ok(array)
}

fn decode_hex_vec(label: &str, value: &str, expected: usize) -> BackendResult<Vec<u8>> {
    let bytes = hex::decode(value)
        .map_err(|err| BackendError::Failure(format!("invalid {label} encoding: {err}")))?;
    if bytes.len() != expected {
        return Err(BackendError::Failure(format!(
            "{label} must encode {expected} bytes"
        )));
    }
    Ok(bytes)
}

fn decode_hash(label: &str, value: &str) -> BackendResult<[u8; 32]> {
    decode_hex_array::<32>(label, value)
}

pub fn compute_consensus_bindings(
    block_hash: &[u8; 32],
    vrf_entries: &[ConsensusVrfPublicEntry],
    witness_commitments: &[[u8; 32]],
    reputation_roots: &[[u8; 32]],
    quorum_bitmap_root: &[u8; 32],
    quorum_signature_root: &[u8; 32],
) -> BackendResult<ConsensusBindingDigests> {
    let parameters = StarkParameters::blueprint_default();
    let hasher = parameters.poseidon_hasher();
    let block_hash_element = parameters.element_from_bytes(block_hash);

    let vrf_output = binding_from_bytes(
        &parameters,
        &hasher,
        &block_hash_element,
        vrf_entries.iter().map(|entry| entry.randomness.as_slice()),
    );
    let vrf_proof = binding_from_bytes(
        &parameters,
        &hasher,
        &block_hash_element,
        vrf_entries.iter().map(|entry| entry.proof.as_slice()),
    );
    let witness_commitment = binding_from_bytes(
        &parameters,
        &hasher,
        &block_hash_element,
        witness_commitments,
    );
    let reputation_root =
        binding_from_bytes(&parameters, &hasher, &block_hash_element, reputation_roots);
    let quorum_bitmap = binding_from_bytes(
        &parameters,
        &hasher,
        &block_hash_element,
        std::iter::once(quorum_bitmap_root.as_slice()),
    );
    let quorum_signature = binding_from_bytes(
        &parameters,
        &hasher,
        &block_hash_element,
        std::iter::once(quorum_signature_root.as_slice()),
    );

    Ok(ConsensusBindingDigests {
        vrf_output: field_to_array(&vrf_output),
        vrf_proof: field_to_array(&vrf_proof),
        witness_commitment: field_to_array(&witness_commitment),
        reputation_root: field_to_array(&reputation_root),
        quorum_bitmap: field_to_array(&quorum_bitmap),
        quorum_signature: field_to_array(&quorum_signature),
    })
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
    ) -> (
        ProofBytes,
        VerifyingKey,
        ConsensusCircuitDef,
        ConsensusPublicInputs,
    ) {
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
    pub metadata: ConsensusProofMetadata,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusProofMetadata {
    #[serde(default)]
    pub vrf_entries: Vec<ConsensusVrfEntry>,
    pub witness_commitments: Vec<String>,
    pub reputation_roots: Vec<String>,
    pub epoch: u64,
    pub slot: u64,
    pub quorum_bitmap_root: String,
    pub quorum_signature_root: String,
}

impl Default for ConsensusProofMetadata {
    fn default() -> Self {
        let zero_digest = "00".repeat(32);
        Self {
            vrf_entries: vec![ConsensusVrfEntry::default()],
            witness_commitments: vec![zero_digest.clone()],
            reputation_roots: vec![zero_digest.clone()],
            epoch: 0,
            slot: 0,
            quorum_bitmap_root: zero_digest.clone(),
            quorum_signature_root: zero_digest,
        }
    }
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
            metadata: ConsensusProofMetadata::default(),
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
        let block_hash = decode_hash("block hash", &self.block_hash.0)?;
        let leader_proposal = block_hash;

        if self.metadata.vrf_entries.is_empty() {
            return Err(BackendError::Failure(
                "consensus metadata missing VRF entries".into(),
            ));
        }
        if self.metadata.witness_commitments.is_empty() {
            return Err(BackendError::Failure(
                "consensus metadata missing witness commitments".into(),
            ));
        }
        if self.metadata.reputation_roots.is_empty() {
            return Err(BackendError::Failure(
                "consensus metadata missing reputation roots".into(),
            ));
        }

        let mut vrf_public_entries = Vec::with_capacity(self.metadata.vrf_entries.len());

        for (index, entry) in self.metadata.vrf_entries.iter().enumerate() {
            if entry.randomness.trim().is_empty() {
                return Err(BackendError::Failure(format!(
                    "consensus metadata vrf entry #{index} missing randomness",
                )));
            }
            if entry.pre_output.trim().is_empty() {
                return Err(BackendError::Failure(format!(
                    "consensus metadata vrf entry #{index} missing pre-output",
                )));
            }
            if entry.proof.trim().is_empty() {
                return Err(BackendError::Failure(format!(
                    "consensus metadata vrf entry #{index} missing proof",
                )));
            }
            if entry.public_key.trim().is_empty() {
                return Err(BackendError::Failure(format!(
                    "consensus metadata vrf entry #{index} missing public key",
                )));
            }
            if entry.poseidon.digest.trim().is_empty() {
                return Err(BackendError::Failure(format!(
                    "consensus metadata vrf entry #{index} missing poseidon digest",
                )));
            }
            if entry.poseidon.last_block_header.trim().is_empty() {
                return Err(BackendError::Failure(format!(
                    "consensus metadata vrf entry #{index} missing poseidon last block header",
                )));
            }
            if entry.poseidon.epoch.trim().is_empty() {
                return Err(BackendError::Failure(format!(
                    "consensus metadata vrf entry #{index} missing poseidon epoch",
                )));
            }
            if entry.poseidon.tier_seed.trim().is_empty() {
                return Err(BackendError::Failure(format!(
                    "consensus metadata vrf entry #{index} missing poseidon tier seed",
                )));
            }

            let randomness = decode_hash(&format!("vrf randomness #{index}"), &entry.randomness)?;
            let pre_output = decode_hex_array::<VRF_PREOUTPUT_LENGTH>(
                &format!("vrf pre-output #{index}"),
                &entry.pre_output,
            )?;
            let proof = decode_hex_vec(
                &format!("vrf proof #{index}"),
                &entry.proof,
                VRF_PROOF_LENGTH,
            )?;
            let public_key = decode_hex_array::<VRF_PUBLIC_KEY_LENGTH>(
                &format!("vrf public key #{index}"),
                &entry.public_key,
            )?;
            let poseidon_digest = decode_hash(
                &format!("vrf poseidon digest #{index}"),
                &entry.poseidon.digest,
            )?;
            let poseidon_last_block_header = decode_hash(
                &format!("vrf poseidon last block header #{index}"),
                &entry.poseidon.last_block_header,
            )?;
            let poseidon_epoch = entry.poseidon.epoch.trim().parse::<u64>().map_err(|err| {
                BackendError::Failure(format!("invalid vrf entry #{index} poseidon epoch: {err}"))
            })?;
            let poseidon_tier_seed = decode_hash(
                &format!("vrf poseidon tier seed #{index}"),
                &entry.poseidon.tier_seed,
            )?;

            if poseidon_last_block_header != block_hash {
                return Err(BackendError::Failure(format!(
                    "consensus metadata vrf entry #{index} poseidon last block header mismatch block hash",
                )));
            }
            if poseidon_epoch != self.metadata.epoch {
                return Err(BackendError::Failure(format!(
                    "consensus metadata vrf entry #{index} poseidon epoch {} does not match certificate epoch {}",
                    poseidon_epoch, self.metadata.epoch
                )));
            }

            vrf_public_entries.push(ConsensusVrfPublicEntry {
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

        let quorum_bitmap_root =
            decode_hash("quorum bitmap root", &self.metadata.quorum_bitmap_root)?;
        let quorum_signature_root = decode_hash(
            "quorum signature root",
            &self.metadata.quorum_signature_root,
        )?;

        let decode_digests = |label: &str, values: &[String]| -> BackendResult<Vec<[u8; 32]>> {
            values
                .iter()
                .enumerate()
                .map(|(index, value)| decode_hash(&format!("{label} #{index}"), value))
                .collect()
        };

        let witness_commitments =
            decode_digests("witness commitment", &self.metadata.witness_commitments)?;
        let reputation_roots = decode_digests("reputation root", &self.metadata.reputation_roots)?;

        let bindings = compute_consensus_bindings(
            &block_hash,
            &vrf_public_entries,
            &witness_commitments,
            &reputation_roots,
            &quorum_bitmap_root,
            &quorum_signature_root,
        )?;

        Ok(ConsensusPublicInputs {
            block_hash,
            round: self.round,
            leader_proposal,
            epoch: self.metadata.epoch,
            slot: self.metadata.slot,
            quorum_threshold: self.quorum_threshold,
            quorum_bitmap_root,
            quorum_signature_root,
            vrf_entries: vrf_public_entries,
            witness_commitments,
            reputation_roots,
            vrf_output_binding: bindings.vrf_output,
            vrf_proof_binding: bindings.vrf_proof,
            witness_commitment_binding: bindings.witness_commitment,
            reputation_root_binding: bindings.reputation_root,
            quorum_bitmap_binding: bindings.quorum_bitmap,
            quorum_signature_binding: bindings.quorum_signature,
        })
    }
}
