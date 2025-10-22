use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::vendor::PeerId;
use base64::{engine::general_purpose, Engine as _};
use blake3::Hash;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::topics::GossipTopic;

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("validator rejected payload: {0}")]
    Validation(String),
    #[error("unknown proposal")]
    UnknownProposal,
    #[error("duplicate message")]
    Duplicate,
    #[error("unknown voter")]
    UnknownVoter,
    #[error("snapshot not found")]
    SnapshotNotFound,
    #[error("snapshot verification failed: {0}")]
    SnapshotVerification(String),
    #[error("persistence error: {0}")]
    Persistence(String),
}

/// Handler invoked whenever a gossip proof is received on the `proofs` topic.
pub trait ProofValidator: std::fmt::Debug + Send + Sync + 'static {
    fn validate(&self, peer: &PeerId, payload: &[u8]) -> Result<(), PipelineError>;
}

#[derive(Debug, Default, Clone)]
pub struct JsonProofValidator;

fn is_hex_digest(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

impl ProofValidator for JsonProofValidator {
    fn validate(&self, _peer: &PeerId, payload: &[u8]) -> Result<(), PipelineError> {
        if payload.is_empty() {
            return Err(PipelineError::Validation("empty proof payload".into()));
        }
        let value: serde_json::Value = serde_json::from_slice(payload).map_err(|err| {
            PipelineError::Validation(format!("invalid proof payload encoding: {err}"))
        })?;
        let bundle = value
            .as_object()
            .ok_or_else(|| PipelineError::Validation("proof payload must be an object".into()))?;
        if !bundle.contains_key("transaction") {
            return Err(PipelineError::Validation(
                "proof payload missing transaction".into(),
            ));
        }
        let proof_value = bundle
            .get("proof")
            .ok_or_else(|| PipelineError::Validation("proof payload missing proof field".into()))?;
        let proof_obj = proof_value
            .as_object()
            .ok_or_else(|| PipelineError::Validation("proof field must be an object".into()))?;
        let stwo = proof_obj
            .get("stwo")
            .ok_or_else(|| PipelineError::Validation("unsupported proof backend".into()))?;
        let commitment = stwo
            .get("commitment")
            .and_then(|value| value.as_str())
            .ok_or_else(|| PipelineError::Validation("proof payload missing commitment".into()))?;
        if !is_hex_digest(commitment) {
            return Err(PipelineError::Validation(
                "proof commitment must be a 32-byte hex digest".into(),
            ));
        }
        if let Some(previous) = stwo.get("previous_commitment") {
            let Some(previous_commitment) = previous.as_str() else {
                return Err(PipelineError::Validation(
                    "previous commitment must be a string".into(),
                ));
            };
            if !is_hex_digest(previous_commitment) {
                return Err(PipelineError::Validation(
                    "previous commitment must be a 32-byte hex digest".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ProofRecord {
    pub peer: PeerId,
    pub topic: GossipTopic,
    pub payload: Vec<u8>,
    pub digest: Hash,
    pub received_at: SystemTime,
}

pub trait ProofStorage: std::fmt::Debug + Send + Sync + 'static {
    fn persist(&self, record: &ProofRecord) -> Result<(), PipelineError>;
    fn load(&self) -> Result<Vec<ProofRecord>, PipelineError> {
        Ok(Vec::new())
    }
}

#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct MemoryProofStorage {
    records: parking_lot::Mutex<Vec<ProofRecord>>,
}

impl ProofStorage for MemoryProofStorage {
    fn persist(&self, record: &ProofRecord) -> Result<(), PipelineError> {
        self.records.lock().push(record.clone());
        Ok(())
    }

    fn load(&self) -> Result<Vec<ProofRecord>, PipelineError> {
        Ok(self.records())
    }
}

impl MemoryProofStorage {
    pub fn records(&self) -> Vec<ProofRecord> {
        self.records.lock().clone()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredProofRecord {
    peer: String,
    topic: String,
    payload: String,
    digest: String,
    received_at: u64,
}

impl From<&ProofRecord> for StoredProofRecord {
    fn from(record: &ProofRecord) -> Self {
        let received_at = record
            .received_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            peer: record.peer.to_base58(),
            topic: record.topic.as_str().to_string(),
            payload: general_purpose::STANDARD.encode(&record.payload),
            digest: record.digest.to_hex().to_string(),
            received_at,
        }
    }
}

impl TryFrom<StoredProofRecord> for ProofRecord {
    type Error = PipelineError;

    fn try_from(value: StoredProofRecord) -> Result<Self, Self::Error> {
        let peer = PeerId::from_str(&value.peer)
            .map_err(|err| PipelineError::Persistence(err.to_string()))?;
        let topic = GossipTopic::from_str(&value.topic)
            .ok_or_else(|| PipelineError::Persistence("unknown topic".into()))?;
        let payload = general_purpose::STANDARD
            .decode(&value.payload)
            .map_err(|err: base64::DecodeError| PipelineError::Persistence(err.to_string()))?;
        let digest_bytes =
            hex::decode(value.digest).map_err(|err| PipelineError::Persistence(err.to_string()))?;
        if digest_bytes.len() != 32 {
            return Err(PipelineError::Persistence("invalid digest".into()));
        }
        let mut digest_array = [0u8; 32];
        digest_array.copy_from_slice(&digest_bytes);
        let received_at = UNIX_EPOCH + Duration::from_secs(value.received_at);
        Ok(ProofRecord {
            peer,
            topic,
            payload,
            digest: Hash::from(digest_array),
            received_at,
        })
    }
}

#[derive(Debug)]
pub struct PersistentProofStorage {
    path: PathBuf,
    retain: usize,
    cache: parking_lot::Mutex<Vec<ProofRecord>>,
}

impl PersistentProofStorage {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, PipelineError> {
        Self::with_capacity(path, 1024)
    }

    pub fn with_capacity(path: impl Into<PathBuf>, retain: usize) -> Result<Self, PipelineError> {
        let path = path.into();
        let cache = if path.exists() {
            let raw = fs::read_to_string(&path)
                .map_err(|err| PipelineError::Persistence(err.to_string()))?;
            let stored: Vec<StoredProofRecord> = serde_json::from_str(&raw)
                .map_err(|err: serde_json::Error| PipelineError::Persistence(err.to_string()))?;
            stored
                .into_iter()
                .map(ProofRecord::try_from)
                .collect::<Result<Vec<_>, _>>()?
        } else {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|err| PipelineError::Persistence(err.to_string()))?;
            }
            Vec::new()
        };
        Ok(Self {
            path,
            retain: retain.max(1),
            cache: parking_lot::Mutex::new(cache),
        })
    }

    fn persist_inner(&self, records: &[ProofRecord]) -> Result<(), PipelineError> {
        let stored: Vec<StoredProofRecord> = records.iter().map(StoredProofRecord::from).collect();
        let encoded = serde_json::to_string_pretty(&stored)
            .map_err(|err: serde_json::Error| PipelineError::Persistence(err.to_string()))?;
        fs::write(&self.path, encoded).map_err(|err| PipelineError::Persistence(err.to_string()))
    }
}

impl ProofStorage for PersistentProofStorage {
    fn persist(&self, record: &ProofRecord) -> Result<(), PipelineError> {
        let mut guard = self.cache.lock();
        guard.push(record.clone());
        if guard.len() > self.retain {
            let overflow = guard.len() - self.retain;
            guard.drain(0..overflow);
        }
        self.persist_inner(&guard)
    }

    fn load(&self) -> Result<Vec<ProofRecord>, PipelineError> {
        Ok(self.cache.lock().clone())
    }
}

/// Deduplicating proof mempool fed directly by gossip.
#[derive(Debug)]
pub struct ProofMempool {
    seen: HashSet<Hash>,
    queue: VecDeque<ProofRecord>,
    validator: Arc<dyn ProofValidator>,
    storage: Arc<dyn ProofStorage>,
}

impl ProofMempool {
    pub fn new(
        validator: Arc<dyn ProofValidator>,
        storage: Arc<dyn ProofStorage>,
    ) -> Result<Self, PipelineError> {
        let mut seen = HashSet::new();
        let mut queue = VecDeque::new();
        for record in storage.load()? {
            seen.insert(record.digest);
            queue.push_back(record);
        }
        Ok(Self {
            seen,
            queue,
            validator,
            storage,
        })
    }

    pub fn ingest(
        &mut self,
        peer: PeerId,
        topic: GossipTopic,
        payload: Vec<u8>,
    ) -> Result<bool, PipelineError> {
        let digest = blake3::hash(&payload);
        if !self.seen.insert(digest) {
            return Err(PipelineError::Duplicate);
        }
        if topic != GossipTopic::Proofs {
            return Err(PipelineError::Validation(format!(
                "unexpected topic: {:?}",
                topic
            )));
        }
        self.validator.validate(&peer, &payload)?;
        let record = ProofRecord {
            peer,
            topic,
            payload,
            digest,
            received_at: SystemTime::now(),
        };
        self.storage.persist(&record)?;
        self.queue.push_back(record);
        Ok(true)
    }

    pub fn pop(&mut self) -> Option<ProofRecord> {
        self.queue.pop_front()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }
}

#[derive(Debug, Clone)]
pub struct BlockProposal {
    pub id: Vec<u8>,
    pub proposer: PeerId,
    pub payload: Vec<u8>,
    pub received_at: SystemTime,
}

#[derive(Debug, Clone)]
pub struct VoteRecord {
    pub block_id: Vec<u8>,
    pub voter: PeerId,
    pub round: u64,
    pub payload: Vec<u8>,
    pub received_at: SystemTime,
}

#[derive(Debug, Clone)]
pub struct ProposalState {
    proposal: BlockProposal,
    votes: HashMap<PeerId, VoteRecord>,
    power_accumulated: f64,
}

#[derive(Debug)]
pub enum VoteOutcome {
    Recorded { reached_quorum: bool, power: f64 },
    Duplicate,
}

#[derive(Debug)]
pub struct ConsensusPipeline {
    voters: HashMap<PeerId, f64>,
    total_power: f64,
    threshold_factor: f64,
    proposals: HashMap<Vec<u8>, ProposalState>,
}

impl ConsensusPipeline {
    pub fn new() -> Self {
        Self {
            voters: HashMap::new(),
            total_power: 0.0,
            threshold_factor: 2.0 / 3.0,
            proposals: HashMap::new(),
        }
    }

    pub fn register_voter(&mut self, peer: PeerId, power: f64) {
        let entry = self.voters.entry(peer).or_insert(0.0);
        self.total_power -= *entry;
        *entry = power.max(0.0);
        self.total_power += *entry;
    }

    pub fn remove_voter(&mut self, peer: &PeerId) {
        if let Some(power) = self.voters.remove(peer) {
            self.total_power -= power;
        }
    }

    pub fn set_threshold_factor(&mut self, factor: f64) {
        self.threshold_factor = factor.clamp(0.0, 1.0);
    }

    pub fn ingest_proposal(
        &mut self,
        id: Vec<u8>,
        proposer: PeerId,
        payload: Vec<u8>,
    ) -> Result<(), PipelineError> {
        let proposal = BlockProposal {
            id: id.clone(),
            proposer,
            payload,
            received_at: SystemTime::now(),
        };
        self.proposals.insert(
            id,
            ProposalState {
                proposal,
                votes: HashMap::new(),
                power_accumulated: 0.0,
            },
        );
        Ok(())
    }

    pub fn ingest_vote(
        &mut self,
        block_id: &[u8],
        voter: PeerId,
        round: u64,
        payload: Vec<u8>,
    ) -> Result<VoteOutcome, PipelineError> {
        let power = match self.voters.get(&voter) {
            Some(power) if *power > 0.0 => *power,
            _ => return Err(PipelineError::UnknownVoter),
        };
        let threshold = self.quorum_threshold();
        let state = self
            .proposals
            .get_mut(block_id)
            .ok_or(PipelineError::UnknownProposal)?;
        if state.votes.contains_key(&voter) {
            return Ok(VoteOutcome::Duplicate);
        }
        let record = VoteRecord {
            block_id: block_id.to_vec(),
            voter,
            round,
            payload,
            received_at: SystemTime::now(),
        };
        state.power_accumulated += power;
        state.votes.insert(voter, record);
        Ok(VoteOutcome::Recorded {
            reached_quorum: state.power_accumulated >= threshold,
            power: state.power_accumulated,
        })
    }

    pub fn proposal(&self, id: &[u8]) -> Option<&BlockProposal> {
        self.proposals.get(id).map(|state| &state.proposal)
    }

    pub fn votes(&self, id: &[u8]) -> Option<Vec<VoteRecord>> {
        self.proposals
            .get(id)
            .map(|state| state.votes.values().cloned().collect())
    }

    fn quorum_threshold(&self) -> f64 {
        self.total_power * self.threshold_factor
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotChunk {
    pub root: Hash,
    pub index: u64,
    pub total: u64,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct SnapshotStore {
    snapshots: HashMap<Hash, Vec<u8>>,
    chunk_size: usize,
}

impl SnapshotStore {
    pub fn new(chunk_size: usize) -> Self {
        Self {
            snapshots: HashMap::new(),
            chunk_size: chunk_size.max(1),
        }
    }

    pub fn insert(&mut self, payload: Vec<u8>) -> Hash {
        let root = blake3::hash(&payload);
        self.snapshots.insert(root, payload);
        root
    }

    pub fn has_snapshot(&self, root: &Hash) -> bool {
        self.snapshots.contains_key(root)
    }

    pub fn stream(&self, root: &Hash) -> Result<Vec<SnapshotChunk>, PipelineError> {
        let data = self
            .snapshots
            .get(root)
            .ok_or(PipelineError::SnapshotNotFound)?;
        let mut chunks = Vec::new();
        let total = ((data.len() as f64) / (self.chunk_size as f64)).ceil() as u64;
        for (index, window) in data.chunks(self.chunk_size).enumerate() {
            chunks.push(SnapshotChunk {
                root: *root,
                index: index as u64,
                total,
                data: window.to_vec(),
            });
        }
        Ok(chunks)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkGlobalStateCommitments {
    pub global_state_root: String,
    pub utxo_root: String,
    pub reputation_root: String,
    pub timetoke_root: String,
    pub zsi_root: String,
    pub proof_root: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSnapshotSummary {
    pub height: u64,
    pub block_hash: String,
    pub commitments: NetworkGlobalStateCommitments,
    pub chain_commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBlockMetadata {
    pub height: u64,
    pub hash: String,
    pub timestamp: u64,
    pub previous_state_root: String,
    pub new_state_root: String,
    pub proof_hash: String,
    pub recursion_anchor: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPayloadExpectations {
    pub transaction_proofs: usize,
    pub transaction_witnesses: usize,
    pub timetoke_witnesses: usize,
    pub reputation_witnesses: usize,
    pub zsi_witnesses: usize,
    pub consensus_witnesses: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkReconstructionRequest {
    pub height: u64,
    pub block_hash: String,
    pub tx_root: String,
    pub state_root: String,
    pub utxo_root: String,
    pub reputation_root: String,
    pub timetoke_root: String,
    pub zsi_root: String,
    pub proof_root: String,
    pub pruning_commitment: String,
    pub aggregated_commitment: String,
    pub previous_commitment: Option<String>,
    #[serde(default)]
    pub payload_expectations: NetworkPayloadExpectations,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStateSyncChunk {
    pub start_height: u64,
    pub end_height: u64,
    pub requests: Vec<NetworkReconstructionRequest>,
    #[serde(default)]
    pub proofs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkLightClientUpdate {
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub proof_commitment: String,
    #[serde(default)]
    pub previous_commitment: Option<String>,
    #[serde(default)]
    pub recursive_proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStateSyncPlan {
    pub snapshot: NetworkSnapshotSummary,
    pub tip: NetworkBlockMetadata,
    pub chunks: Vec<NetworkStateSyncChunk>,
    pub light_client_updates: Vec<NetworkLightClientUpdate>,
}

pub trait RecursiveProofVerifier: std::fmt::Debug + Send + Sync + 'static {
    fn verify_recursive(
        &self,
        proof: &[u8],
        expected_commitment: &str,
        previous_commitment: Option<&str>,
    ) -> Result<(), PipelineError>;
}

#[derive(Debug, Default)]
pub struct BasicRecursiveProofVerifier;

impl RecursiveProofVerifier for BasicRecursiveProofVerifier {
    fn verify_recursive(
        &self,
        proof: &[u8],
        expected_commitment: &str,
        previous_commitment: Option<&str>,
    ) -> Result<(), PipelineError> {
        if proof.is_empty() {
            return Err(PipelineError::Validation(
                "recursive proof payload is empty".into(),
            ));
        }
        if !is_hex_digest(expected_commitment) {
            return Err(PipelineError::Validation(
                "expected commitment must be a 32-byte hex digest".into(),
            ));
        }
        if let Some(previous) = previous_commitment {
            if !is_hex_digest(previous) {
                return Err(PipelineError::Validation(
                    "previous commitment must be a 32-byte hex digest".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct LightClientSync {
    verifier: Arc<dyn RecursiveProofVerifier>,
    plan: Option<ActivePlan>,
    received_chunks: HashMap<usize, [u8; 32]>,
    accepted_updates: HashSet<u64>,
}

impl Default for LightClientSync {
    fn default() -> Self {
        Self::new(Arc::new(BasicRecursiveProofVerifier::default()))
    }
}

impl LightClientSync {
    pub fn new(verifier: Arc<dyn RecursiveProofVerifier>) -> Self {
        Self {
            verifier,
            plan: None,
            received_chunks: HashMap::new(),
            accepted_updates: HashSet::new(),
        }
    }

    pub fn ingest_plan(&mut self, payload: &[u8]) -> Result<(), PipelineError> {
        let plan: NetworkStateSyncPlan = serde_json::from_slice(payload)
            .map_err(|err| PipelineError::Validation(format!("invalid plan payload: {err}")))?;
        let active = ActivePlan::try_from(plan)?;
        self.plan = Some(active);
        self.received_chunks.clear();
        self.accepted_updates.clear();
        Ok(())
    }

    pub fn ingest_light_client_update(&mut self, payload: &[u8]) -> Result<(), PipelineError> {
        let update: NetworkLightClientUpdate = serde_json::from_slice(payload)
            .map_err(|err| PipelineError::Validation(format!("invalid update payload: {err}")))?;
        let plan = self
            .plan
            .as_mut()
            .ok_or_else(|| PipelineError::SnapshotVerification("no active plan".into()))?;
        let Some(index) = plan.update_index_by_height.get(&update.height).copied() else {
            return Err(PipelineError::SnapshotVerification(format!(
                "unexpected light client height {}",
                update.height
            )));
        };
        if self.accepted_updates.contains(&update.height) {
            return Err(PipelineError::Duplicate);
        }
        let expected = &plan.updates[index];
        if expected.block_hash != update.block_hash {
            return Err(PipelineError::SnapshotVerification(format!(
                "block hash mismatch for height {}",
                update.height
            )));
        }
        if expected.state_root != update.state_root {
            return Err(PipelineError::SnapshotVerification(format!(
                "state root mismatch for height {}",
                update.height
            )));
        }
        if expected.commitment != update.proof_commitment {
            return Err(PipelineError::SnapshotVerification(format!(
                "commitment mismatch for height {}",
                update.height
            )));
        }
        if index > 0 {
            let previous_height = plan.updates[index - 1].height;
            if !self.accepted_updates.contains(&previous_height) {
                return Err(PipelineError::SnapshotVerification(format!(
                    "missing checkpoint for height {}",
                    previous_height
                )));
            }
        }
        let expected_previous = if index == 0 {
            expected
                .expected_previous
                .as_deref()
                .or_else(|| Some(plan.snapshot.chain_commitment.as_str()))
        } else {
            Some(plan.updates[index - 1].commitment.as_str())
        };
        if let Some(ref advertised) = update.previous_commitment {
            if Some(advertised.as_str()) != expected_previous {
                return Err(PipelineError::SnapshotVerification(format!(
                    "previous commitment mismatch for height {}",
                    update.height
                )));
            }
        }
        let proof_bytes = general_purpose::STANDARD
            .decode(update.recursive_proof.as_bytes())
            .map_err(|err: base64::DecodeError| {
                PipelineError::Validation(format!("invalid proof encoding: {err}"))
            })?;
        if proof_bytes.is_empty() {
            return Err(PipelineError::SnapshotVerification(
                "empty recursive proof".into(),
            ));
        }
        self.verifier
            .verify_recursive(&proof_bytes, &expected.commitment, expected_previous)?;
        self.accepted_updates.insert(update.height);
        Ok(())
    }

    pub fn ingest_chunk(&mut self, payload: &[u8]) -> Result<(), PipelineError> {
        let chunk: NetworkStateSyncChunk = serde_json::from_slice(payload)
            .map_err(|err| PipelineError::Validation(format!("invalid chunk payload: {err}")))?;
        let plan = self
            .plan
            .as_ref()
            .ok_or_else(|| PipelineError::SnapshotVerification("no active plan".into()))?;
        let Some(index) = plan.chunk_index_by_start.get(&chunk.start_height).copied() else {
            return Err(PipelineError::SnapshotVerification(format!(
                "unexpected chunk starting at {}",
                chunk.start_height
            )));
        };
        let expected = &plan.chunks[index];
        if expected.end_height != chunk.end_height {
            return Err(PipelineError::SnapshotVerification(format!(
                "chunk end height mismatch for start {}",
                chunk.start_height
            )));
        }
        if chunk.requests.len() != expected.aggregated_commitments.len() {
            return Err(PipelineError::SnapshotVerification(format!(
                "chunk request count mismatch for start {}",
                chunk.start_height
            )));
        }
        for (request, expected_commitment) in chunk
            .requests
            .iter()
            .zip(expected.aggregated_commitments.iter())
        {
            let commitment = decode_hex_digest(&request.aggregated_commitment)?;
            if &commitment != expected_commitment {
                return Err(PipelineError::SnapshotVerification(format!(
                    "aggregated commitment mismatch at height {}",
                    request.height
                )));
            }
        }
        if chunk.proofs.is_empty() {
            return Err(PipelineError::SnapshotVerification(format!(
                "missing merkle proofs for chunk starting at {}",
                chunk.start_height
            )));
        }
        let mut proofs = Vec::with_capacity(chunk.proofs.len());
        for proof in &chunk.proofs {
            proofs.push(decode_base64_digest(proof)?);
        }
        let mut leaves = proofs;
        let root = compute_merkle_root(&mut leaves);
        if root != expected.expected_root {
            return Err(PipelineError::SnapshotVerification(format!(
                "chunk root mismatch for start {}",
                chunk.start_height
            )));
        }
        self.received_chunks.insert(index, root);
        Ok(())
    }

    pub fn verify(&self) -> Result<bool, PipelineError> {
        let Some(plan) = &self.plan else {
            return Ok(false);
        };
        if self.received_chunks.len() != plan.chunks.len() {
            return Err(PipelineError::SnapshotVerification(
                "incomplete chunk set".into(),
            ));
        }
        for chunk in &plan.chunks {
            if !self.received_chunks.contains_key(&chunk.index) {
                return Err(PipelineError::SnapshotVerification(format!(
                    "missing chunk starting at {}",
                    chunk.start_height
                )));
            }
        }
        if self.accepted_updates.len() != plan.updates.len() {
            return Err(PipelineError::SnapshotVerification(
                "missing recursive proofs".into(),
            ));
        }
        for update in &plan.updates {
            if !self.accepted_updates.contains(&update.height) {
                return Err(PipelineError::SnapshotVerification(format!(
                    "missing proof for height {}",
                    update.height
                )));
            }
        }
        let mut chunk_roots: Vec<[u8; 32]> = Vec::with_capacity(plan.chunks.len());
        for chunk in &plan.chunks {
            let root = self.received_chunks.get(&chunk.index).ok_or_else(|| {
                PipelineError::SnapshotVerification(format!(
                    "missing chunk starting at {}",
                    chunk.start_height
                ))
            })?;
            chunk_roots.push(*root);
        }
        let computed_snapshot = compute_merkle_root(&mut chunk_roots);
        if computed_snapshot != plan.snapshot_commitment {
            return Err(PipelineError::SnapshotVerification(
                "snapshot commitment mismatch".into(),
            ));
        }
        Ok(true)
    }
}

#[derive(Debug, Clone)]
struct ExpectedChunk {
    index: usize,
    start_height: u64,
    end_height: u64,
    aggregated_commitments: Vec<[u8; 32]>,
    expected_root: [u8; 32],
}

#[derive(Debug, Clone)]
struct ExpectedUpdate {
    height: u64,
    block_hash: String,
    state_root: String,
    commitment: String,
    expected_previous: Option<String>,
}

#[derive(Debug, Clone)]
struct ActivePlan {
    snapshot: NetworkSnapshotSummary,
    snapshot_commitment: [u8; 32],
    chunks: Vec<ExpectedChunk>,
    chunk_index_by_start: BTreeMap<u64, usize>,
    updates: Vec<ExpectedUpdate>,
    update_index_by_height: BTreeMap<u64, usize>,
}

impl TryFrom<NetworkStateSyncPlan> for ActivePlan {
    type Error = PipelineError;

    fn try_from(plan: NetworkStateSyncPlan) -> Result<Self, Self::Error> {
        let snapshot_commitment = decode_hex_digest(&plan.snapshot.chain_commitment)?;
        let mut chunks = Vec::with_capacity(plan.chunks.len());
        let mut chunk_index_by_start = BTreeMap::new();
        for (index, chunk) in plan.chunks.iter().enumerate() {
            if chunk.requests.is_empty() {
                return Err(PipelineError::SnapshotVerification(format!(
                    "empty chunk starting at {}",
                    chunk.start_height
                )));
            }
            if chunk_index_by_start
                .insert(chunk.start_height, index)
                .is_some()
            {
                return Err(PipelineError::SnapshotVerification(format!(
                    "duplicate chunk start height {}",
                    chunk.start_height
                )));
            }
            let mut aggregated = Vec::with_capacity(chunk.requests.len());
            for request in &chunk.requests {
                aggregated.push(decode_hex_digest(&request.aggregated_commitment)?);
            }
            let mut leaves = aggregated.clone();
            let expected_root = compute_merkle_root(&mut leaves);
            chunks.push(ExpectedChunk {
                index,
                start_height: chunk.start_height,
                end_height: chunk.end_height,
                aggregated_commitments: aggregated,
                expected_root,
            });
        }

        let mut updates = Vec::with_capacity(plan.light_client_updates.len());
        let mut update_index_by_height = BTreeMap::new();
        let mut previous_commitment = Some(plan.snapshot.chain_commitment.clone());
        for (index, update) in plan.light_client_updates.iter().enumerate() {
            if update.proof_commitment.is_empty() {
                return Err(PipelineError::SnapshotVerification(format!(
                    "missing proof commitment for height {}",
                    update.height
                )));
            }
            if update_index_by_height
                .insert(update.height, index)
                .is_some()
            {
                return Err(PipelineError::SnapshotVerification(format!(
                    "duplicate light client height {}",
                    update.height
                )));
            }
            let expected_previous = update
                .previous_commitment
                .clone()
                .or_else(|| previous_commitment.clone());
            updates.push(ExpectedUpdate {
                height: update.height,
                block_hash: update.block_hash.clone(),
                state_root: update.state_root.clone(),
                commitment: update.proof_commitment.clone(),
                expected_previous,
            });
            previous_commitment = Some(update.proof_commitment.clone());
        }

        Ok(Self {
            snapshot: plan.snapshot,
            snapshot_commitment,
            chunks,
            chunk_index_by_start,
            updates,
            update_index_by_height,
        })
    }
}

fn decode_hex_digest(value: &str) -> Result<[u8; 32], PipelineError> {
    let bytes = hex::decode(value)
        .map_err(|err| PipelineError::Validation(format!("invalid hex digest: {err}")))?;
    if bytes.len() != 32 {
        return Err(PipelineError::SnapshotVerification(format!(
            "expected 32-byte digest, received {} bytes",
            bytes.len()
        )));
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes);
    Ok(digest)
}

fn decode_base64_digest(value: &str) -> Result<[u8; 32], PipelineError> {
    let bytes = general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|err| PipelineError::Validation(format!("invalid base64 digest: {err}")))?;
    if bytes.len() != 32 {
        return Err(PipelineError::SnapshotVerification(format!(
            "expected 32-byte digest, received {} bytes",
            bytes.len()
        )));
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes);
    Ok(digest)
}

fn compute_merkle_root(leaves: &mut Vec<[u8; 32]>) -> [u8; 32] {
    use blake2::digest::Digest;
    use blake2::Blake2s256;

    if leaves.is_empty() {
        let mut hasher = Blake2s256::new();
        hasher.update(b"rpp-empty");
        let output = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&output);
        return digest;
    }
    leaves.sort();
    let mut current = leaves.clone();
    while current.len() > 1 {
        let mut next = Vec::with_capacity((current.len() + 1) / 2);
        for pair in current.chunks(2) {
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&left);
            data.extend_from_slice(&right);
            let mut hasher = Blake2s256::new();
            hasher.update(&data);
            let output = hasher.finalize();
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&output);
            next.push(digest);
        }
        current = next;
    }
    current[0]
}

#[derive(Debug, Clone)]
pub struct TelemetryEvent {
    pub peer: PeerId,
    pub version: String,
    pub latency: Duration,
    pub received_at: SystemTime,
}

#[derive(Debug)]
pub struct MetaTelemetry {
    heartbeats: HashMap<PeerId, TelemetryEvent>,
}

impl MetaTelemetry {
    pub fn new() -> Self {
        Self {
            heartbeats: HashMap::new(),
        }
    }

    pub fn record(&mut self, peer: PeerId, version: String, latency: Duration) {
        self.heartbeats.insert(
            peer,
            TelemetryEvent {
                peer,
                version,
                latency,
                received_at: SystemTime::now(),
            },
        );
    }

    pub fn offline_peers(&self, threshold: Duration) -> Vec<TelemetryEvent> {
        let now = SystemTime::now();
        self.heartbeats
            .values()
            .filter(|event| match now.duration_since(event.received_at) {
                Ok(elapsed) => elapsed > threshold,
                Err(_) => false,
            })
            .cloned()
            .collect()
    }

    pub fn latest(&self, peer: &PeerId) -> Option<&TelemetryEvent> {
        self.heartbeats.get(peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[derive(Debug, Default)]
    struct CountingValidator(parking_lot::Mutex<usize>);

    impl ProofValidator for CountingValidator {
        fn validate(&self, _peer: &PeerId, payload: &[u8]) -> Result<(), PipelineError> {
            if payload.is_empty() {
                return Err(PipelineError::Validation("empty payload".into()));
            }
            *self.0.lock() += 1;
            Ok(())
        }
    }

    #[tokio::test]
    async fn proof_pipeline_deduplicates_and_persists() {
        let validator = Arc::new(CountingValidator::default());
        let storage = Arc::new(MemoryProofStorage::default());
        let mut pipeline = ProofMempool::new(validator.clone(), storage.clone()).expect("pipeline");

        let peer: PeerId = PeerId::random();
        let payload = b"proof-payload".to_vec();
        assert!(pipeline
            .ingest(peer, GossipTopic::Proofs, payload.clone())
            .unwrap());
        assert_eq!(pipeline.len(), 1);
        assert_eq!(*validator.0.lock(), 1);

        // duplicate payload should be rejected
        let err = pipeline
            .ingest(peer, GossipTopic::Proofs, payload.clone())
            .unwrap_err();
        assert!(matches!(err, PipelineError::Duplicate));

        // pop restores record order and storage persisted it
        let record = pipeline.pop().unwrap();
        assert_eq!(record.payload, payload);
        assert!(pipeline.is_empty());
        assert_eq!(storage.records().len(), 1);
    }

    #[tokio::test]
    async fn persistent_storage_recovers_state() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("proofs.json");
        let storage =
            Arc::new(PersistentProofStorage::with_capacity(&path, 8).expect("persistent storage"));
        let validator = Arc::new(CountingValidator::default());

        {
            let mut pipeline =
                ProofMempool::new(validator.clone(), storage.clone()).expect("pipeline");
            pipeline
                .ingest(PeerId::random(), GossipTopic::Proofs, b"payload".to_vec())
                .expect("ingest");
            assert_eq!(pipeline.len(), 1);
        }

        let mut recovered = ProofMempool::new(validator, storage).expect("recovered");
        assert_eq!(recovered.len(), 1);
        assert!(recovered.pop().is_some());
    }

    #[tokio::test]
    async fn consensus_pipeline_reaches_quorum() {
        let mut pipeline = ConsensusPipeline::new();
        let voters: Vec<PeerId> = (0..3).map(|_| PeerId::random()).collect();
        for peer in &voters {
            pipeline.register_voter(*peer, 1.0);
        }
        let block_id = b"block-1".to_vec();
        pipeline
            .ingest_proposal(block_id.clone(), PeerId::random(), b"block".to_vec())
            .unwrap();

        // First vote accumulates 1/3
        let outcome = pipeline
            .ingest_vote(&block_id, voters[0], 0, b"vote-0".to_vec())
            .unwrap();
        assert!(matches!(
            outcome,
            VoteOutcome::Recorded {
                reached_quorum: false,
                ..
            }
        ));

        // Second vote reaches quorum (2/3)
        let outcome = pipeline
            .ingest_vote(&block_id, voters[1], 0, b"vote-1".to_vec())
            .unwrap();
        match outcome {
            VoteOutcome::Recorded {
                reached_quorum,
                power,
            } => {
                assert!(reached_quorum);
                assert!(power >= 2.0);
            }
            _ => panic!("unexpected outcome"),
        }

        // Duplicate vote ignored
        assert!(matches!(
            pipeline
                .ingest_vote(&block_id, voters[1], 0, b"vote-1".to_vec())
                .unwrap(),
            VoteOutcome::Duplicate
        ));
    }

    #[tokio::test]
    async fn snapshot_roundtrip_and_light_client_validation() {
        let aggregated_one = [1u8; 32];
        let aggregated_two = [2u8; 32];
        let mut chunk_leaves = vec![aggregated_one, aggregated_two];
        let chunk_root = compute_merkle_root(&mut chunk_leaves);
        let mut snapshot_leaves = vec![chunk_root];
        let snapshot_root = compute_merkle_root(&mut snapshot_leaves);

        let plan = NetworkStateSyncPlan {
            snapshot: NetworkSnapshotSummary {
                height: 0,
                block_hash: "snapshot".into(),
                commitments: NetworkGlobalStateCommitments {
                    global_state_root: hex::encode([0u8; 32]),
                    utxo_root: hex::encode([0u8; 32]),
                    reputation_root: hex::encode([0u8; 32]),
                    timetoke_root: hex::encode([0u8; 32]),
                    zsi_root: hex::encode([0u8; 32]),
                    proof_root: hex::encode([0u8; 32]),
                },
                chain_commitment: hex::encode(snapshot_root),
            },
            tip: NetworkBlockMetadata {
                height: 1,
                hash: "tip".into(),
                timestamp: 42,
                previous_state_root: hex::encode([0x11; 32]),
                new_state_root: hex::encode([0x22; 32]),
                proof_hash: hex::encode([0x33; 32]),
                recursion_anchor: "anchor".into(),
            },
            chunks: vec![NetworkStateSyncChunk {
                start_height: 0,
                end_height: 1,
                requests: vec![
                    NetworkReconstructionRequest {
                        height: 0,
                        block_hash: "block-0".into(),
                        tx_root: "tx".into(),
                        state_root: "state".into(),
                        utxo_root: "utxo".into(),
                        reputation_root: "reputation".into(),
                        timetoke_root: "timetoke".into(),
                        zsi_root: "zsi".into(),
                        proof_root: "proof".into(),
                        pruning_commitment: "pruning".into(),
                        aggregated_commitment: hex::encode(aggregated_one),
                        previous_commitment: None,
                        payload_expectations: NetworkPayloadExpectations::default(),
                    },
                    NetworkReconstructionRequest {
                        height: 1,
                        block_hash: "block-1".into(),
                        tx_root: "tx".into(),
                        state_root: "state".into(),
                        utxo_root: "utxo".into(),
                        reputation_root: "reputation".into(),
                        timetoke_root: "timetoke".into(),
                        zsi_root: "zsi".into(),
                        proof_root: "proof".into(),
                        pruning_commitment: "pruning".into(),
                        aggregated_commitment: hex::encode(aggregated_two),
                        previous_commitment: None,
                        payload_expectations: NetworkPayloadExpectations::default(),
                    },
                ],
                proofs: Vec::new(),
            }],
            light_client_updates: vec![NetworkLightClientUpdate {
                height: 1,
                block_hash: "block-1".into(),
                state_root: "state".into(),
                proof_commitment: hex::encode([9u8; 32]),
                previous_commitment: None,
                recursive_proof: String::new(),
            }],
        };

        let plan_payload = serde_json::to_vec(&plan).expect("plan encode");
        let mut client = LightClientSync::default();
        client.ingest_plan(&plan_payload).expect("plan");

        let chunk_payload = serde_json::to_vec(&NetworkStateSyncChunk {
            start_height: 0,
            end_height: 1,
            requests: plan.chunks[0].requests.clone(),
            proofs: vec![
                general_purpose::STANDARD.encode(aggregated_one),
                general_purpose::STANDARD.encode(aggregated_two),
            ],
        })
        .expect("chunk encode");
        client.ingest_chunk(&chunk_payload).expect("chunk");

        let update_payload = serde_json::to_vec(&NetworkLightClientUpdate {
            height: 1,
            block_hash: "block-1".into(),
            state_root: "state".into(),
            proof_commitment: plan.light_client_updates[0].proof_commitment.clone(),
            previous_commitment: Some(plan.snapshot.chain_commitment.clone()),
            recursive_proof: general_purpose::STANDARD.encode(b"recursive-proof"),
        })
        .expect("update encode");
        client
            .ingest_light_client_update(&update_payload)
            .expect("update");

        assert!(client.verify().unwrap());
    }

    #[tokio::test]
    async fn meta_channel_marks_offline_peers() {
        let mut meta = MetaTelemetry::new();
        let peer = PeerId::random();
        meta.record(peer, "1.0.0".into(), Duration::from_millis(42));
        assert!(meta.offline_peers(Duration::from_secs(60)).is_empty());

        // artificially age the heartbeat
        if let Some(event) = meta.heartbeats.get_mut(&peer) {
            let past = SystemTime::now() - Duration::from_secs(120);
            event.received_at = past;
        }
        let offline = meta.offline_peers(Duration::from_secs(60));
        assert_eq!(offline.len(), 1);
        assert_eq!(offline[0].peer, peer);
    }
}

#[cfg(test)]
mod interface_schemas {
    use super::{
        NetworkBlockMetadata, NetworkGlobalStateCommitments, NetworkLightClientUpdate,
        NetworkPayloadExpectations, NetworkReconstructionRequest, NetworkStateSyncChunk,
        NetworkStateSyncPlan,
    };
    use jsonschema::{Draft, JSONSchema};
    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use serde_json::Value;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn interfaces_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/interfaces")
    }

    fn load_json(path: &Path) -> Value {
        let raw = fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("unable to read {}: {err}", path.display()));
        serde_json::from_str(&raw)
            .unwrap_or_else(|err| panic!("invalid JSON in {}: {err}", path.display()))
    }

    fn resolve_refs(value: &mut Value, base: &Path) {
        match value {
            Value::Object(map) => {
                if let Some(reference) = map.get("$ref").and_then(Value::as_str) {
                    let target_path = base.join(reference);
                    let mut target = load_json(&target_path);
                    let target_base = target_path
                        .parent()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| base.to_path_buf());
                    resolve_refs(&mut target, &target_base);
                    *value = target;
                } else {
                    for sub in map.values_mut() {
                        resolve_refs(sub, base);
                    }
                }
            }
            Value::Array(items) => {
                for item in items {
                    resolve_refs(item, base);
                }
            }
            _ => {}
        }
    }

    fn load_schema(segment: &str) -> Value {
        let path = interfaces_dir().join(segment);
        let mut schema = load_json(&path);
        let base = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| interfaces_dir());
        resolve_refs(&mut schema, &base);
        schema
    }

    fn load_example(segment: &str) -> Value {
        load_json(&interfaces_dir().join(segment))
    }

    fn assert_roundtrip<T>(schema_file: &str, example_file: &str)
    where
        T: Serialize + DeserializeOwned,
    {
        let schema = load_schema(schema_file);
        let compiled = JSONSchema::options()
            .with_draft(Draft::Draft202012)
            .compile(&schema)
            .expect("schema compiles");
        let example = load_example(example_file);
        compiled.validate(&example).expect("example matches schema");
        let typed: T = serde_json::from_value(example.clone()).expect("deserialize example");
        let roundtrip = serde_json::to_value(&typed).expect("serialize payload");
        assert_eq!(roundtrip, example);
    }

    #[test]
    fn global_state_commitments_schema_roundtrip() {
        assert_roundtrip::<NetworkGlobalStateCommitments>(
            "p2p/network_global_state_commitments.jsonschema",
            "p2p/examples/network_global_state_commitments.json",
        );
    }

    #[test]
    fn block_metadata_schema_roundtrip() {
        assert_roundtrip::<NetworkBlockMetadata>(
            "p2p/network_block_metadata.jsonschema",
            "p2p/examples/network_block_metadata.json",
        );
    }

    #[test]
    fn payload_expectations_schema_roundtrip() {
        assert_roundtrip::<NetworkPayloadExpectations>(
            "p2p/network_payload_expectations.jsonschema",
            "p2p/examples/network_payload_expectations.json",
        );
    }

    #[test]
    fn reconstruction_request_schema_roundtrip() {
        assert_roundtrip::<NetworkReconstructionRequest>(
            "p2p/network_reconstruction_request.jsonschema",
            "p2p/examples/network_reconstruction_request.json",
        );
    }

    #[test]
    fn state_sync_chunk_schema_roundtrip() {
        assert_roundtrip::<NetworkStateSyncChunk>(
            "p2p/network_state_sync_chunk.jsonschema",
            "p2p/examples/network_state_sync_chunk.json",
        );
    }

    #[test]
    fn light_client_update_schema_roundtrip() {
        assert_roundtrip::<NetworkLightClientUpdate>(
            "p2p/network_light_client_update.jsonschema",
            "p2p/examples/network_light_client_update.json",
        );
    }

    #[test]
    fn state_sync_plan_schema_roundtrip() {
        assert_roundtrip::<NetworkStateSyncPlan>(
            "p2p/network_state_sync_plan.jsonschema",
            "p2p/examples/network_state_sync_plan.json",
        );
    }
}
