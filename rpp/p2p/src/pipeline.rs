use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::str::FromStr;

use base64::{engine::general_purpose, Engine as _};
use blake3::Hash;
use hex;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::topics::GossipTopic;

const HEX_DIGEST_LENGTH: usize = 32;

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
    #[error("encoding error: {0}")]
    Encoding(String),
}

/// Handler invoked whenever a gossip proof is received on the `proofs` topic.
pub trait ProofValidator: std::fmt::Debug + Send + Sync + 'static {
    fn validate(&self, peer: &PeerId, payload: &[u8]) -> Result<(), PipelineError>;
}

#[derive(Debug, Default, Clone)]
#[allow(dead_code)]
pub struct NoopProofValidator;

impl ProofValidator for NoopProofValidator {
    fn validate(&self, _peer: &PeerId, _payload: &[u8]) -> Result<(), PipelineError> {
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
        let digest_bytes = hex::decode(value.digest)
            .map_err(|err| PipelineError::Persistence(err.to_string()))?;
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

    pub fn ingest(&mut self, peer: PeerId, topic: GossipTopic, payload: Vec<u8>) -> Result<bool, PipelineError> {
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
        self.validator
            .validate(&peer, &payload)?;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSnapshotSummary {
    pub height: u64,
    pub block_hash: String,
    pub commitments: serde_json::Value,
    pub chain_commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBlockMetadata {
    pub height: u64,
    pub hash: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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
    #[serde(default)]
    pub previous_commitment: Option<String>,
    pub payload_expectations: NetworkPayloadExpectations,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStateSyncChunk {
    pub start_height: u64,
    pub end_height: u64,
    #[serde(default)]
    pub requests: Vec<NetworkReconstructionRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkLightClientUpdate {
    pub height: u64,
    pub block_hash: String,
    pub state_root: String,
    pub recursive_proof: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStateSyncPlan {
    pub snapshot: NetworkSnapshotSummary,
    pub tip: NetworkBlockMetadata,
    #[serde(default)]
    pub chunks: Vec<NetworkStateSyncChunk>,
    #[serde(default)]
    pub light_client_updates: Vec<NetworkLightClientUpdate>,
}

#[derive(Debug, Clone)]
struct ActivePlan {
    plan: NetworkStateSyncPlan,
}

impl TryFrom<NetworkStateSyncPlan> for ActivePlan {
    type Error = PipelineError;

    fn try_from(plan: NetworkStateSyncPlan) -> Result<Self, Self::Error> {
        if plan.tip.hash.is_empty() {
            return Err(PipelineError::Validation(
                "plan tip hash cannot be empty".into(),
            ));
        }
        if let Some(out_of_order) = plan
            .light_client_updates
            .windows(2)
            .find(|window| window[0].height > window[1].height)
        {
            return Err(PipelineError::Validation(format!(
                "light client updates out of order at height {}",
                out_of_order[1].height
            )));
        }
        Ok(Self { plan })
    }
}

impl ActivePlan {
    fn tip_height(&self) -> u64 {
        self.plan.tip.height
    }

    fn tip_hash(&self) -> &str {
        &self.plan.tip.hash
    }

    fn latest_light_client_height(&self) -> Option<u64> {
        self.plan
            .light_client_updates
            .iter()
            .map(|update| update.height)
            .max()
    }

    fn pending_light_client_updates(&self, accepted: &HashSet<u64>) -> usize {
        self.plan
            .light_client_updates
            .iter()
            .filter(|update| !accepted.contains(&update.height))
            .count()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotPlanMetadata {
    pub payload_root: String,
    pub snapshot_height: u64,
    pub snapshot_hash: String,
    pub tip_height: u64,
    pub tip_hash: String,
    pub chunk_count: u64,
    pub light_client_updates: u64,
    pub refreshed_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotChunkPayload {
    pub root: String,
    pub index: u64,
    pub total: u64,
    pub data: Vec<u8>,
}

impl SnapshotChunkPayload {
    pub fn from_chunk(chunk: &SnapshotChunk) -> Self {
        Self {
            root: chunk.root.to_hex().to_string(),
            index: chunk.index,
            total: chunk.total,
            data: chunk.data.clone(),
        }
    }

    pub fn into_chunk(self) -> Result<SnapshotChunk, PipelineError> {
        let decoded = hex::decode(&self.root)
            .map_err(|err| PipelineError::Encoding(err.to_string()))?;
        if decoded.len() != HEX_DIGEST_LENGTH {
            return Err(PipelineError::Encoding("invalid snapshot root".into()));
        }
        let mut root = [0u8; HEX_DIGEST_LENGTH];
        root.copy_from_slice(&decoded);
        Ok(SnapshotChunk {
            root: Hash::from(root),
            index: self.index,
            total: self.total,
            data: self.data,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SnapshotMessage {
    Announcement(SnapshotPlanMetadata),
    Chunk(SnapshotChunkPayload),
}

pub fn encode_snapshot_message(message: &SnapshotMessage) -> Result<Vec<u8>, PipelineError> {
    serde_json::to_vec(message).map_err(|err| PipelineError::Encoding(err.to_string()))
}

pub fn decode_snapshot_message(payload: &[u8]) -> Result<SnapshotMessage, PipelineError> {
    serde_json::from_slice(payload).map_err(|err| PipelineError::Encoding(err.to_string()))
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
        let chunk_size = self.chunk_size.max(1);
        let total = if data.is_empty() {
            0
        } else {
            ((data.len() as u64) + (chunk_size as u64) - 1) / (chunk_size as u64)
        };
        for (index, window) in data.chunks(chunk_size).enumerate() {
            chunks.push(SnapshotChunk {
                root: *root,
                index: index as u64,
                total,
                data: window.to_vec(),
            });
        }
        Ok(chunks)
    }

    pub fn chunk_count(&self, root: &Hash) -> Result<u64, PipelineError> {
        let data = self
            .snapshots
            .get(root)
            .ok_or(PipelineError::SnapshotNotFound)?;
        if data.is_empty() {
            Ok(0)
        } else {
            let chunk_size = self.chunk_size.max(1) as u64;
            let len = data.len() as u64;
            Ok((len + chunk_size - 1) / chunk_size)
        }
    }
}

#[derive(Debug)]
pub struct LightClientSync {
    expected_root: Option<Hash>,
    received_chunks: HashMap<u64, Vec<u8>>,
    total: Option<u64>,
    plan: Option<ActivePlan>,
    accepted_updates: HashSet<u64>,
}

impl LightClientSync {
    pub fn new() -> Self {
        Self {
            expected_root: None,
            received_chunks: HashMap::new(),
            total: None,
            plan: None,
            accepted_updates: HashSet::new(),
        }
    }

    pub fn reset(&mut self) {
        self.expected_root = None;
        self.received_chunks.clear();
        self.total = None;
        self.plan = None;
        self.accepted_updates.clear();
    }

    pub fn prepare(&mut self, root: Option<Hash>, chunk_total: u64) {
        self.reset();
        self.expected_root = root;
        self.total = Some(chunk_total);
    }

    pub fn ingest_recursive_proof(&mut self, _proof: &[u8]) {
        // Placeholder for real recursive verification.
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

    pub fn ingest_chunk(&mut self, chunk: SnapshotChunk) -> Result<(), PipelineError> {
        if let Some(expected) = self.expected_root {
            if expected != chunk.root {
                return Err(PipelineError::SnapshotVerification(
                    "chunk root mismatch".to_string(),
                ));
            }
        } else {
            self.expected_root = Some(chunk.root);
        }
        self.total = Some(chunk.total);
        self.received_chunks.insert(chunk.index, chunk.data);
        Ok(())
    }

    pub fn verify(&mut self) -> Result<bool, PipelineError> {
        let expected_root = match self.expected_root {
            Some(root) => root,
            None => return Ok(false),
        };
        let total = match self.total {
            Some(total) => total,
            None => return Ok(false),
        };
        for index in 0..total {
            if !self.received_chunks.contains_key(&index) {
                return Ok(false);
            }
        }
        let mut payload = Vec::new();
        for index in 0..total {
            if let Some(data) = self.received_chunks.get(&index) {
                payload.extend_from_slice(data);
            }
        }
        let root = blake3::hash(&payload);
        if root == expected_root {
            self.ingest_plan(&payload)?;
            Ok(true)
        } else {
            Err(PipelineError::SnapshotVerification(
                "reconstructed root mismatch".to_string(),
            ))
        }
    }

    pub fn received_chunks(&self) -> usize {
        self.received_chunks.len()
    }

    pub fn expected_total(&self) -> Option<u64> {
        self.total
    }

    pub fn expected_root(&self) -> Option<Hash> {
        self.expected_root
    }

    pub fn latest_verified_height(&self) -> Option<u64> {
        self.plan
            .as_ref()
            .and_then(|plan| plan.latest_light_client_height())
    }

    pub fn plan_tip_height(&self) -> Option<u64> {
        self.plan.as_ref().map(|plan| plan.tip_height())
    }

    pub fn plan_tip_hash(&self) -> Option<&str> {
        self.plan.as_ref().map(|plan| plan.tip_hash())
    }

    pub fn pending_light_client_updates(&self) -> usize {
        self.plan
            .as_ref()
            .map(|plan| plan.pending_light_client_updates(&self.accepted_updates))
            .unwrap_or(0)
    }

    pub fn mark_light_client_update_applied(&mut self, height: u64) {
        self.accepted_updates.insert(height);
    }
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
        let storage = Arc::new(
            PersistentProofStorage::with_capacity(&path, 8).expect("persistent storage"),
        );
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
            VoteOutcome::Recorded { reached_quorum, power } => {
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
        let mut store = SnapshotStore::new(8);
        let plan = NetworkStateSyncPlan {
            snapshot: NetworkSnapshotSummary {
                height: 42,
                block_hash: "snapshot-hash".into(),
                commitments: serde_json::json!({
                    "global_state_root": "root",
                    "utxo_root": "utxo",
                    "reputation_root": "rep",
                    "timetoke_root": "tt",
                    "zsi_root": "zsi",
                    "proof_root": "proof",
                }),
                chain_commitment: "chain".into(),
            },
            tip: NetworkBlockMetadata {
                height: 128,
                hash: "tip-hash".into(),
                timestamp: 1,
            },
            chunks: vec![NetworkStateSyncChunk {
                start_height: 10,
                end_height: 20,
                requests: vec![NetworkReconstructionRequest {
                    height: 10,
                    block_hash: "block-10".into(),
                    tx_root: "tx".into(),
                    state_root: "state".into(),
                    utxo_root: "utxo".into(),
                    reputation_root: "rep".into(),
                    timetoke_root: "tt".into(),
                    zsi_root: "zsi".into(),
                    proof_root: "proof".into(),
                    pruning_commitment: "prune".into(),
                    aggregated_commitment: "agg".into(),
                    previous_commitment: Some("prev".into()),
                    payload_expectations: NetworkPayloadExpectations::default(),
                }],
            }],
            light_client_updates: vec![NetworkLightClientUpdate {
                height: 128,
                block_hash: "tip-hash".into(),
                state_root: "state".into(),
                recursive_proof: serde_json::json!({ "kind": "stwo" }),
            }],
        };
        let payload = serde_json::to_vec(&plan).unwrap();
        let root = store.insert(payload.clone());
        let expected_chunks = store.chunk_count(&root).unwrap();
        let chunks = store.stream(&root).unwrap();
        assert!(chunks.len() > 1);
        assert_eq!(expected_chunks, chunks.len() as u64);

        let mut client = LightClientSync::new();
        client.prepare(Some(root), expected_chunks);
        client.ingest_recursive_proof(b"recursive-proof");
        for chunk in chunks {
            client.ingest_chunk(chunk).unwrap();
        }
        assert!(client.verify().unwrap());
        assert_eq!(client.latest_verified_height(), Some(128));
        assert_eq!(client.pending_light_client_updates(), 1);
        client.mark_light_client_update_applied(128);
        assert_eq!(client.pending_light_client_updates(), 0);
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
