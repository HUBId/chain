use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use blake3::Hash;
use parking_lot::{Mutex, RwLock};
use rpp_p2p::vendor::PeerId;
use rpp_p2p::{
    decode_gossip_payload, decode_meta_payload, validate_block_payload, validate_vote_payload,
    AdmissionAuditTrail, AdmissionPolicies, AllowlistedPeer, ConsensusPipeline,
    GossipBlockValidator, GossipPayloadError, GossipTopic, GossipVoteValidator, HandshakePayload,
    LightClientHead, LightClientSync, MetaTelemetry, NetworkError, NetworkEvent,
    NetworkFeatureAnnouncement, NetworkLightClientUpdate, NetworkMetaTelemetryReport,
    NetworkPeerTelemetry, NetworkStateSyncPlan, NodeIdentity, Peerstore, PeerstoreError,
    PersistentConsensusStorage, PersistentProofStorage, PipelineError, ProofMempool,
    ReputationBroadcast, ReputationEvent, ReputationHeuristics, RuntimeProofValidator,
    SeenDigestRecord, SnapshotChunk, SnapshotProviderHandle, SnapshotSessionId, TierLevel,
    VoteOutcome,
};
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::Value;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::time;
use tracing::{debug, info, info_span, instrument, warn, Span};

use crate::config::{FeatureGates, NodeConfig, P2pConfig, TelemetryConfig};
use crate::consensus::{ConsensusCertificate, EvidenceRecord, SignedBftVote};
use crate::node::NetworkIdentityProfile;
use crate::proof_backend::Blake2sHasher;
use crate::proof_system::{ProofVerifierRegistry, VerifierMetricsSnapshot};
use crate::rpp::{GlobalStateCommitments, TimetokeRecord};
use crate::runtime::telemetry::RuntimeMetrics;
use crate::runtime::vrf_gossip::{gossip_to_submission, verify_submission, GossipVrfSubmission};
use crate::state::merkle::compute_merkle_root;
use crate::sync::{RuntimeRecursiveProofVerifier, RuntimeTransactionProofVerifier};
use crate::types::{Address, Block, PruningProof};
use crate::vrf::VrfSubmission;

use super::network::{NetworkConfig, NetworkResources, NetworkSetupError};

/// Commands issued to the node runtime.
#[derive(Debug, Clone, Copy)]
pub enum ProofReputationCode {
    InvalidProof,
    DuplicateProof,
    PipelineFailure,
    InvalidVrfSubmission,
    InvalidTimetokeDelta,
}

#[derive(Debug)]
enum NodeCommand {
    Publish {
        topic: GossipTopic,
        data: Vec<u8>,
        response: oneshot::Sender<Result<(), NodeError>>,
    },
    UpdateIdentity {
        profile: IdentityProfile,
        response: oneshot::Sender<Result<(), NodeError>>,
    },
    MetaTelemetrySnapshot {
        response: oneshot::Sender<Result<MetaTelemetryReport, NodeError>>,
    },
    ReloadAccessLists {
        allowlist: Vec<AllowlistedPeer>,
        blocklist: Vec<PeerId>,
        response: oneshot::Sender<Result<(), NodeError>>,
    },
    StartSnapshotStream {
        session: SnapshotSessionId,
        peer: PeerId,
        root: String,
        response: oneshot::Sender<Result<(), NodeError>>,
    },
    ResumeSnapshotStream {
        session: SnapshotSessionId,
        response: oneshot::Sender<Result<(), NodeError>>,
    },
    CancelSnapshotStream {
        session: SnapshotSessionId,
        response: oneshot::Sender<Result<(), NodeError>>,
    },
    Shutdown,
    ApplyReputationPenalty {
        peer: PeerId,
        code: ProofReputationCode,
    },
    ReportBackpressure {
        topic: GossipTopic,
        queue_depth: usize,
    },
    HeuristicsSnapshot {
        response: oneshot::Sender<Vec<(PeerId, PeerHeuristics)>>,
    },
}

/// In-memory metrics that are periodically forwarded to the runtime metrics pipeline.
#[derive(Clone, Debug, Default)]
pub struct NodeMetrics {
    pub block_height: u64,
    pub block_hash: String,
    pub transaction_count: usize,
    pub reputation_score: f64,
    pub verifier_metrics: VerifierMetricsSnapshot,
    pub round_latencies_ms: Vec<u64>,
    pub leader_changes: u64,
    pub quorum_latency_ms: Option<u64>,
    pub witness_events: u64,
    pub slashing_events: u64,
    pub failed_votes: u64,
}

#[derive(Clone, Debug, Default)]
pub struct PeerHeuristics {
    pub vote_timeouts: u64,
    pub proof_relay_misses: u64,
    pub gossip_backpressure_events: u64,
}

/// Summary of peer activity that is emitted via heartbeat and meta telemetry events.
#[derive(Clone, Debug)]
pub struct PeerTelemetry {
    pub peer: PeerId,
    pub version: String,
    pub latency_ms: u64,
    pub last_seen: SystemTime,
}

#[derive(Clone, Debug)]
pub struct FeatureAnnouncement {
    pub peer_id: PeerId,
    pub feature_gates: FeatureGates,
}

impl From<&FeatureAnnouncement> for NetworkFeatureAnnouncement {
    fn from(announcement: &FeatureAnnouncement) -> Self {
        Self {
            peer_id: announcement.peer_id.to_base58(),
            features: announcement.feature_gates.advertise(),
        }
    }
}

impl TryFrom<NetworkFeatureAnnouncement> for FeatureAnnouncement {
    type Error = String;

    fn try_from(announcement: NetworkFeatureAnnouncement) -> Result<Self, Self::Error> {
        let peer_id = announcement
            .peer_id
            .parse()
            .map_err(|err| format!("invalid peer id: {err}"))?;
        let feature_gates = FeatureGates::from_advertisement(&announcement.features)
            .map_err(|err| err.to_string())?;
        Ok(Self {
            peer_id,
            feature_gates,
        })
    }
}

/// Aggregate telemetry information for all known peers.
#[derive(Clone, Debug)]
pub struct MetaTelemetryReport {
    pub local_peer_id: PeerId,
    pub peer_count: usize,
    pub peers: Vec<PeerTelemetry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TimetokeDeltaBroadcast {
    pub timetoke_root: String,
    pub records: Vec<TimetokeRecord>,
}

#[derive(Clone, Debug)]
pub enum MetaPayload {
    Reputation(ReputationBroadcast),
    Evidence(EvidenceRecord),
    Telemetry(MetaTelemetryReport),
    FeatureAnnouncement(FeatureAnnouncement),
    TimetokeDelta(TimetokeDeltaBroadcast),
}

impl<'de> Deserialize<'de> for MetaPayload {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        if let Ok(broadcast) = serde_json::from_value::<ReputationBroadcast>(value.clone()) {
            return Ok(Self::Reputation(broadcast));
        }
        if let Ok(evidence) = serde_json::from_value::<EvidenceRecord>(value.clone()) {
            return Ok(Self::Evidence(evidence));
        }
        if let Ok(report) = serde_json::from_value::<NetworkMetaTelemetryReport>(value.clone()) {
            let report = MetaTelemetryReport::try_from(report).map_err(|err| {
                de::Error::custom(format!("invalid meta telemetry report: {err}"))
            })?;
            return Ok(Self::Telemetry(report));
        }
        if let Ok(announcement) =
            serde_json::from_value::<NetworkFeatureAnnouncement>(value.clone())
        {
            let announcement = FeatureAnnouncement::try_from(announcement)
                .map_err(|err| de::Error::custom(format!("invalid feature announcement: {err}")))?;
            return Ok(Self::FeatureAnnouncement(announcement));
        }
        if let Ok(delta) = serde_json::from_value::<TimetokeDeltaBroadcast>(value.clone()) {
            return Ok(Self::TimetokeDelta(delta));
        }
        Err(de::Error::custom("unknown meta payload format"))
    }
}

fn system_time_to_millis(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn millis_to_system_time(millis: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(millis)
}

impl From<&PeerTelemetry> for NetworkPeerTelemetry {
    fn from(telemetry: &PeerTelemetry) -> Self {
        Self {
            peer: telemetry.peer.to_base58(),
            version: telemetry.version.clone(),
            latency_ms: telemetry.latency_ms,
            last_seen: system_time_to_millis(telemetry.last_seen),
        }
    }
}

impl TryFrom<NetworkPeerTelemetry> for PeerTelemetry {
    type Error = String;

    fn try_from(telemetry: NetworkPeerTelemetry) -> Result<Self, Self::Error> {
        let peer = telemetry
            .peer
            .parse()
            .map_err(|err| format!("invalid peer id: {err}"))?;
        Ok(Self {
            peer,
            version: telemetry.version,
            latency_ms: telemetry.latency_ms,
            last_seen: millis_to_system_time(telemetry.last_seen),
        })
    }
}

impl From<&MetaTelemetryReport> for NetworkMetaTelemetryReport {
    fn from(report: &MetaTelemetryReport) -> Self {
        Self {
            local_peer_id: report.local_peer_id.to_base58(),
            peer_count: report.peer_count,
            peers: report
                .peers
                .iter()
                .map(NetworkPeerTelemetry::from)
                .collect(),
        }
    }
}

impl TryFrom<NetworkMetaTelemetryReport> for MetaTelemetryReport {
    type Error = String;

    fn try_from(report: NetworkMetaTelemetryReport) -> Result<Self, Self::Error> {
        let local_peer_id = report
            .local_peer_id
            .parse()
            .map_err(|err| format!("invalid peer id: {err}"))?;
        let peers = report
            .peers
            .into_iter()
            .map(PeerTelemetry::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            local_peer_id,
            peer_count: report.peer_count,
            peers,
        })
    }
}

/// Periodic heartbeat message emitted by the node runtime.
#[derive(Clone, Debug)]
pub struct Heartbeat {
    pub peer_count: usize,
    pub block_height: u64,
    pub block_hash: String,
    pub transaction_count: usize,
    pub reputation_score: f64,
}

/// Public configuration wrapper used by the node runtime.
#[derive(Clone)]
pub struct NodeRuntimeConfig {
    pub identity_path: PathBuf,
    pub p2p: P2pConfig,
    pub telemetry: TelemetryConfig,
    pub metrics: Arc<RuntimeMetrics>,
    pub identity: Option<IdentityProfile>,
    pub proof_storage_path: PathBuf,
    pub consensus_storage_path: PathBuf,
    pub feature_gates: FeatureGates,
    pub snapshot_provider: Option<SnapshotProviderHandle>,
}

impl From<&NodeConfig> for NodeRuntimeConfig {
    fn from(config: &NodeConfig) -> Self {
        Self {
            identity_path: config.p2p_key_path.clone(),
            p2p: config.network.p2p.clone(),
            telemetry: config.rollout.telemetry.clone(),
            metrics: RuntimeMetrics::noop(),
            identity: None,
            proof_storage_path: config.proof_cache_dir.join("gossip_proofs.json"),
            consensus_storage_path: config.consensus_pipeline_path.clone(),
            feature_gates: config.rollout.feature_gates.clone(),
            snapshot_provider: None,
        }
    }
}

impl fmt::Debug for NodeRuntimeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeRuntimeConfig")
            .field("identity_path", &self.identity_path)
            .field("p2p", &self.p2p)
            .field("telemetry", &self.telemetry)
            .field("identity", &self.identity)
            .field("proof_storage_path", &self.proof_storage_path)
            .field("consensus_storage_path", &self.consensus_storage_path)
            .field("feature_gates", &self.feature_gates)
            .field(
                "snapshot_provider",
                if self.snapshot_provider.is_some() {
                    &"Some(..)"
                } else {
                    &"None"
                },
            )
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct IdentityProfile {
    pub zsi_id: String,
    pub tier: TierLevel,
    pub vrf_public_key: Vec<u8>,
    pub vrf_proof: Vec<u8>,
    pub feature_gates: FeatureGates,
}

impl From<NetworkIdentityProfile> for IdentityProfile {
    fn from(profile: NetworkIdentityProfile) -> Self {
        Self {
            zsi_id: profile.zsi_id,
            tier: profile.tier,
            vrf_public_key: profile.vrf_public_key,
            vrf_proof: profile.vrf_proof,
            feature_gates: profile.feature_gates,
        }
    }
}

#[derive(Clone, Debug)]
pub struct SnapshotStreamStatus {
    pub session: SnapshotSessionId,
    pub peer: PeerId,
    pub root: String,
    pub last_chunk_index: Option<u64>,
    pub last_update_index: Option<u64>,
    pub last_update_height: Option<u64>,
    pub verified: Option<bool>,
    pub error: Option<String>,
}

impl SnapshotStreamStatus {
    fn new(session: SnapshotSessionId, peer: PeerId, root: String) -> Self {
        Self {
            session,
            peer,
            root,
            last_chunk_index: None,
            last_update_index: None,
            last_update_height: None,
            verified: None,
            error: None,
        }
    }
}

#[derive(Clone, Debug)]
pub enum SnapshotStreamProgressStage {
    Plan {
        plan: NetworkStateSyncPlan,
    },
    Chunk {
        index: u64,
        chunk: SnapshotChunk,
    },
    Update {
        index: u64,
        update: NetworkLightClientUpdate,
    },
}

/// Events emitted by the node runtime for consumption by higher layers.
#[derive(Clone, Debug)]
pub enum NodeEvent {
    Gossip {
        peer: PeerId,
        topic: GossipTopic,
        data: Vec<u8>,
    },
    Evidence {
        peer: PeerId,
        evidence: EvidenceRecord,
    },
    TimetokeDelta {
        peer: PeerId,
        delta: TimetokeDeltaBroadcast,
    },
    BlockProposal {
        peer: PeerId,
        block: Block,
    },
    BlockRejected {
        peer: PeerId,
        block: Block,
        reason: String,
    },
    Vote {
        peer: PeerId,
        vote: SignedBftVote,
    },
    VoteRejected {
        peer: PeerId,
        vote: SignedBftVote,
        reason: String,
    },
    VrfSubmission {
        peer: PeerId,
        submission: VrfSubmission,
    },
    PeerConnected {
        peer: PeerId,
        payload: HandshakePayload,
    },
    PeerDisconnected {
        peer: PeerId,
    },
    Heartbeat(Heartbeat),
    MetaTelemetry(MetaTelemetryReport),
    VrfLeadership {
        height: u64,
        round: u64,
        proposer: Address,
        randomness: String,
        block_hash: Option<String>,
    },
    BftFinalised {
        height: u64,
        round: u64,
        block_hash: String,
        commitments: GlobalStateCommitments,
        certificate: ConsensusCertificate,
    },
    FirewoodCommitment {
        height: u64,
        round: u64,
        block_hash: String,
        previous_root: String,
        new_root: String,
        pruning_proof: Option<PruningProof>,
    },
    SnapshotStreamProgress {
        session: SnapshotSessionId,
        peer: PeerId,
        status: SnapshotStreamStatus,
        stage: SnapshotStreamProgressStage,
    },
    SnapshotStreamCompleted {
        session: SnapshotSessionId,
        peer: PeerId,
        status: SnapshotStreamStatus,
        verified: bool,
    },
    SnapshotStreamFailed {
        session: SnapshotSessionId,
        peer: PeerId,
        status: SnapshotStreamStatus,
        reason: String,
    },
}

/// Errors raised by the node runtime.
#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("network setup error: {0}")]
    NetworkSetup(#[from] NetworkSetupError),
    #[error("network error: {0}")]
    Network(#[from] NetworkError),
    #[error("pipeline error: {0}")]
    Pipeline(#[from] PipelineError),
    #[error("peerstore error: {0}")]
    Peerstore(#[from] PeerstoreError),
    #[error("command channel closed")]
    CommandChannelClosed,
    #[error("gossip propagation disabled")]
    GossipDisabled,
    #[error("snapshot stream not found")]
    SnapshotStreamNotFound,
}

struct GossipPipelines {
    proofs: ProofMempool,
    light_client: LightClientSync,
    block_cache: HashSet<Hash>,
    vote_cache: Mutex<HashSet<Hash>>,
    meta_cache: HashSet<Hash>,
    timetoke_roots: HashSet<[u8; 32]>,
    consensus: Mutex<ConsensusPipeline>,
    commands: mpsc::Sender<NodeCommand>,
}

#[derive(Debug)]
enum BlockIngestResult {
    Duplicate,
    Valid(Block),
    Invalid { block: Block, reason: String },
    DecodeFailed(String),
}

#[derive(Debug)]
enum VoteIngestResult {
    Duplicate,
    Valid { vote: SignedBftVote, digest: Hash },
    Invalid { vote: SignedBftVote, reason: String },
    DecodeFailed(String),
}

#[derive(Debug)]
enum MetaIngestResult {
    Duplicate,
    Payload(MetaPayload),
    DecodeFailed(String),
}

impl GossipPipelines {
    #[inline]
    fn consensus_flow_span(
        operation: &'static str,
        height: u64,
        round: u64,
        block_hash: &str,
        peer: &PeerId,
    ) -> Span {
        info_span!(
            "runtime.consensus.flow",
            operation,
            height,
            round,
            block_hash,
            peer = %peer
        )
    }

    fn initialise(
        config: &NodeRuntimeConfig,
        commands: mpsc::Sender<NodeCommand>,
    ) -> Result<Self, PipelineError> {
        let storage = Arc::new(PersistentProofStorage::open(&config.proof_storage_path)?);
        let registry = ProofVerifierRegistry::default();
        let proof_backend = Arc::new(RuntimeTransactionProofVerifier::new(registry.clone()));
        let validator = Arc::new(RuntimeProofValidator::new(proof_backend));
        let proofs = ProofMempool::new(validator, storage)?;
        let verifier = Arc::new(RuntimeRecursiveProofVerifier::new(registry));
        let light_client = LightClientSync::new(verifier);
        let consensus_storage = Arc::new(PersistentConsensusStorage::open(
            &config.consensus_storage_path,
        )?);
        let (consensus, persisted_digests) =
            ConsensusPipeline::new_with_storage(consensus_storage)?;
        let mut vote_cache = HashSet::new();
        for record in persisted_digests {
            vote_cache.insert(record.digest);
        }
        Ok(Self {
            proofs,
            light_client,
            block_cache: HashSet::new(),
            vote_cache: Mutex::new(vote_cache),
            meta_cache: HashSet::new(),
            timetoke_roots: HashSet::new(),
            consensus: Mutex::new(consensus),
            commands,
        })
    }

    fn decode_timetoke_root(root_hex: &str) -> Result<[u8; 32], String> {
        let bytes = hex::decode(root_hex)
            .map_err(|err| format!("invalid timetoke root encoding: {err}"))?;
        if bytes.len() != 32 {
            return Err("timetoke root must be a 32-byte hex digest".into());
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes);
        Ok(root)
    }

    fn commitment_from_records(records: &[TimetokeRecord]) -> Result<[u8; 32], String> {
        let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(records.len());
        for record in records {
            let encoded = serde_json::to_vec(record)
                .map_err(|err| format!("encode timetoke record: {err}"))?;
            leaves.push(Blake2sHasher::hash(&encoded).into());
        }
        Ok(compute_merkle_root(&mut leaves))
    }

    fn register_voter(&self, peer: PeerId, tier: TierLevel) {
        let power = Self::tier_voting_power(tier);
        self.consensus.lock().register_voter(peer, power);
    }

    fn remove_voter(&self, peer: &PeerId) {
        self.consensus.lock().remove_voter(peer);
    }

    #[instrument(
        name = "runtime.consensus.proposal",
        skip(self, payload),
        fields(block_hash, peer = %peer)
    )]
    fn ingest_proposal(
        &self,
        peer: PeerId,
        block_hash: &str,
        payload: Vec<u8>,
    ) -> Result<(), PipelineError> {
        let span = Span::current();
        span.record("block_hash", &block_hash);
        let flow_span = Self::consensus_flow_span("proposal", 0, 0, block_hash, &peer);
        let _guard = flow_span.enter();
        self.consensus
            .lock()
            .ingest_proposal(block_hash.as_bytes().to_vec(), peer, payload)
    }

    #[instrument(
        name = "runtime.consensus.vote",
        skip(self, payload),
        fields(block_hash, round, peer = %peer, digest = tracing::field::Empty)
    )]
    fn ingest_vote(
        &self,
        peer: PeerId,
        block_hash: &str,
        round: u64,
        payload: Vec<u8>,
        digest: Hash,
    ) -> Result<VoteOutcome, PipelineError> {
        let span = Span::current();
        span.record("block_hash", &block_hash);
        span.record("round", &round);
        span.record("digest", &tracing::field::display(digest.to_hex()));
        let flow_span = Self::consensus_flow_span("vote", 0, round, block_hash, &peer);
        let _guard = flow_span.enter();
        let result = self
            .consensus
            .lock()
            .ingest_vote(block_hash.as_bytes(), peer, round, payload);
        if result.is_err() {
            self.vote_cache.lock().remove(&digest);
        }
        result
    }

    fn tier_voting_power(tier: TierLevel) -> f64 {
        tier as u8 as f64
    }

    fn handle_blocks(&mut self, _peer: PeerId, data: Vec<u8>) -> BlockIngestResult {
        let digest = blake3::hash(&data);
        if !self.block_cache.insert(digest) {
            return BlockIngestResult::Duplicate;
        }
        let block: Block = match decode_gossip_payload(&data) {
            Ok(block) => block,
            Err(GossipPayloadError::Decode(reason))
            | Err(GossipPayloadError::Validation(reason)) => {
                return BlockIngestResult::DecodeFailed(reason);
            }
        };
        match validate_block_payload(&block) {
            Ok(()) => BlockIngestResult::Valid(block),
            Err(GossipPayloadError::Validation(reason)) => {
                BlockIngestResult::Invalid { block, reason }
            }
            Err(GossipPayloadError::Decode(reason)) => BlockIngestResult::DecodeFailed(reason),
        }
    }

    fn handle_votes(&mut self, _peer: PeerId, data: Vec<u8>) -> VoteIngestResult {
        let digest = blake3::hash(&data);
        {
            let mut cache = self.vote_cache.lock();
            if !cache.insert(digest) {
                return VoteIngestResult::Duplicate;
            }
        }
        let vote: SignedBftVote = match decode_gossip_payload(&data) {
            Ok(vote) => vote,
            Err(err) => {
                self.vote_cache.lock().remove(&digest);
                let reason = match err {
                    GossipPayloadError::Decode(reason) | GossipPayloadError::Validation(reason) => {
                        reason
                    }
                };
                return VoteIngestResult::DecodeFailed(reason);
            }
        };
        match validate_vote_payload(&vote) {
            Ok(()) => VoteIngestResult::Valid { vote, digest },
            Err(GossipPayloadError::Validation(reason)) => {
                self.vote_cache.lock().remove(&digest);
                VoteIngestResult::Invalid { vote, reason }
            }
            Err(GossipPayloadError::Decode(reason)) => {
                self.vote_cache.lock().remove(&digest);
                VoteIngestResult::DecodeFailed(reason)
            }
        }
    }

    fn prune(&self, block_hash: &str) -> Result<(), PipelineError> {
        let digests = self.consensus.lock().prune(block_hash.as_bytes())?;
        let mut cache = self.vote_cache.lock();
        for digest in digests {
            cache.remove(&digest);
        }
        Ok(())
    }

    #[instrument(
        name = "node.runtime.proof.ingest",
        skip(self, data),
        fields(peer = %peer, bytes = data.len(), topic = ?topic)
    )]
    fn handle_proofs(&mut self, peer: PeerId, topic: GossipTopic, data: Vec<u8>) {
        match self.proofs.ingest(peer, topic, data) {
            Ok(_) => while self.proofs.pop().is_some() {},
            Err(PipelineError::Duplicate) => {
                debug!(target: "node", "duplicate proof gossip ignored");
                self.enqueue_proof_penalty(peer, ProofReputationCode::DuplicateProof);
            }
            Err(PipelineError::Validation(reason)) => {
                warn!(
                    target: "node",
                    %peer,
                    reason = %reason,
                    "failed to ingest proof gossip: validation error"
                );
                let lower_reason = reason.to_lowercase();
                if lower_reason.contains("missing proof")
                    || lower_reason.contains("missing commitment")
                {
                    self.apply_reputation_event(
                        peer.clone(),
                        ReputationEvent::ProofRelayMissed {
                            height: None,
                            reason: Some(Cow::Owned(reason.clone())),
                        },
                    );
                }
                self.enqueue_proof_penalty(peer, ProofReputationCode::InvalidProof);
            }
            Err(err) => {
                warn!(
                    target: "node",
                    %peer,
                    "failed to ingest proof gossip: {err:?}"
                );
                self.enqueue_proof_penalty(peer, ProofReputationCode::PipelineFailure);
            }
        }
    }

    #[instrument(
        name = "node.runtime.proof.penalty",
        skip(self),
        fields(peer = %peer, code = ?code)
    )]
    fn enqueue_proof_penalty(&self, peer: PeerId, code: ProofReputationCode) {
        let peer_for_log = peer.clone();
        let command = NodeCommand::ApplyReputationPenalty { peer, code };
        if let Err(err) = self.commands.try_send(command) {
            warn!(
                target: "node",
                %peer_for_log,
                ?err,
                "failed to enqueue reputation penalty command"
            );
        }
    }

    fn enqueue_meta_penalty(&self, peer: PeerId) {
        self.enqueue_proof_penalty(peer, ProofReputationCode::InvalidTimetokeDelta);
    }

    fn handle_snapshots(&mut self, payload: &[u8]) {
        if self.light_client.ingest_plan(payload).is_ok() {
            return;
        }

        let chunk_result = self.light_client.ingest_chunk(payload);
        match chunk_result {
            Ok(()) => return,
            Err(PipelineError::Duplicate) => {
                debug!(target: "node", "duplicate snapshot chunk ignored");
                return;
            }
            Err(_) => {}
        }

        match self.light_client.ingest_light_client_update(payload) {
            Ok(()) => {
                if let Err(err) = self.light_client.verify() {
                    warn!(
                        target: "node",
                        "light client verification failed: {err:?}"
                    );
                }
            }
            Err(PipelineError::Duplicate) => {
                debug!(target: "node", "duplicate light client update ignored");
            }
            Err(err) => {
                warn!(
                    target: "node",
                    "failed to ingest snapshot gossip: {err:?}"
                );
            }
        }
    }

    fn handle_meta(&mut self, peer: PeerId, data: Vec<u8>) -> MetaIngestResult {
        let digest = blake3::hash(&data);
        if !self.meta_cache.insert(digest) {
            debug!(target: "node", ?peer, "duplicate meta gossip ignored");
            return MetaIngestResult::Duplicate;
        }
        match decode_meta_payload(&data) {
            Ok(value) => match serde_json::from_value::<MetaPayload>(value) {
                Ok(MetaPayload::TimetokeDelta(delta)) => {
                    let root_bytes = match Self::decode_timetoke_root(&delta.timetoke_root) {
                        Ok(root) => root,
                        Err(reason) => {
                            warn!(
                                target: "node",
                                ?peer,
                                %reason,
                                "rejected timetoke delta gossip"
                            );
                            self.enqueue_meta_penalty(peer);
                            return MetaIngestResult::DecodeFailed(reason);
                        }
                    };
                    let commitment = match Self::commitment_from_records(&delta.records) {
                        Ok(commitment) => commitment,
                        Err(reason) => {
                            warn!(
                                target: "node",
                                ?peer,
                                %reason,
                                "failed to hash timetoke delta gossip"
                            );
                            self.enqueue_meta_penalty(peer);
                            return MetaIngestResult::DecodeFailed(reason);
                        }
                    };
                    if commitment != root_bytes {
                        warn!(
                            target: "node",
                            ?peer,
                            expected = hex::encode(root_bytes),
                            computed = hex::encode(commitment),
                            "timetoke delta commitment mismatch"
                        );
                        self.enqueue_meta_penalty(peer);
                        return MetaIngestResult::DecodeFailed(
                            "timetoke delta commitment mismatch".into(),
                        );
                    }
                    if !self.timetoke_roots.insert(root_bytes) {
                        debug!(
                            target: "node",
                            ?peer,
                            "duplicate timetoke delta ignored"
                        );
                        return MetaIngestResult::Duplicate;
                    }
                    debug!(target: "node", ?peer, "timetoke delta gossip ingested");
                    MetaIngestResult::Payload(MetaPayload::TimetokeDelta(delta))
                }
                Ok(payload) => {
                    debug!(target: "node", ?peer, "meta gossip ingested");
                    MetaIngestResult::Payload(payload)
                }
                Err(err) => {
                    MetaIngestResult::DecodeFailed(format!("invalid meta payload encoding: {err}"))
                }
            },
            Err(GossipPayloadError::Decode(reason)) => MetaIngestResult::DecodeFailed(reason),
            Err(GossipPayloadError::Validation(reason)) => MetaIngestResult::DecodeFailed(reason),
        }
    }

    fn handle_vrf_proofs(&mut self, peer: PeerId, data: Vec<u8>) -> Option<VrfSubmission> {
        let payload = match serde_json::from_slice::<GossipVrfSubmission>(&data) {
            Ok(payload) => payload,
            Err(err) => {
                warn!(
                    target: "node",
                    %peer,
                    error = %err,
                    "failed to decode VRF gossip payload"
                );
                self.enqueue_proof_penalty(peer, ProofReputationCode::InvalidVrfSubmission);
                return None;
            }
        };
        let submission = match gossip_to_submission(payload) {
            Ok(submission) => submission,
            Err(err) => {
                warn!(
                    target: "node",
                    %peer,
                    error = %err,
                    "invalid VRF gossip payload"
                );
                self.enqueue_proof_penalty(peer, ProofReputationCode::InvalidVrfSubmission);
                return None;
            }
        };
        if let Err(err) = verify_submission(&submission) {
            warn!(
                target: "node",
                %peer,
                error = %err,
                "VRF submission verification failed"
            );
            self.enqueue_proof_penalty(peer, ProofReputationCode::InvalidVrfSubmission);
            None
        } else {
            Some(submission)
        }
    }
}

impl GossipBlockValidator for Block {
    fn advertised_block_hash(&self) -> &str {
        &self.hash
    }

    fn computed_block_hash(&self) -> Result<String, String> {
        Ok(hex::encode(self.header.hash()))
    }
}

impl GossipVoteValidator for SignedBftVote {
    fn verify_vote(&self) -> Result<(), String> {
        self.verify().map_err(|err| err.to_string())
    }
}

/// Node runtime internals responsible for coordinating networking and telemetry.
pub struct NodeInner {
    network: rpp_p2p::Network,
    identity: Arc<NodeIdentity>,
    commands: mpsc::Receiver<NodeCommand>,
    events: broadcast::Sender<NodeEvent>,
    metrics: Arc<RwLock<NodeMetrics>>,
    runtime_metrics: Arc<RuntimeMetrics>,
    connected_peers: HashSet<PeerId>,
    known_versions: HashMap<PeerId, String>,
    peer_features: HashMap<PeerId, FeatureGates>,
    local_features: FeatureGates,
    meta_telemetry: MetaTelemetry,
    heartbeat_interval: Duration,
    gossip_enabled: bool,
    reputation_heuristics: ReputationHeuristics,
    pipelines: GossipPipelines,
    snapshot_streams: Arc<RwLock<HashMap<SnapshotSessionId, SnapshotStreamStatus>>>,
    heuristic_counters: HashMap<PeerId, PeerHeuristics>,
}

impl NodeInner {
    /// Builds a new [`NodeInner`] alongside its corresponding [`NodeHandle`].
    pub fn new(config: NodeRuntimeConfig) -> Result<(Self, NodeHandle), NodeError> {
        let network_config = NetworkConfig::from_config(&config.p2p)?;
        let resources = NetworkResources::initialise(
            &config.identity_path,
            &network_config,
            &config.p2p,
            config.identity.clone(),
            config.feature_gates.clone(),
            config.snapshot_provider.clone(),
        )?;
        let (network, identity, peerstore) = resources.into_parts();
        let (command_tx, command_rx) = mpsc::channel(64);
        let (event_tx, _) = broadcast::channel(256);
        let metrics = Arc::new(RwLock::new(NodeMetrics::default()));
        let mut pipelines = GossipPipelines::initialise(&config, command_tx.clone())?;
        let light_client_heads = pipelines.light_client.subscribe_light_client_heads();
        pipelines.register_voter(identity.peer_id(), identity.tier());
        let snapshot_streams = Arc::new(RwLock::new(HashMap::new()));
        let handle = NodeHandle {
            commands: command_tx.clone(),
            metrics: metrics.clone(),
            runtime_metrics: config.metrics.clone(),
            events: event_tx.clone(),
            local_peer_id: identity.peer_id(),
            light_client_heads,
            snapshot_streams: snapshot_streams.clone(),
            peerstore: peerstore.clone(),
        };
        let local_features = config
            .identity
            .as_ref()
            .map(|profile| profile.feature_gates.clone())
            .unwrap_or_else(|| config.feature_gates.clone());
        let heuristics = network_config.reputation_heuristics();
        let inner = Self {
            network,
            identity,
            commands: command_rx,
            events: event_tx,
            metrics,
            runtime_metrics: config.metrics,
            connected_peers: HashSet::new(),
            known_versions: HashMap::new(),
            meta_telemetry: MetaTelemetry::new(),
            heartbeat_interval: network_config.heartbeat_interval(),
            gossip_enabled: network_config.gossip_enabled(),
            reputation_heuristics: heuristics,
            pipelines,
            snapshot_streams,
            peer_features: HashMap::new(),
            local_features,
            heuristic_counters: HashMap::new(),
        };
        Ok((inner, handle))
    }

    /// Main async loop that drives network events and periodic telemetry.
    pub async fn run(mut self) -> Result<(), NodeError> {
        let mut heartbeat = time::interval(self.heartbeat_interval);
        if self.gossip_enabled {
            self.publish_feature_announcement();
        }
        loop {
            tokio::select! {
                Some(command) = self.commands.recv() => {
                    if self.handle_command(command).await? {
                        break;
                    }
                }
                event = self.network.next_event() => {
                    let event = event?;
                    self.handle_network_event(event);
                }
                _ = heartbeat.tick() => {
                    self.emit_heartbeat().await;
                }
            }
        }
        Ok(())
    }

    fn publish_feature_announcement(&mut self) {
        if !self.gossip_enabled {
            return;
        }
        let announcement = FeatureAnnouncement {
            peer_id: self.identity.peer_id(),
            feature_gates: self.local_features.clone(),
        };
        let payload = match serde_json::to_vec(&NetworkFeatureAnnouncement::from(&announcement)) {
            Ok(payload) => payload,
            Err(err) => {
                warn!(
                    target: "node",
                    %err,
                    "failed to encode feature announcement",
                );
                return;
            }
        };
        if let Err(err) = self.network.publish(GossipTopic::Meta, payload) {
            warn!(
                target: "node",
                %err,
                "failed to publish feature announcement",
            );
        }
    }

    fn update_snapshot_status<F>(
        &self,
        session: SnapshotSessionId,
        peer: &PeerId,
        root_hint: Option<String>,
        update: F,
    ) -> SnapshotStreamStatus
    where
        F: FnOnce(&mut SnapshotStreamStatus),
    {
        let mut streams = self.snapshot_streams.write();
        let default_root = root_hint.clone().unwrap_or_default();
        let entry = streams
            .entry(session)
            .or_insert_with(|| SnapshotStreamStatus::new(session, peer.clone(), default_root));
        entry.session = session;
        entry.peer = peer.clone();
        if let Some(root) = root_hint {
            if !root.is_empty() {
                entry.root = root;
            }
        }
        update(entry);
        entry.clone()
    }

    fn snapshot_stream_failure(
        &self,
        session: SnapshotSessionId,
        peer: PeerId,
        reason: impl Into<String>,
    ) {
        let reason = reason.into();
        let status = self.update_snapshot_status(session, &peer, None, |status| {
            status.error = Some(reason.clone());
            if status.verified != Some(true) {
                status.verified = Some(false);
            }
        });
        let _ = self.events.send(NodeEvent::SnapshotStreamFailed {
            session,
            peer,
            status,
            reason,
        });
    }

    async fn handle_command(&mut self, command: NodeCommand) -> Result<bool, NodeError> {
        match command {
            NodeCommand::Publish {
                topic,
                data,
                response,
            } => {
                let result = if self.gossip_enabled {
                    self.network
                        .publish(topic, data)
                        .map(|_| ())
                        .map_err(NodeError::from)
                } else {
                    Err(NodeError::GossipDisabled)
                };
                let _ = response.send(result);
                Ok(false)
            }
            NodeCommand::UpdateIdentity { profile, response } => {
                let tier = profile.tier;
                let features = profile.feature_gates.clone();
                let result = self
                    .network
                    .update_identity(
                        profile.zsi_id,
                        tier,
                        profile.vrf_public_key,
                        profile.vrf_proof,
                        profile.feature_gates.advertise(),
                    )
                    .map_err(NodeError::from);
                if result.is_ok() {
                    self.local_features = features;
                    self.pipelines.register_voter(self.identity.peer_id(), tier);
                    self.publish_feature_announcement();
                }
                let _ = response.send(result);
                Ok(false)
            }
            NodeCommand::MetaTelemetrySnapshot { response } => {
                let peer_count = self.connected_peers.len();
                let report = self.build_meta_report(peer_count);
                let _ = response.send(Ok(report));
                Ok(false)
            }
            NodeCommand::ReloadAccessLists {
                allowlist,
                blocklist,
                response,
            } => {
                let result = self
                    .network
                    .reload_access_lists(allowlist, blocklist)
                    .map_err(NodeError::from);
                let _ = response.send(result);
                Ok(false)
            }
            NodeCommand::StartSnapshotStream {
                session,
                peer,
                root,
                response,
            } => {
                let result = self
                    .network
                    .start_snapshot_stream(session, peer.clone(), root.clone())
                    .map_err(NodeError::from);
                if result.is_ok() {
                    self.update_snapshot_status(session, &peer, Some(root), |status| {
                        status.last_chunk_index = None;
                        status.last_update_index = None;
                        status.last_update_height = None;
                        status.verified = None;
                        status.error = None;
                    });
                }
                let _ = response.send(result);
                Ok(false)
            }
            NodeCommand::ResumeSnapshotStream { session, response } => {
                let resume_params = {
                    let streams = self.snapshot_streams.read();
                    streams.get(&session).map(|status| {
                        let next_chunk = status
                            .last_chunk_index
                            .map(|index| index.saturating_add(1))
                            .unwrap_or(0);
                        let next_update = status
                            .last_update_index
                            .map(|index| index.saturating_add(1))
                            .unwrap_or(0);
                        (status.peer.clone(), next_chunk, next_update)
                    })
                };
                let (peer, next_chunk, next_update) = match resume_params {
                    Some(params) => params,
                    None => {
                        let _ = response.send(Err(NodeError::SnapshotStreamNotFound));
                        return Ok(false);
                    }
                };
                let result = self
                    .network
                    .resume_snapshot_stream(session, next_chunk, next_update)
                    .map_err(NodeError::from);
                if result.is_ok() {
                    self.update_snapshot_status(session, &peer, None, |status| {
                        status.error = None;
                        status.verified = None;
                    });
                }
                let _ = response.send(result);
                Ok(false)
            }
            NodeCommand::CancelSnapshotStream { session, response } => {
                let result = self
                    .network
                    .cancel_snapshot_stream(session)
                    .map_err(NodeError::from);
                if result.is_ok() {
                    self.snapshot_streams.write().remove(&session);
                }
                let _ = response.send(result);
                Ok(false)
            }
            NodeCommand::Shutdown => Ok(true),
            NodeCommand::ApplyReputationPenalty { peer, code } => {
                if let Err(err) = self.apply_reputation_penalty(peer, code) {
                    warn!(
                        target: "node",
                        %peer,
                        ?err,
                        "failed to apply reputation penalty"
                    );
                }
                Ok(false)
            }
            NodeCommand::ReportBackpressure { topic, queue_depth } => {
                self.report_gossip_backpressure(topic, queue_depth);
                Ok(false)
            }
            NodeCommand::HeuristicsSnapshot { response } => {
                let snapshot = self.heuristics_snapshot();
                let _ = response.send(snapshot);
                Ok(false)
            }
        }
    }

    fn handle_network_event(&mut self, event: NetworkEvent) {
        let event_span = info_span!("node.runtime.network_event", event = ?event);
        let _event_guard = event_span.enter();
        match event {
            NetworkEvent::NewListenAddr(addr) => {
                info!(target: "node", "listening on {addr}");
            }
            NetworkEvent::HandshakeCompleted { peer, payload } => {
                info!(target: "node", "peer connected: {peer}");
                self.connected_peers.insert(peer);
                let tier = payload.tier;
                self.pipelines.register_voter(peer, tier);
                let features = match FeatureGates::from_advertisement(&payload.features) {
                    Ok(gates) => gates,
                    Err(err) => {
                        warn!(
                            target: "node",
                            ?peer,
                            %err,
                            "invalid feature advertisement in handshake"
                        );
                        FeatureGates::default()
                    }
                };
                self.peer_features.insert(peer, features);
                let agent_version = payload
                    .telemetry
                    .as_ref()
                    .and_then(|meta| meta.tags.get("agent"))
                    .cloned()
                    .unwrap_or_else(|| payload.zsi_id.clone());
                self.known_versions.insert(peer, agent_version.clone());
                self.meta_telemetry
                    .record(peer, agent_version, Duration::from_millis(0));
                let _ = self.events.send(NodeEvent::PeerConnected { peer, payload });
                self.publish_feature_announcement();
            }
            NetworkEvent::PeerDisconnected { peer } => {
                info!(target: "node", "peer disconnected: {peer}");
                self.connected_peers.remove(&peer);
                self.known_versions.remove(&peer);
                self.peer_features.remove(&peer);
                self.pipelines.remove_voter(&peer);
                let _ = self.events.send(NodeEvent::PeerDisconnected { peer });
            }
            NetworkEvent::PingSuccess { peer, rtt } => {
                let version = self
                    .known_versions
                    .get(&peer)
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string());
                self.meta_telemetry.record(peer, version, rtt);
                debug!(
                    target: "telemetry.ping",
                    peer = %self.identity.peer_id(),
                    remote = %peer,
                    latency_ms = rtt.as_millis(),
                    "ping_success"
                );
            }
            NetworkEvent::PingFailure {
                peer,
                reason,
                consecutive_failures,
            } => {
                warn!(
                    target: "telemetry.ping",
                    peer = %self.identity.peer_id(),
                    remote = %peer,
                    %reason,
                    failures = consecutive_failures,
                    "ping_failure"
                );
            }
            NetworkEvent::GossipMessage { peer, topic, data } => {
                if self.gossip_enabled {
                    if let Some(version) = self.known_versions.get(&peer) {
                        self.meta_telemetry
                            .record(peer, version.clone(), Duration::from_millis(0));
                    }
                    let payload_len = data.len();
                    let gossip_span = info_span!(
                        "node.runtime.gossip",
                        peer = %peer,
                        topic = ?topic,
                        bytes = payload_len
                    );
                    let _gossip_guard = gossip_span.enter();
                    match topic {
                        GossipTopic::Blocks => {
                            match self.pipelines.handle_blocks(peer.clone(), data.clone()) {
                                BlockIngestResult::Duplicate => {
                                    debug!(
                                        target: "node",
                                        ?peer,
                                        "duplicate block gossip ignored"
                                    );
                                }
                                BlockIngestResult::Valid(block) => {
                                    debug!(target: "node", ?peer, "block gossip ingested");
                                    if let Err(err) = self.pipelines.ingest_proposal(
                                        peer.clone(),
                                        &block.hash,
                                        data.clone(),
                                    ) {
                                        warn!(
                                            target: "node",
                                            ?peer,
                                            ?err,
                                            "failed to ingest block into consensus pipeline"
                                        );
                                    } else {
                                        let _ = self.events.send(NodeEvent::BlockProposal {
                                            peer: peer.clone(),
                                            block,
                                        });
                                    }
                                }
                                BlockIngestResult::Invalid { block, reason } => {
                                    warn!(
                                        target: "node",
                                        ?peer,
                                        %reason,
                                        "invalid block gossip"
                                    );
                                    let _ = self.events.send(NodeEvent::BlockRejected {
                                        peer: peer.clone(),
                                        block,
                                        reason,
                                    });
                                }
                                BlockIngestResult::DecodeFailed(reason) => {
                                    warn!(
                                        target: "node",
                                        ?peer,
                                        %reason,
                                        "failed to decode block gossip"
                                    );
                                }
                            }
                        }
                        GossipTopic::Votes => {
                            match self.pipelines.handle_votes(peer.clone(), data.clone()) {
                                VoteIngestResult::Duplicate => {
                                    debug!(
                                        target: "node",
                                        ?peer,
                                        "duplicate vote gossip ignored"
                                    );
                                }
                                VoteIngestResult::Valid { vote, digest } => {
                                    debug!(target: "node", ?peer, "vote gossip ingested");
                                    match self.pipelines.ingest_vote(
                                        peer.clone(),
                                        &vote.vote.block_hash,
                                        vote.vote.round,
                                        data.clone(),
                                        digest,
                                    ) {
                                        Ok(VoteOutcome::Recorded {
                                            reached_quorum,
                                            power,
                                        }) => {
                                            if reached_quorum {
                                                info!(
                                                    target: "node",
                                                    ?peer,
                                                    power = power,
                                                    "consensus quorum reached via gossip"
                                                );
                                                if let Err(err) =
                                                    self.pipelines.prune(&vote.vote.block_hash)
                                                {
                                                    warn!(
                                                        target: "node",
                                                        ?peer,
                                                        ?err,
                                                        "failed to prune consensus pipeline"
                                                    );
                                                }
                                            }
                                            let _ = self.events.send(NodeEvent::Vote {
                                                peer: peer.clone(),
                                                vote,
                                            });
                                        }
                                        Ok(VoteOutcome::Duplicate) => {
                                            debug!(
                                                target: "node",
                                                ?peer,
                                                "duplicate vote ignored by consensus pipeline"
                                            );
                                        }
                                        Err(err) => {
                                            warn!(
                                                target: "node",
                                                ?peer,
                                                ?err,
                                                "failed to ingest vote into consensus pipeline"
                                            );
                                        }
                                    }
                                }
                                VoteIngestResult::Invalid { vote, reason } => {
                                    warn!(
                                        target: "node",
                                        ?peer,
                                        %reason,
                                        "invalid vote gossip"
                                    );
                                    let reason_lower = reason.to_lowercase();
                                    if reason_lower.contains("timeout")
                                        || reason_lower.contains("expired")
                                        || reason_lower.contains("stale")
                                    {
                                        self.apply_reputation_event(
                                            peer.clone(),
                                            ReputationEvent::VoteTimeout {
                                                height: vote.vote.height,
                                                round: vote.vote.round,
                                            },
                                        );
                                    }
                                    let _ = self.events.send(NodeEvent::VoteRejected {
                                        peer: peer.clone(),
                                        vote,
                                        reason,
                                    });
                                }
                                VoteIngestResult::DecodeFailed(reason) => {
                                    warn!(
                                        target: "node",
                                        ?peer,
                                        %reason,
                                        "failed to decode vote gossip"
                                    );
                                }
                            }
                        }
                        GossipTopic::VrfProofs => {
                            if let Some(submission) =
                                self.pipelines.handle_vrf_proofs(peer.clone(), data.clone())
                            {
                                let _ = self
                                    .events
                                    .send(NodeEvent::VrfSubmission { peer, submission });
                            }
                        }
                        GossipTopic::Proofs | GossipTopic::WitnessProofs => {
                            let proof_span = info_span!(
                                "node.runtime.proof.pipeline",
                                peer = %peer,
                                bytes = payload_len,
                                topic = ?topic
                            );
                            let _proof_guard = proof_span.enter();
                            self.pipelines
                                .handle_proofs(peer.clone(), topic, data.clone());
                        }
                        GossipTopic::Snapshots => {
                            self.pipelines.handle_snapshots(&data);
                        }
                        GossipTopic::Meta | GossipTopic::WitnessMeta => {
                            match self.pipelines.handle_meta(peer.clone(), data.clone()) {
                                MetaIngestResult::Duplicate => {
                                    debug!(
                                        target: "node",
                                        ?peer,
                                        "duplicate meta gossip ignored"
                                    );
                                }
                                MetaIngestResult::Payload(payload) => match payload {
                                    MetaPayload::Reputation(broadcast) => {
                                        if peer == self.identity.peer_id() {
                                            debug!(
                                                target: "node",
                                                ?peer,
                                                "ignoring local reputation broadcast"
                                            );
                                        } else if let Err(err) =
                                            self.network.apply_reputation_broadcast(broadcast)
                                        {
                                            warn!(
                                                target: "node",
                                                ?peer,
                                                %err,
                                                "failed to apply reputation broadcast"
                                            );
                                        }
                                    }
                                    MetaPayload::Evidence(evidence) => {
                                        debug!(
                                            target: "node",
                                            ?peer,
                                            "meta evidence gossip ingested"
                                        );
                                        let _ = self.events.send(NodeEvent::Evidence {
                                            peer: peer.clone(),
                                            evidence,
                                        });
                                    }
                                    MetaPayload::Telemetry(report) => {
                                        let remote = report.local_peer_id;
                                        if remote != peer {
                                            warn!(
                                                target: "node",
                                                expected = %peer,
                                                received = %remote,
                                                "meta telemetry peer mismatch"
                                            );
                                        }
                                        let version = self
                                            .known_versions
                                            .get(&remote)
                                            .cloned()
                                            .unwrap_or_else(|| remote.to_base58());
                                        if let Some(entry) = report.peers.iter().find(|telemetry| {
                                            telemetry.peer == self.identity.peer_id()
                                        }) {
                                            self.meta_telemetry.record_at(
                                                remote,
                                                version,
                                                Duration::from_millis(entry.latency_ms),
                                                entry.last_seen,
                                            );
                                        }
                                    }
                                    MetaPayload::FeatureAnnouncement(announcement) => {
                                        if announcement.peer_id != peer {
                                            warn!(
                                                target: "node",
                                                expected = %peer,
                                                announced = %announcement.peer_id,
                                                "feature announcement peer mismatch",
                                            );
                                        }
                                        self.peer_features.insert(
                                            announcement.peer_id,
                                            announcement.feature_gates,
                                        );
                                    }
                                    MetaPayload::TimetokeDelta(delta) => {
                                        debug!(
                                            target: "node",
                                            ?peer,
                                            "meta timetoke delta ingested"
                                        );
                                        let _ = self.events.send(NodeEvent::TimetokeDelta {
                                            peer: peer.clone(),
                                            delta,
                                        });
                                    }
                                },
                                MetaIngestResult::DecodeFailed(reason) => {
                                    warn!(
                                    target: "node",
                                    ?peer,
                                        %reason,
                                        "failed to decode meta gossip"
                                    );
                                }
                            }
                        }
                    }
                    let _ = self.events.send(NodeEvent::Gossip { peer, topic, data });
                }
            }
            NetworkEvent::SnapshotPlan {
                peer,
                session,
                plan,
            } => {
                let payload = match serde_json::to_vec(&plan) {
                    Ok(payload) => payload,
                    Err(err) => {
                        warn!(
                            target: "node",
                            %peer,
                            session = session.get(),
                            %err,
                            "failed to encode snapshot plan"
                        );
                        self.snapshot_stream_failure(
                            session,
                            peer,
                            format!("failed to encode snapshot plan: {err}"),
                        );
                        return;
                    }
                };
                match self.pipelines.light_client.ingest_plan(&payload) {
                    Ok(()) | Err(PipelineError::Duplicate) => {
                        debug!(
                            target: "node",
                            %peer,
                            session = session.get(),
                            height = plan.snapshot.height,
                            "snapshot plan received"
                        );
                        let plan_clone = plan.clone();
                        let status = self.update_snapshot_status(
                            session,
                            &peer,
                            Some(plan.snapshot.chain_commitment.clone()),
                            |status| {
                                status.last_chunk_index = None;
                                status.last_update_index = None;
                                status.last_update_height = None;
                                status.verified = None;
                                status.error = None;
                            },
                        );
                        let stage = SnapshotStreamProgressStage::Plan { plan: plan_clone };
                        let _ = self.events.send(NodeEvent::SnapshotStreamProgress {
                            session,
                            peer,
                            status,
                            stage,
                        });
                    }
                    Err(err) => {
                        warn!(
                            target: "node",
                            %peer,
                            session = session.get(),
                            ?err,
                            "failed to ingest snapshot plan"
                        );
                        self.snapshot_stream_failure(
                            session,
                            peer,
                            format!("failed to ingest snapshot plan: {err}"),
                        );
                    }
                }
            }
            NetworkEvent::SnapshotChunk {
                peer,
                session,
                index,
                chunk,
            } => {
                let payload = match serde_json::to_vec(&chunk) {
                    Ok(payload) => payload,
                    Err(err) => {
                        warn!(
                            target: "node",
                            %peer,
                            session = session.get(),
                            %index,
                            %err,
                            "failed to encode snapshot chunk"
                        );
                        self.snapshot_stream_failure(
                            session,
                            peer,
                            format!("failed to encode snapshot chunk: {err}"),
                        );
                        return;
                    }
                };
                match self.pipelines.light_client.ingest_chunk(&payload) {
                    Ok(()) | Err(PipelineError::Duplicate) => {
                        debug!(
                            target: "node",
                            %peer,
                            session = session.get(),
                            %index,
                            "snapshot chunk received"
                        );
                        let chunk_clone = chunk.clone();
                        let root = chunk.root.to_hex().to_string();
                        let status =
                            self.update_snapshot_status(session, &peer, Some(root), |status| {
                                status.last_chunk_index = Some(
                                    status
                                        .last_chunk_index
                                        .map(|previous| previous.max(index))
                                        .unwrap_or(index),
                                );
                                status.error = None;
                            });
                        let stage = SnapshotStreamProgressStage::Chunk {
                            index,
                            chunk: chunk_clone,
                        };
                        let _ = self.events.send(NodeEvent::SnapshotStreamProgress {
                            session,
                            peer,
                            status,
                            stage,
                        });
                    }
                    Err(err) => {
                        warn!(
                            target: "node",
                            %peer,
                            session = session.get(),
                            %index,
                            ?err,
                            "failed to ingest snapshot chunk"
                        );
                        self.snapshot_stream_failure(
                            session,
                            peer,
                            format!("failed to ingest snapshot chunk: {err}"),
                        );
                    }
                }
            }
            NetworkEvent::SnapshotUpdate {
                peer,
                session,
                index,
                update,
            } => {
                let payload = match serde_json::to_vec(&update) {
                    Ok(payload) => payload,
                    Err(err) => {
                        warn!(
                            target: "node",
                            %peer,
                            session = session.get(),
                            %index,
                            %err,
                            "failed to encode snapshot update"
                        );
                        self.snapshot_stream_failure(
                            session,
                            peer,
                            format!("failed to encode snapshot update: {err}"),
                        );
                        return;
                    }
                };
                match self
                    .pipelines
                    .light_client
                    .ingest_light_client_update(&payload)
                {
                    Ok(()) | Err(PipelineError::Duplicate) => {
                        debug!(
                            target: "node",
                            %peer,
                            session = session.get(),
                            %index,
                            "snapshot update received"
                        );
                        let update_clone = update.clone();
                        let status = self.update_snapshot_status(session, &peer, None, |status| {
                            let previous = status.last_update_index;
                            let updated_index = previous
                                .map(|existing| existing.max(index))
                                .unwrap_or(index);
                            status.last_update_index = Some(updated_index);
                            if previous.map_or(true, |existing| index >= existing) {
                                status.last_update_height = Some(update.height);
                            }
                            status.error = None;
                        });
                        let stage = SnapshotStreamProgressStage::Update {
                            index,
                            update: update_clone,
                        };
                        let _ = self.events.send(NodeEvent::SnapshotStreamProgress {
                            session,
                            peer,
                            status,
                            stage,
                        });
                    }
                    Err(err) => {
                        warn!(
                            target: "node",
                            %peer,
                            session = session.get(),
                            %index,
                            ?err,
                            "failed to ingest snapshot update"
                        );
                        self.snapshot_stream_failure(
                            session,
                            peer,
                            format!("failed to ingest snapshot update: {err}"),
                        );
                    }
                }
            }
            NetworkEvent::SnapshotStreamCompleted { peer, session } => {
                info!(
                    target: "node",
                    %peer,
                    session = session.get(),
                    "snapshot stream completed"
                );
                match self.pipelines.light_client.verify() {
                    Ok(verified) => {
                        let status = self.update_snapshot_status(session, &peer, None, |status| {
                            status.verified = Some(verified);
                            status.error = None;
                        });
                        let _ = self.events.send(NodeEvent::SnapshotStreamCompleted {
                            session,
                            peer,
                            status,
                            verified,
                        });
                    }
                    Err(err) => {
                        warn!(
                            target: "node",
                            %peer,
                            session = session.get(),
                            ?err,
                            "snapshot verification failed"
                        );
                        self.snapshot_stream_failure(
                            session,
                            peer,
                            format!("snapshot verification failed: {err}"),
                        );
                    }
                }
            }
            NetworkEvent::SnapshotStreamError {
                peer,
                session,
                reason,
            } => {
                warn!(
                    target: "node",
                    %peer,
                    session = session.get(),
                    %reason,
                    "snapshot stream error"
                );
                self.snapshot_stream_failure(session, peer, reason);
            }
            NetworkEvent::ReputationUpdated {
                peer,
                tier,
                score,
                label,
            } => {
                debug!(
                    target: "node",
                    "reputation updated for {peer}: tier={tier:?} score={score} label={label}"
                );
            }
            NetworkEvent::PeerBanned { peer, until } => {
                warn!(target: "node", "peer {peer} banned until {until:?}");
            }
            NetworkEvent::AdmissionRejected {
                peer,
                topic,
                reason,
            } => {
                warn!(
                    target: "node",
                    "peer {peer} rejected on topic {topic:?}: {reason}"
                );
            }
        }
    }

    fn apply_reputation_penalty(
        &mut self,
        peer: PeerId,
        code: ProofReputationCode,
    ) -> Result<(), NodeError> {
        let event = match code {
            ProofReputationCode::InvalidProof => ReputationEvent::ManualPenalty {
                amount: 1.0,
                reason: Cow::Borrowed("invalid_proof"),
            },
            ProofReputationCode::DuplicateProof => ReputationEvent::ManualPenalty {
                amount: 0.2,
                reason: Cow::Borrowed("duplicate_proof"),
            },
            ProofReputationCode::PipelineFailure => ReputationEvent::ManualPenalty {
                amount: 0.5,
                reason: Cow::Borrowed("proof_pipeline_error"),
            },
            ProofReputationCode::InvalidVrfSubmission => ReputationEvent::ManualPenalty {
                amount: 1.0,
                reason: Cow::Borrowed("invalid_vrf_submission"),
            },
            ProofReputationCode::InvalidTimetokeDelta => ReputationEvent::ManualPenalty {
                amount: 1.0,
                reason: Cow::Borrowed("invalid_timetoke_delta"),
            },
        };
        let label = event.label().to_string();
        self.runtime_metrics
            .record_reputation_penalty(label.clone());
        self.network
            .apply_reputation_event(peer.clone(), event)
            .map_err(NodeError::from)?;
        debug!(
            target: "node",
            %peer,
            label = %label,
            "applied reputation penalty"
        );
        Ok(())
    }

    fn apply_reputation_event(&mut self, peer: PeerId, event: ReputationEvent) {
        let label = event.label().to_string();
        self.update_peer_heuristics(&peer, &event);
        if let Err(err) = self.network.apply_reputation_event(peer.clone(), event) {
            warn!(
                target: "node",
                %peer,
                ?err,
                "failed to apply reputation heuristic event"
            );
        } else {
            debug!(
                target: "node",
                %peer,
                label = %label,
                "applied reputation heuristic"
            );
        }
    }

    fn report_gossip_backpressure(&mut self, topic: GossipTopic, queue_depth: usize) {
        if queue_depth < self.reputation_heuristics.gossip_backpressure_threshold {
            return;
        }
        if self.connected_peers.is_empty() {
            return;
        }
        let event = ReputationEvent::GossipBackpressure { topic, queue_depth };
        for peer in self.connected_peers.clone() {
            self.apply_reputation_event(peer, event.clone());
        }
    }

    fn update_peer_heuristics(&mut self, peer: &PeerId, event: &ReputationEvent) {
        let counters = self
            .heuristic_counters
            .entry(peer.clone())
            .or_insert_with(PeerHeuristics::default);
        match event {
            ReputationEvent::VoteTimeout { .. } => {
                counters.vote_timeouts = counters.vote_timeouts.saturating_add(1);
            }
            ReputationEvent::ProofRelayMissed { .. } => {
                counters.proof_relay_misses = counters.proof_relay_misses.saturating_add(1);
            }
            ReputationEvent::GossipBackpressure { .. } => {
                counters.gossip_backpressure_events =
                    counters.gossip_backpressure_events.saturating_add(1);
            }
            _ => {}
        }
    }

    fn heuristics_snapshot(&self) -> Vec<(PeerId, PeerHeuristics)> {
        self.heuristic_counters
            .iter()
            .map(|(peer, counters)| (peer.clone(), counters.clone()))
            .collect()
    }

    async fn emit_heartbeat(&mut self) {
        let metrics = self.metrics.read().clone();
        let peer_count = self.connected_peers.len();
        let verifier_metrics = metrics.verifier_metrics.clone();
        self.runtime_metrics.record_peer_count(peer_count);
        let heartbeat = Heartbeat {
            peer_count,
            block_height: metrics.block_height,
            block_hash: metrics.block_hash.clone(),
            transaction_count: metrics.transaction_count,
            reputation_score: metrics.reputation_score,
        };
        let _ = self.events.send(NodeEvent::Heartbeat(heartbeat));

        let meta = self.build_meta_report(peer_count);
        let _ = self.events.send(NodeEvent::MetaTelemetry(meta.clone()));

        if self.gossip_enabled {
            let network_report = NetworkMetaTelemetryReport::from(&meta);
            match serde_json::to_vec(&network_report) {
                Ok(payload) => {
                    if let Err(err) = self.network.publish(GossipTopic::Meta, payload) {
                        warn!(
                            target: "node",
                            %err,
                            "failed to publish meta telemetry heartbeat"
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        target: "node",
                        %err,
                        "failed to encode meta telemetry heartbeat"
                    );
                }
            }
        }
    }

    fn build_meta_report(&self, peer_count: usize) -> MetaTelemetryReport {
        let mut peers = Vec::new();
        for peer in &self.connected_peers {
            if let Some(event) = self.meta_telemetry.latest(peer) {
                peers.push(PeerTelemetry {
                    peer: event.peer,
                    version: event.version.clone(),
                    latency_ms: event.latency.as_millis() as u64,
                    last_seen: event.received_at,
                });
            }
        }
        MetaTelemetryReport {
            local_peer_id: self.identity.peer_id(),
            peer_count,
            peers,
        }
    }
}

/// Handle used to interact with the asynchronous node runtime.
#[derive(Clone)]
pub struct NodeHandle {
    commands: mpsc::Sender<NodeCommand>,
    metrics: Arc<RwLock<NodeMetrics>>,
    runtime_metrics: Arc<RuntimeMetrics>,
    events: broadcast::Sender<NodeEvent>,
    local_peer_id: PeerId,
    light_client_heads: watch::Receiver<Option<LightClientHead>>,
    snapshot_streams: Arc<RwLock<HashMap<SnapshotSessionId, SnapshotStreamStatus>>>,
    peerstore: Arc<Peerstore>,
}

impl NodeHandle {
    /// Returns a broadcast receiver for node events.
    pub fn subscribe(&self) -> broadcast::Receiver<NodeEvent> {
        self.events.subscribe()
    }

    /// Subscribes to verified light client head updates emitted by the gossip pipeline.
    pub fn subscribe_light_client_heads(&self) -> watch::Receiver<Option<LightClientHead>> {
        self.light_client_heads.clone()
    }

    /// Returns the latest verified light client head, if any have been observed.
    pub fn latest_light_client_head(&self) -> Option<LightClientHead> {
        self.light_client_heads.borrow().clone()
    }

    /// Returns the current snapshot stream status for the provided session, if known.
    pub fn snapshot_stream_status(
        &self,
        session: SnapshotSessionId,
    ) -> Option<SnapshotStreamStatus> {
        self.snapshot_streams.read().get(&session).cloned()
    }

    /// Returns all tracked snapshot stream statuses.
    pub fn all_snapshot_streams(&self) -> Vec<SnapshotStreamStatus> {
        self.snapshot_streams.read().values().cloned().collect()
    }

    /// Updates the metrics that will be forwarded to telemetry.
    pub fn update_metrics(&self, metrics: NodeMetrics) {
        *self.metrics.write() = metrics;
    }

    pub fn admission_policies(&self) -> AdmissionPolicies {
        self.peerstore.admission_policies()
    }

    pub fn update_admission_policies(
        &self,
        allowlist: Vec<AllowlistedPeer>,
        blocklist: Vec<PeerId>,
        audit: AdmissionAuditTrail,
    ) -> Result<(), NodeError> {
        self.peerstore
            .update_admission_policies(allowlist, blocklist, audit)
            .map_err(NodeError::from)
    }

    /// Publishes a gossip message via the libp2p network.
    #[instrument(
        name = "node.runtime.publish_gossip",
        skip(self, data),
        fields(topic = ?topic, bytes = data.len())
    )]
    pub async fn publish_gossip(&self, topic: GossipTopic, data: Vec<u8>) -> Result<(), NodeError> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(NodeCommand::Publish {
                topic,
                data,
                response: tx,
            })
            .await
            .map_err(|_| NodeError::CommandChannelClosed)?;
        let result = rx.await.map_err(|_| NodeError::CommandChannelClosed)?;
        result
    }

    pub async fn apply_reputation_penalty(
        &self,
        peer: PeerId,
        code: ProofReputationCode,
    ) -> Result<(), NodeError> {
        self.commands
            .send(NodeCommand::ApplyReputationPenalty { peer, code })
            .await
            .map_err(|_| NodeError::CommandChannelClosed)
    }

    pub async fn report_gossip_backpressure(
        &self,
        topic: GossipTopic,
        queue_depth: usize,
    ) -> Result<(), NodeError> {
        self.commands
            .send(NodeCommand::ReportBackpressure { topic, queue_depth })
            .await
            .map_err(|_| NodeError::CommandChannelClosed)
    }

    pub async fn start_snapshot_stream(
        &self,
        session: SnapshotSessionId,
        peer: PeerId,
        root: String,
    ) -> Result<(), NodeError> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(NodeCommand::StartSnapshotStream {
                session,
                peer,
                root,
                response: tx,
            })
            .await
            .map_err(|_| NodeError::CommandChannelClosed)?;
        rx.await.map_err(|_| NodeError::CommandChannelClosed)??;
        Ok(())
    }

    pub async fn resume_snapshot_stream(
        &self,
        session: SnapshotSessionId,
    ) -> Result<(), NodeError> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(NodeCommand::ResumeSnapshotStream {
                session,
                response: tx,
            })
            .await
            .map_err(|_| NodeError::CommandChannelClosed)?;
        rx.await.map_err(|_| NodeError::CommandChannelClosed)??;
        Ok(())
    }

    pub async fn cancel_snapshot_stream(
        &self,
        session: SnapshotSessionId,
    ) -> Result<(), NodeError> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(NodeCommand::CancelSnapshotStream {
                session,
                response: tx,
            })
            .await
            .map_err(|_| NodeError::CommandChannelClosed)?;
        rx.await.map_err(|_| NodeError::CommandChannelClosed)??;
        Ok(())
    }

    pub async fn heuristics_snapshot(&self) -> Result<Vec<(PeerId, PeerHeuristics)>, NodeError> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(NodeCommand::HeuristicsSnapshot { response: tx })
            .await
            .map_err(|_| NodeError::CommandChannelClosed)?;
        rx.await.map_err(|_| NodeError::CommandChannelClosed)
    }

    pub async fn reload_access_lists(
        &self,
        allowlist: Vec<AllowlistedPeer>,
        blocklist: Vec<PeerId>,
    ) -> Result<(), NodeError> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(NodeCommand::ReloadAccessLists {
                allowlist,
                blocklist,
                response: tx,
            })
            .await
            .map_err(|_| NodeError::CommandChannelClosed)?;
        rx.await.map_err(|_| NodeError::CommandChannelClosed)??
    }

    /// Updates the handshake identity used for peer admission and gossip permissions.
    pub async fn update_identity(&self, profile: IdentityProfile) -> Result<(), NodeError> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(NodeCommand::UpdateIdentity {
                profile,
                response: tx,
            })
            .await
            .map_err(|_| NodeError::CommandChannelClosed)?;
        rx.await.map_err(|_| NodeError::CommandChannelClosed)?
    }

    /// Collects the latest meta telemetry snapshot across known peers.
    pub async fn meta_telemetry_snapshot(&self) -> Result<MetaTelemetryReport, NodeError> {
        let (tx, rx) = oneshot::channel();
        self.commands
            .send(NodeCommand::MetaTelemetrySnapshot { response: tx })
            .await
            .map_err(|_| NodeError::CommandChannelClosed)?;
        rx.await.map_err(|_| NodeError::CommandChannelClosed)??
    }

    /// Signals the runtime to shut down.
    pub async fn shutdown(&self) -> Result<(), NodeError> {
        self.commands
            .send(NodeCommand::Shutdown)
            .await
            .map_err(|_| NodeError::CommandChannelClosed)
    }

    /// Returns the local libp2p peer identifier.
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration as StdDuration;
    use tempfile::tempdir;
    use tokio::task::{self, LocalSet};
    use tokio::time::timeout;

    use serde_json::json;

    fn test_config(
        identity_path: PathBuf,
        listen: String,
        bootstrap: Vec<String>,
    ) -> NodeRuntimeConfig {
        let proof_storage_path = identity_path
            .parent()
            .map(|path| path.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
            .join("proofs.json");
        let consensus_storage_path = identity_path
            .parent()
            .map(|path| path.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
            .join("consensus_pipeline.json");
        let mut p2p = P2pConfig::default();
        p2p.listen_addr = listen;
        p2p.bootstrap_peers = bootstrap;
        p2p.heartbeat_interval_ms = 200;
        p2p.gossip_enabled = true;
        NodeRuntimeConfig {
            identity_path,
            p2p,
            telemetry: TelemetryConfig {
                enabled: false,
                endpoint: None,
                auth_token: None,
                timeout_ms: 50,
                retry_max: 0,
                sample_interval_secs: 1,
                redact_logs: true,
            },
            metrics: RuntimeMetrics::noop(),
            identity: None,
            proof_storage_path,
            consensus_storage_path,
            feature_gates: FeatureGates::default(),
            snapshot_provider: None,
        }
    }

    fn random_listen_addr() -> (String, u16) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind random port");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        (format!("/ip4/127.0.0.1/tcp/{port}"), port)
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nodes_exchange_gossip() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let dir_one = tempdir().expect("tempdir");
                let dir_two = tempdir().expect("tempdir");
                let (addr_one, _) = random_listen_addr();
                let (addr_two, _) = random_listen_addr();

                let config_one = test_config(
                    dir_one.path().join("node1.key"),
                    addr_one.clone(),
                    Vec::new(),
                );
                let config_two = test_config(
                    dir_two.path().join("node2.key"),
                    addr_two.clone(),
                    vec![addr_one.clone()],
                );

                let (node_one, handle_one) = NodeInner::new(config_one).expect("node1");
                let (node_two, handle_two) = NodeInner::new(config_two).expect("node2");
                let mut events_two = handle_two.subscribe();

                let task_one = task::spawn_local(async move {
                    node_one.run().await.expect("run node1");
                });
                let task_two = task::spawn_local(async move {
                    node_two.run().await.expect("run node2");
                });

                wait_for_peer_connected(&mut events_two).await;

                handle_one
                    .publish_gossip(GossipTopic::Blocks, b"hello".to_vec())
                    .await
                    .expect("publish");

                let received = timeout(StdDuration::from_secs(5), async {
                    loop {
                        match events_two.recv().await {
                            Ok(NodeEvent::Gossip { topic, data, .. }) => {
                                if topic == GossipTopic::Blocks && data == b"hello".to_vec() {
                                    break;
                                }
                            }
                            Ok(_) => continue,
                            Err(err) => panic!("event channel closed: {err}"),
                        }
                    }
                })
                .await;
                assert!(received.is_ok(), "gossip message not received");

                handle_one.shutdown().await.expect("shutdown1");
                handle_two.shutdown().await.expect("shutdown2");
                let _ = task_one.await;
                let _ = task_two.await;
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn proof_gossip_persists_to_storage() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let dir = tempdir().expect("tempdir");
                let (listen, _) = random_listen_addr();
                let identity_path = dir.path().join("node.key");
                let config = test_config(identity_path, listen, Vec::new());
                let proof_path = config.proof_storage_path.clone();
                let (mut node, _handle) = NodeInner::new(config).expect("node runtime");

                let payload = json!({
                    "transaction": {
                        "id": "00000000-0000-0000-0000-000000000000",
                        "payload": {
                            "from": "addr1",
                            "to": "addr2",
                            "amount": 1,
                            "fee": 1,
                            "nonce": 0,
                            "memo": null,
                            "timestamp": 0
                        },
                        "signature": "00",
                        "public_key": "00"
                    },
                    "proof": {
                        "stwo": {
                            "kind": "Transaction",
                            "commitment": hex::encode([0x11u8; 32]),
                            "public_inputs": [],
                            "payload": {"Transaction": {"dummy": true}},
                            "trace": {"rows": 0, "columns": 0},
                            "fri_proof": {"commitments": [], "challenges": []}
                        }
                    }
                });
                let data = serde_json::to_vec(&payload).expect("encode payload");
                let peer = PeerId::random();

                node.handle_network_event(NetworkEvent::GossipMessage {
                    peer,
                    topic: GossipTopic::WitnessProofs,
                    data,
                });

                let stored = std::fs::read_to_string(&proof_path).expect("proof storage exists");
                let records: serde_json::Value =
                    serde_json::from_str(&stored).expect("decode stored proofs");
                assert!(records
                    .as_array()
                    .map(|array| !array.is_empty())
                    .unwrap_or(false));
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn disconnect_produces_event() {
        let local = LocalSet::new();
        local
            .run_until(async {
                let dir_one = tempdir().expect("tempdir");
                let dir_two = tempdir().expect("tempdir");
                let (addr_one, _) = random_listen_addr();
                let (addr_two, _) = random_listen_addr();

                let config_one = test_config(
                    dir_one.path().join("node1.key"),
                    addr_one.clone(),
                    Vec::new(),
                );
                let config_two = test_config(
                    dir_two.path().join("node2.key"),
                    addr_two.clone(),
                    vec![addr_one.clone()],
                );

                let (node_one, handle_one) = NodeInner::new(config_one).expect("node1");
                let (node_two, handle_two) = NodeInner::new(config_two).expect("node2");
                let mut events_two = handle_two.subscribe();

                let task_one = task::spawn_local(async move {
                    node_one.run().await.expect("run node1");
                });
                let task_two = task::spawn_local(async move {
                    node_two.run().await.expect("run node2");
                });

                wait_for_peer_connected(&mut events_two).await;
                handle_one.shutdown().await.expect("shutdown1");

                let disconnected = timeout(StdDuration::from_secs(5), async {
                    loop {
                        match events_two.recv().await {
                            Ok(NodeEvent::PeerDisconnected { .. }) => break,
                            Ok(_) => continue,
                            Err(err) => panic!("event channel closed: {err}"),
                        }
                    }
                })
                .await;
                assert!(disconnected.is_ok(), "disconnect event not observed");

                handle_two.shutdown().await.expect("shutdown2");
                let _ = task_one.await;
                let _ = task_two.await;
            })
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn heartbeat_emits_events_and_metrics() {
        use opentelemetry_sdk::metrics::{
            InMemoryMetricExporter, PeriodicReader, SdkMeterProvider,
        };
        use std::collections::HashSet;

        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("heartbeat-test");
        let runtime_metrics = Arc::new(RuntimeMetrics::from_meter(&meter));
        let local = LocalSet::new();
        local
            .run_until(async {
                let dir = tempdir().expect("tempdir");
                let (addr, _) = random_listen_addr();
                let mut config = test_config(dir.path().join("node.key"), addr, Vec::new());
                config.metrics = runtime_metrics.clone();
                let (node, handle) = NodeInner::new(config).expect("node");
                let mut events = handle.subscribe();

                handle.update_metrics(NodeMetrics {
                    block_height: 12,
                    block_hash: "0xabc".into(),
                    transaction_count: 4,
                    reputation_score: 0.9,
                    verifier_metrics: VerifierMetricsSnapshot::default(),
                    ..Default::default()
                });

                let task = task::spawn_local(async move {
                    node.run().await.expect("run node");
                });

                let heartbeat = timeout(StdDuration::from_secs(5), async {
                    loop {
                        match events.recv().await {
                            Ok(NodeEvent::Heartbeat(hb)) => break hb,
                            Ok(_) => continue,
                            Err(err) => panic!("event channel closed: {err}"),
                        }
                    }
                })
                .await
                .expect("heartbeat event");
                assert_eq!(heartbeat.block_height, 12);
                assert_eq!(heartbeat.peer_count, 0);

                let meta = timeout(StdDuration::from_secs(5), async {
                    loop {
                        match events.recv().await {
                            Ok(NodeEvent::MetaTelemetry(report)) => break report,
                            Ok(_) => continue,
                            Err(err) => panic!("event channel closed: {err}"),
                        }
                    }
                })
                .await
                .expect("meta telemetry");
                assert_eq!(meta.peer_count, 0);

                handle.shutdown().await.expect("shutdown");
                let _ = task.await;
            })
            .await;

        provider.force_flush().expect("force flush metrics");
        let exported = exporter.get_finished_metrics().expect("export metrics");
        let mut seen = HashSet::new();
        for resource in exported {
            for scope in resource.scope_metrics {
                for metric in scope.metrics {
                    seen.insert(metric.name);
                }
            }
        }
        assert!(seen.contains("rpp.runtime.network.peer_count"));
    }

    async fn wait_for_peer_connected(events: &mut broadcast::Receiver<NodeEvent>) {
        timeout(StdDuration::from_secs(5), async {
            loop {
                match events.recv().await {
                    Ok(NodeEvent::PeerConnected { .. }) => break,
                    Ok(_) => continue,
                    Err(err) => panic!("event channel closed: {err}"),
                }
            }
        })
        .await
        .expect("peer connected");
    }
}
