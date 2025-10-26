//! Stateful runtime node coordinating consensus, storage, and external services.
//!
//! The [`Node`] type wraps the chain runtime, orchestrating mempool management,
//! block production, and proof generation. Invariants maintained here include:
//!
//! * The in-memory tip (`ChainTip`) always reflects the latest committed block
//!   stored in [`Storage`].
//! * VRF submissions are validated against the current epoch before they are
//!   admitted to consensus queues.
//! * Side-effectful subsystems (telemetry, gossip, prover tasks) are spawned and
//!   owned by [`NodeHandle`], which ensures graceful shutdown via the async
//!   join handles it tracks.
//!
//! Public status/reporting structs are defined alongside the runtime to expose
//! snapshot views without leaking internal locks.
use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::Keypair;
use malachite::Natural;
use parking_lot::{Mutex as ParkingMutex, RwLock};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{broadcast, mpsc, watch, Mutex, Notify};
use tokio::task::JoinHandle;
use tokio::time;
use tracing::field::display;
use tracing::instrument;
use tracing::Span;
use tracing::{debug, error, info, info_span, warn};
use tracing::Instrument;

use hex;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json;

use crate::config::{
    FeatureGates, GenesisAccount, NodeConfig, QueueWeightsConfig, ReleaseChannel, SecretsConfig,
};
use crate::consensus::{
    aggregate_total_stake, classify_participants, evaluate_vrf, BftVote, BftVoteKind,
    ConsensusCertificate, ConsensusRound, EvidenceKind, EvidencePool, EvidenceRecord,
    SignedBftVote, ValidatorCandidate,
};
use crate::crypto::{
    address_from_public_key, load_or_generate_keypair, sign_message, signature_to_hex,
    vrf_public_key_to_hex, VrfKeypair,
};
use crate::errors::{ChainError, ChainResult};
use crate::ledger::{
    EpochInfo, Ledger, ReputationAudit, SlashingEvent, SlashingReason, VrfHistoryRecord,
};
#[cfg(feature = "backend-plonky3")]
use crate::plonky3::circuit::transaction::TransactionWitness as Plonky3TransactionWitness;
use crate::proof_backend::{Blake2sHasher, ProofBytes};
#[cfg(feature = "prover-stwo")]
use crate::proof_backend::{
    ConsensusCircuitDef, PruningCircuitDef, RecursiveCircuitDef, StateCircuitDef, WitnessBytes,
    WitnessHeader,
};
use crate::proof_system::{ProofProver, ProofVerifierRegistry, VerifierMetricsSnapshot};
use crate::reputation::{Tier, TimetokeParams};
use crate::rpp::{
    GlobalStateCommitments, ModuleWitnessBundle, ProofArtifact, ProofModule, ProofSystemKind,
    TimetokeRecord,
};
use crate::runtime::node_runtime::{
    node::{
        IdentityProfile as RuntimeIdentityProfile, MetaTelemetryReport, NodeError as P2pError,
        NodeRuntimeConfig as P2pRuntimeConfig, TimetokeDeltaBroadcast,
    },
    NodeEvent, NodeHandle as P2pHandle, NodeInner as P2pRuntime, NodeMetrics as P2pMetrics,
};
use crate::runtime::sync::{
    state_sync_chunk_by_index as runtime_state_sync_chunk_by_index,
    stream_state_sync_chunks as runtime_stream_state_sync_chunks,
};
use crate::runtime::vrf_gossip::{submission_to_gossip, verify_submission};
use crate::runtime::{
    ProofVerificationBackend, ProofVerificationKind, ProofVerificationOutcome,
    ProofVerificationStage, RuntimeMetrics,
};
use crate::state::lifecycle::StateLifecycle;
use crate::state::merkle::compute_merkle_root;
use crate::storage::{StateTransitionReceipt, Storage};
use crate::stwo::circuit::transaction::TransactionWitness;
use crate::stwo::proof::ProofPayload;
#[cfg(feature = "prover-stwo")]
use crate::stwo::prover::WalletProver;
#[cfg(feature = "prover-stwo")]
use prover_stwo_backend::backend::{
    decode_consensus_proof, decode_pruning_proof, decode_recursive_proof, decode_state_proof,
    StwoBackend,
};
use crate::sync::{PayloadProvider, ReconstructionEngine, ReconstructionPlan, StateSyncPlan};
use crate::types::{
    Account, Address, AttestedIdentityRequest, Block, BlockHeader, BlockMetadata, BlockProofBundle,
    ChainProof, IdentityDeclaration, PruningEnvelopeMetadata, PruningProof, RecursiveProof,
    ReputationUpdate,
    SignedTransaction, Stake, TimetokeUpdate, TransactionProofBundle, UptimeProof,
    IDENTITY_ATTESTATION_GOSSIP_MIN, IDENTITY_ATTESTATION_QUORUM,
};
use crate::vrf::{
    self, PoseidonVrfInput, VrfEpochManager, VrfProof, VrfSubmission, VrfSubmissionPool,
};
#[cfg(feature = "backend-rpp-stark")]
use crate::zk::rpp_adapter::compute_public_digest;
#[cfg(feature = "backend-rpp-stark")]
use crate::zk::rpp_verifier::RppStarkVerificationReport;
use blake3::Hash;
use libp2p::PeerId;
use rpp_p2p::vendor::PeerId as NetworkPeerId;
use rpp_p2p::{
    AllowlistedPeer, GossipTopic, HandshakePayload, LightClientHead, NetworkLightClientUpdate,
    NetworkStateSyncChunk, NetworkStateSyncPlan, NodeIdentity, SnapshotChunk, SnapshotChunkStream,
    SnapshotStore, TierLevel, VRF_HANDSHAKE_CONTEXT,
};
use storage_firewood::pruning::PruningProof as FirewoodPruningProof;

const BASE_BLOCK_REWARD: u64 = 5;
const LEADER_BONUS_PERCENT: u8 = 20;
pub const DEFAULT_STATE_SYNC_CHUNK: usize = 16;
#[derive(Clone)]
struct ChainTip {
    height: u64,
    last_hash: [u8; 32],
    pruning: Option<PruningEnvelopeMetadata>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NodeStatus {
    pub address: Address,
    pub height: u64,
    pub last_hash: String,
    pub epoch: u64,
    pub epoch_nonce: String,
    pub pending_transactions: usize,
    pub pending_identities: usize,
    pub pending_votes: usize,
    pub pending_uptime_proofs: usize,
    pub vrf_metrics: crate::vrf::VrfSelectionMetrics,
    pub tip: Option<BlockMetadata>,
}

#[derive(Clone, Debug, Serialize)]
pub struct P2pCensorshipEntry {
    pub peer: String,
    pub vote_timeouts: u64,
    pub proof_relay_misses: u64,
    pub gossip_backpressure_events: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct P2pCensorshipReport {
    pub entries: Vec<P2pCensorshipEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingTransactionSummary {
    pub hash: String,
    pub from: Address,
    pub to: Address,
    pub amount: u128,
    pub fee: u64,
    pub nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<ChainProof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<TransactionWitness>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_payload: Option<ProofPayload>,
    #[cfg(feature = "backend-rpp-stark")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_inputs_digest: Option<String>,
}

#[derive(Clone, Debug)]
struct PendingTransactionMetadata {
    proof: ChainProof,
    witness: Option<TransactionWitness>,
    proof_payload: Option<ProofPayload>,
    #[cfg(feature = "backend-rpp-stark")]
    public_inputs_digest: Option<String>,
}

impl PendingTransactionMetadata {
    fn from_bundle(bundle: &TransactionProofBundle) -> Self {
        let witness = bundle.witness.clone().or_else(|| {
            bundle
                .proof_payload
                .as_ref()
                .and_then(Self::transaction_witness)
        });
        let proof_payload = bundle
            .proof_payload
            .clone()
            .or_else(|| Self::clone_payload(&bundle.proof));
        #[cfg(feature = "backend-rpp-stark")]
        let public_inputs_digest = match &bundle.proof {
            ChainProof::RppStark(proof) => {
                Some(compute_public_digest(proof.public_inputs()).to_hex())
            }
            _ => None,
        };
        Self {
            proof: bundle.proof.clone(),
            witness,
            proof_payload,
            #[cfg(feature = "backend-rpp-stark")]
            public_inputs_digest,
        }
    }

    fn transaction_witness(payload: &ProofPayload) -> Option<TransactionWitness> {
        match payload {
            ProofPayload::Transaction(witness) => Some(witness.clone()),
            _ => None,
        }
    }

    fn clone_payload(proof: &ChainProof) -> Option<ProofPayload> {
        match proof {
            ChainProof::Stwo(stark) => Some(stark.payload.clone()),
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => None,
            #[cfg(feature = "backend-rpp-stark")]
            ChainProof::RppStark(_) => None,
        }
    }
}

fn wallet_rpc_flow_span(method: &'static str, wallet: &Address, hash: &str) -> Span {
    info_span!(
        "runtime.wallet.rpc",
        method,
        wallet = %wallet,
        tx_hash = %hash
    )
}

fn proof_operation_span(
    operation: &'static str,
    backend: ProofSystemKind,
    height: Option<u64>,
    block_hash: Option<&str>,
) -> Span {
    let span = info_span!(
        "runtime.proof.operation",
        operation,
        backend = ?backend,
        height = tracing::field::Empty,
        block_hash = tracing::field::Empty
    );
    if let Some(height) = height {
        span.record("height", &height);
    }
    if let Some(block_hash) = block_hash {
        span.record("block_hash", &display(block_hash));
    }
    span
}

fn storage_flush_span(operation: &'static str, height: u64, block_hash: &str) -> Span {
    info_span!(
        "runtime.storage.flush",
        operation,
        height,
        block_hash = %block_hash
    )
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingIdentitySummary {
    pub wallet_addr: Address,
    pub commitment: String,
    pub epoch_nonce: String,
    pub state_root: String,
    pub identity_root: String,
    pub vrf_tag: String,
    pub attested_votes: usize,
    pub gossip_confirmations: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingVoteSummary {
    pub hash: String,
    pub voter: Address,
    pub height: u64,
    pub round: u64,
    pub block_hash: String,
    pub kind: BftVoteKind,
}

#[derive(Clone, Debug, Serialize)]
pub struct MempoolStatus {
    pub transactions: Vec<PendingTransactionSummary>,
    pub identities: Vec<PendingIdentitySummary>,
    pub votes: Vec<PendingVoteSummary>,
    pub uptime_proofs: Vec<PendingUptimeSummary>,
    pub queue_weights: QueueWeightsConfig,
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingUptimeSummary {
    pub identity: Address,
    pub window_start: u64,
    pub window_end: u64,
    pub credited_hours: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConsensusStatus {
    pub height: u64,
    pub block_hash: Option<String>,
    pub proposer: Option<Address>,
    pub round: u64,
    pub total_power: String,
    pub quorum_threshold: String,
    pub pre_vote_power: String,
    pub pre_commit_power: String,
    pub commit_power: String,
    pub quorum_reached: bool,
    pub observers: u64,
    pub epoch: u64,
    pub epoch_nonce: String,
    pub pending_votes: usize,
    pub round_latencies_ms: Vec<u64>,
    pub leader_changes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quorum_latency_ms: Option<u64>,
    pub witness_events: u64,
    pub slashing_events: u64,
    pub failed_votes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct VrfStatus {
    pub address: Address,
    pub epoch: u64,
    pub epoch_nonce: String,
    pub public_key: String,
    pub proof: crate::vrf::VrfProof,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct VrfThresholdStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<String>,
    pub committee_target: usize,
    pub pool_entries: usize,
    pub accepted_validators: usize,
    pub participation_rate: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatorMembershipEntry {
    pub address: Address,
    pub stake: Stake,
    pub reputation_score: f64,
    pub tier: Tier,
    pub timetoke_hours: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ObserverMembershipEntry {
    pub address: Address,
    pub tier: Tier,
}

#[derive(Clone, Debug, Serialize)]
pub struct BftMembership {
    pub height: u64,
    pub epoch: u64,
    pub epoch_nonce: String,
    pub validators: Vec<ValidatorMembershipEntry>,
    pub observers: Vec<ObserverMembershipEntry>,
}

#[derive(Clone, Debug, Serialize)]
pub struct BlockProofArtifactsView {
    pub hash: String,
    pub height: u64,
    pub pruning_proof: PruningProof,
    pub recursive_proof: RecursiveProof,
    pub stark: BlockProofBundle,
    pub module_witnesses: ModuleWitnessBundle,
    pub proof_artifacts: Vec<ProofArtifact>,
    pub consensus_proof: Option<ChainProof>,
    pub pruned: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct TelemetryRuntimeStatus {
    pub enabled: bool,
    pub endpoint: Option<String>,
    pub sample_interval_secs: u64,
    pub last_observed_height: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RolloutStatus {
    pub release_channel: ReleaseChannel,
    pub feature_gates: FeatureGates,
    pub telemetry: TelemetryRuntimeStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PruningJobStatus {
    pub plan: StateSyncPlan,
    pub missing_heights: Vec<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persisted_path: Option<String>,
    pub stored_proofs: Vec<u64>,
    pub last_updated: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatorTelemetryView {
    pub rollout: RolloutStatus,
    pub node: NodeStatus,
    pub consensus: ValidatorConsensusTelemetry,
    pub mempool: ValidatorMempoolTelemetry,
    pub timetoke_params: TimetokeParams,
    pub verifier_metrics: VerifierMetricsSnapshot,
    pub pruning: Option<PruningJobStatus>,
    pub vrf_threshold: VrfThresholdStatus,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatorConsensusTelemetry {
    pub height: u64,
    pub round: u64,
    pub pending_votes: usize,
    pub quorum_reached: bool,
    pub leader_changes: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub round_latencies_ms: Vec<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quorum_latency_ms: Option<u64>,
    pub witness_events: u64,
    pub slashing_events: u64,
    pub failed_votes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ValidatorMempoolTelemetry {
    pub transactions: usize,
    pub identities: usize,
    pub votes: usize,
    pub uptime_proofs: usize,
}

impl From<ConsensusStatus> for ValidatorConsensusTelemetry {
    fn from(status: ConsensusStatus) -> Self {
        Self {
            height: status.height,
            round: status.round,
            pending_votes: status.pending_votes,
            quorum_reached: status.quorum_reached,
            leader_changes: status.leader_changes,
            round_latencies_ms: status.round_latencies_ms,
            quorum_latency_ms: status.quorum_latency_ms,
            witness_events: status.witness_events,
            slashing_events: status.slashing_events,
            failed_votes: status.failed_votes,
        }
    }
}

impl From<&NodeStatus> for ValidatorMempoolTelemetry {
    fn from(status: &NodeStatus) -> Self {
        Self {
            transactions: status.pending_transactions,
            identities: status.pending_identities,
            votes: status.pending_votes,
            uptime_proofs: status.pending_uptime_proofs,
        }
    }
}

#[derive(Clone, Debug)]
pub enum PipelineObservation {
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
        pruning_proof: Option<FirewoodPruningProof>,
    },
}

const MAX_ROUND_LATENCY_SAMPLES: usize = 32;

#[derive(Clone, Debug, Default, Serialize)]
pub struct ConsensusTelemetrySnapshot {
    pub round_latencies_ms: Vec<u64>,
    pub leader_changes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quorum_latency_ms: Option<u64>,
    pub witness_events: u64,
    pub slashing_events: u64,
    pub failed_votes: u64,
}

#[derive(Default)]
struct ConsensusTelemetryState {
    round_latencies_ms: VecDeque<u64>,
    last_round_started: Option<Instant>,
    last_round_height: Option<u64>,
    last_round_number: Option<u64>,
    leader_changes: u64,
    last_leader: Option<Address>,
    quorum_latency_ms: Option<u64>,
    witness_events: u64,
    slashing_events: u64,
    failed_votes: u64,
}

pub struct ConsensusTelemetry {
    state: ParkingMutex<ConsensusTelemetryState>,
    metrics: Arc<RuntimeMetrics>,
}

impl ConsensusTelemetry {
    pub fn new(metrics: Arc<RuntimeMetrics>) -> Self {
        Self {
            state: ParkingMutex::new(ConsensusTelemetryState::default()),
            metrics,
        }
    }

    pub fn record_round_start(&self, height: u64, round: u64, leader: &Address) {
        let mut state = self.state.lock();
        let leader_changed = state
            .last_leader
            .as_ref()
            .map(|previous| previous != leader)
            .unwrap_or(true);
        if leader_changed {
            state.leader_changes = state.leader_changes.saturating_add(1);
        }
        state.last_leader = Some(leader.clone());
        state.last_round_started = Some(Instant::now());
        state.last_round_height = Some(height);
        state.last_round_number = Some(round);
        state.quorum_latency_ms = None;
        drop(state);

        if leader_changed {
            self.metrics
                .record_consensus_leader_change(height, round, leader.clone());
        }
    }

    pub fn record_quorum(&self, height: u64, round: u64) {
        let mut state = self.state.lock();
        if state.last_round_height == Some(height) && state.last_round_number == Some(round) {
            let latency_ms = state
                .last_round_started
                .map(|started| started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
            state.quorum_latency_ms = latency_ms;
            drop(state);
            if let Some(latency_ms) = latency_ms {
                self.metrics.record_consensus_quorum_latency(
                    height,
                    round,
                    Duration::from_millis(latency_ms),
                );
            }
        }
    }

    pub fn record_round_end(&self, height: u64, round: u64) {
        let mut state = self.state.lock();
        if state.last_round_height == Some(height) && state.last_round_number == Some(round) {
            if let Some(started) = state.last_round_started.take() {
                let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
                if state.round_latencies_ms.len() >= MAX_ROUND_LATENCY_SAMPLES {
                    state.round_latencies_ms.pop_front();
                }
                state.round_latencies_ms.push_back(duration_ms);
                drop(state);
                self.metrics.record_consensus_round_duration(
                    height,
                    round,
                    Duration::from_millis(duration_ms),
                );
                return;
            }
        }
    }

    pub fn record_witness_event<S: Into<String>>(&self, topic: S) {
        let mut state = self.state.lock();
        state.witness_events = state.witness_events.saturating_add(1);
        drop(state);
        self.metrics.record_consensus_witness_event(topic.into());
    }

    pub fn record_slashing<S: Into<String>>(&self, reason: S) {
        let mut state = self.state.lock();
        state.slashing_events = state.slashing_events.saturating_add(1);
        drop(state);
        self.metrics.record_consensus_slashing_event(reason.into());
    }

    pub fn record_failed_vote<S: Into<String>>(&self, reason: S) {
        let mut state = self.state.lock();
        state.failed_votes = state.failed_votes.saturating_add(1);
        drop(state);
        self.metrics.record_consensus_failed_vote(reason.into());
    }

    pub fn snapshot(&self) -> ConsensusTelemetrySnapshot {
        let state = self.state.lock();
        ConsensusTelemetrySnapshot {
            round_latencies_ms: state.round_latencies_ms.iter().copied().collect(),
            leader_changes: state.leader_changes,
            quorum_latency_ms: state.quorum_latency_ms,
            witness_events: state.witness_events,
            slashing_events: state.slashing_events,
            failed_votes: state.failed_votes,
        }
    }
}

struct WitnessChannels {
    blocks: broadcast::Sender<Vec<u8>>,
    votes: broadcast::Sender<Vec<u8>>,
    proofs: broadcast::Sender<Vec<u8>>,
    snapshots: broadcast::Sender<Vec<u8>>,
    meta: broadcast::Sender<Vec<u8>>,
    publisher: ParkingMutex<Option<mpsc::Sender<(GossipTopic, Vec<u8>)>>>,
    backpressure_hook: ParkingMutex<Option<Arc<dyn Fn(GossipTopic, usize) + Send + Sync>>>,
    queue_capacity: usize,
}

impl WitnessChannels {
    fn new(capacity: usize) -> Self {
        let (blocks, _) = broadcast::channel(capacity);
        let (votes, _) = broadcast::channel(capacity);
        let (proofs, _) = broadcast::channel(capacity);
        let (snapshots, _) = broadcast::channel(capacity);
        let (meta, _) = broadcast::channel(capacity);
        Self {
            blocks,
            votes,
            proofs,
            snapshots,
            meta,
            publisher: ParkingMutex::new(None),
            backpressure_hook: ParkingMutex::new(None),
            queue_capacity: capacity,
        }
    }

    fn attach_publisher(&self, publisher: mpsc::Sender<(GossipTopic, Vec<u8>)>) {
        *self.publisher.lock() = Some(publisher);
    }

    fn set_backpressure_hook(&self, hook: Arc<dyn Fn(GossipTopic, usize) + Send + Sync>) {
        *self.backpressure_hook.lock() = Some(hook);
    }

    fn publish_local(&self, topic: GossipTopic, payload: Vec<u8>) {
        self.forward_to_network(topic.clone(), payload.clone());
        self.fanout_local(topic, payload);
    }

    fn ingest_remote(&self, topic: GossipTopic, payload: Vec<u8>) {
        self.fanout_local(topic, payload);
    }

    fn subscribe(&self, topic: GossipTopic) -> broadcast::Receiver<Vec<u8>> {
        match topic {
            GossipTopic::Blocks => self.blocks.subscribe(),
            GossipTopic::Votes => self.votes.subscribe(),
            GossipTopic::Proofs | GossipTopic::WitnessProofs => self.proofs.subscribe(),
            GossipTopic::Snapshots => self.snapshots.subscribe(),
            GossipTopic::Meta | GossipTopic::WitnessMeta => self.meta.subscribe(),
        }
    }

    fn forward_to_network(&self, topic: GossipTopic, payload: Vec<u8>) {
        if let Some(sender) = self.publisher.lock().as_ref() {
            match sender.try_send((topic.clone(), payload)) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    warn!(
                        ?topic,
                        queue_depth = self.queue_capacity,
                        "failed to enqueue witness gossip for publishing"
                    );
                    if let Some(callback) = self.backpressure_hook.lock().as_ref() {
                        callback(topic, self.queue_capacity);
                    }
                }
                Err(TrySendError::Closed(_)) => {
                    warn!(
                        ?topic,
                        "failed to enqueue witness gossip for publishing: channel closed"
                    );
                }
            }
        }
    }

    fn fanout_local(&self, topic: GossipTopic, payload: Vec<u8>) {
        let sender = match topic {
            GossipTopic::Blocks => &self.blocks,
            GossipTopic::Votes => &self.votes,
            GossipTopic::Proofs | GossipTopic::WitnessProofs => &self.proofs,
            GossipTopic::Snapshots => &self.snapshots,
            GossipTopic::Meta | GossipTopic::WitnessMeta => &self.meta,
        };
        let _ = sender.send(payload);
    }
}

pub struct Node {
    inner: Arc<NodeInner>,
}

pub(crate) struct NodeInner {
    config: NodeConfig,
    mempool_limit: AtomicUsize,
    queue_weights: RwLock<QueueWeightsConfig>,
    keypair: Keypair,
    vrf_keypair: VrfKeypair,
    p2p_identity: Arc<NodeIdentity>,
    address: Address,
    storage: Storage,
    ledger: Ledger,
    mempool: RwLock<VecDeque<TransactionProofBundle>>,
    pending_transaction_metadata: RwLock<HashMap<String, PendingTransactionMetadata>>,
    identity_mempool: RwLock<VecDeque<AttestedIdentityRequest>>,
    uptime_mempool: RwLock<VecDeque<RecordedUptimeProof>>,
    vrf_mempool: RwLock<VrfSubmissionPool>,
    vrf_epoch: RwLock<VrfEpochManager>,
    chain_tip: RwLock<ChainTip>,
    block_interval: Duration,
    vote_mempool: RwLock<VecDeque<SignedBftVote>>,
    proposal_inbox: RwLock<HashMap<(u64, Address), VerifiedProposal>>,
    consensus_rounds: RwLock<HashMap<u64, u64>>,
    evidence_pool: RwLock<EvidencePool>,
    pruning_status: RwLock<Option<PruningJobStatus>>,
    vrf_metrics: RwLock<crate::vrf::VrfSelectionMetrics>,
    vrf_threshold: RwLock<VrfThresholdStatus>,
    verifiers: ProofVerifierRegistry,
    shutdown: broadcast::Sender<()>,
    pipeline_events: broadcast::Sender<PipelineObservation>,
    worker_tasks: Mutex<Vec<JoinHandle<()>>>,
    completion: Notify,
    witness_channels: WitnessChannels,
    p2p_runtime: ParkingMutex<Option<P2pHandle>>,
    consensus_telemetry: Arc<ConsensusTelemetry>,
    audit_exporter: AuditExporter,
    runtime_metrics: Arc<RuntimeMetrics>,
}

#[cfg_attr(not(feature = "prover-stwo"), allow(dead_code))]
struct LocalProofArtifacts {
    bundle: BlockProofBundle,
    consensus_proof: Option<ChainProof>,
    module_witnesses: ModuleWitnessBundle,
    proof_artifacts: Vec<ProofArtifact>,
}

enum FinalizationContext {
    Local(LocalFinalizationContext),
    #[allow(dead_code)]
    External(ExternalFinalizationContext),
}

struct LocalFinalizationContext {
    round: ConsensusRound,
    block_hash: String,
    header: BlockHeader,
    parent_height: u64,
    commitments: GlobalStateCommitments,
    accepted_identities: Vec<AttestedIdentityRequest>,
    transactions: Vec<SignedTransaction>,
    transaction_proofs: Vec<ChainProof>,
    identity_proofs: Vec<ChainProof>,
    uptime_proofs: Vec<UptimeProof>,
    timetoke_updates: Vec<TimetokeUpdate>,
    reputation_updates: Vec<ReputationUpdate>,
    recorded_votes: Vec<SignedBftVote>,
}

#[allow(dead_code)]
pub struct ExternalFinalizationContext {
    round: ConsensusRound,
    block: Block,
    previous_block: Option<Block>,
    archived_votes: Vec<SignedBftVote>,
}

pub enum FinalizationOutcome {
    Sealed { block: Block, tip_height: u64 },
    AwaitingQuorum,
}

#[derive(Clone)]
pub struct NodeHandle {
    inner: Arc<NodeInner>,
}

#[derive(Clone)]
struct RecordedUptimeProof {
    proof: UptimeProof,
    credited_hours: u64,
}

#[derive(Clone)]
struct VerifiedProposal {
    block: Block,
}

#[derive(Clone, Debug)]
pub struct NetworkIdentityProfile {
    pub zsi_id: String,
    pub tier: TierLevel,
    pub vrf_public_key: Vec<u8>,
    pub vrf_proof: Vec<u8>,
    pub feature_gates: FeatureGates,
}

struct AuditExporter {
    reputation: AuditStream,
    slashing: AuditStream,
}

impl AuditExporter {
    fn new(base_dir: &Path) -> ChainResult<Self> {
        fs::create_dir_all(base_dir)?;
        let reputation = AuditStream::new(base_dir.join("reputation"), "reputation")?;
        let slashing = AuditStream::new(base_dir.join("slashing"), "slashing")?;
        Ok(Self {
            reputation,
            slashing,
        })
    }

    fn export_reputation(&self, audit: &ReputationAudit) -> ChainResult<()> {
        self.reputation.append(audit)
    }

    fn export_slashing(&self, event: &SlashingEvent) -> ChainResult<()> {
        self.slashing.append(event)
    }

    fn recent_reputation(&self, limit: usize) -> ChainResult<Vec<ReputationAudit>> {
        self.reputation.tail(limit)
    }

    fn recent_slashing(&self, limit: usize) -> ChainResult<Vec<SlashingEvent>> {
        self.slashing.tail(limit)
    }
}

struct AuditStream {
    directory: PathBuf,
    prefix: &'static str,
    rotation: Duration,
    retention: usize,
    state: ParkingMutex<Option<ActiveAuditFile>>,
}

impl AuditStream {
    fn new(directory: PathBuf, prefix: &'static str) -> ChainResult<Self> {
        fs::create_dir_all(&directory)?;
        Ok(Self {
            directory,
            prefix,
            rotation: Duration::from_secs(24 * 60 * 60),
            retention: 30,
            state: ParkingMutex::new(None),
        })
    }

    fn append<T: Serialize>(&self, record: &T) -> ChainResult<()> {
        let now = SystemTime::now();
        let mut guard = self.state.lock();
        let file = self.ensure_file(now, &mut guard)?;
        serde_json::to_writer(&mut file.writer, record)
            .map_err(|err| ChainError::Config(format!("failed to encode audit record: {err}")))?;
        file.writer.write_all(b"\n")?;
        file.writer.flush()?;
        Ok(())
    }

    fn tail<T>(&self, limit: usize) -> ChainResult<Vec<T>>
    where
        T: DeserializeOwned,
    {
        if limit == 0 {
            return Ok(Vec::new());
        }
        if let Some(state) = self.state.lock().as_mut() {
            state.writer.flush()?;
        }
        let mut entries = fs::read_dir(&self.directory)?
            .filter_map(|entry| match entry {
                Ok(entry) if entry.path().is_file() => Some(entry.path()),
                _ => None,
            })
            .collect::<Vec<_>>();
        entries.sort();
        let mut tail = std::collections::VecDeque::with_capacity(limit);
        for path in entries {
            let file = File::open(&path)?;
            let reader = BufReader::new(file);
            for line in reader.lines() {
                let line = line?;
                let record: T = serde_json::from_str(&line).map_err(|err| {
                    ChainError::Config(format!(
                        "failed to decode audit record from {}: {err}",
                        path.display()
                    ))
                })?;
                if tail.len() == limit {
                    tail.pop_front();
                }
                tail.push_back(record);
            }
        }
        Ok(tail.into_iter().collect())
    }

    fn ensure_file<'a>(
        &self,
        now: SystemTime,
        state: &'a mut Option<ActiveAuditFile>,
    ) -> ChainResult<&'a mut ActiveAuditFile> {
        let rotate = match state {
            Some(current) => {
                now.duration_since(current.opened_at).unwrap_or_default() >= self.rotation
            }
            None => true,
        };
        if rotate {
            *state = Some(self.open_file(now)?);
            self.prune_old_files()?;
        }
        Ok(state.as_mut().expect("audit file initialized"))
    }

    fn open_file(&self, now: SystemTime) -> ChainResult<ActiveAuditFile> {
        let timestamp = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let path = self
            .directory
            .join(format!("{}-{}.jsonl", self.prefix, timestamp));
        let file = File::create(&path)?;
        Ok(ActiveAuditFile {
            opened_at: now,
            writer: BufWriter::new(file),
            path,
        })
    }

    fn prune_old_files(&self) -> ChainResult<()> {
        let mut entries = fs::read_dir(&self.directory)?
            .filter_map(|entry| match entry {
                Ok(entry) if entry.path().is_file() => Some(entry.path()),
                _ => None,
            })
            .collect::<Vec<_>>();
        entries.sort();
        while entries.len() > self.retention {
            if let Some(path) = entries.first().cloned() {
                if let Err(err) = fs::remove_file(&path) {
                    warn!(?err, ?path, "failed to prune audit file");
                }
                entries.remove(0);
            } else {
                break;
            }
        }
        Ok(())
    }
}

struct ActiveAuditFile {
    opened_at: SystemTime,
    writer: BufWriter<File>,
    path: PathBuf,
}

impl Node {
    pub fn new(config: NodeConfig, runtime_metrics: Arc<RuntimeMetrics>) -> ChainResult<Self> {
        config.validate()?;
        config.ensure_directories()?;
        let keypair = load_or_generate_keypair(&config.key_path)?;
        let vrf_keypair = config.load_or_generate_vrf_keypair()?;
        let p2p_identity = Arc::new(
            NodeIdentity::load_or_generate(&config.p2p_key_path)
                .map_err(|err| ChainError::Config(format!("unable to load p2p identity: {err}")))?,
        );
        let address = address_from_public_key(&keypair.public);
        let reputation_params = config.reputation_params();
        let db_path = config.data_dir.join("db");
        let storage = Storage::open(&db_path)?;
        let mut accounts = storage.load_accounts()?;
        let mut tip_metadata = storage.tip()?;
        let verifier_registry =
            ProofVerifierRegistry::with_max_proof_size_bytes(config.max_proof_size_bytes)?;
        if tip_metadata.is_none() {
            let genesis_accounts = if config.genesis.accounts.is_empty() {
                vec![GenesisAccount {
                    address: address.clone(),
                    balance: 1_000_000_000,
                    stake: "1000".to_string(),
                }]
            } else {
                config.genesis.accounts.clone()
            };
            accounts = build_genesis_accounts(genesis_accounts)?;
            for account in &accounts {
                storage.persist_account(account)?;
            }
            let utxo_snapshot = storage.load_utxo_snapshot()?.unwrap_or_default();
            let mut ledger = Ledger::load(accounts.clone(), utxo_snapshot, config.epoch_length);
            ledger.set_reputation_params(reputation_params.clone());
            ledger.set_timetoke_params(config.timetoke_params());
            ledger.configure_reward_pools(
                config.malachite.rewards.treasury_accounts(),
                config.malachite.rewards.witness_pool_weights(),
            );
            let mut tx_hashes: Vec<[u8; 32]> = Vec::new();
            let tx_root = compute_merkle_root(&mut tx_hashes);
            let commitments = ledger.global_commitments();
            let state_root_hex = hex::encode(commitments.global_state_root);
            let stakes = ledger.stake_snapshot();
            let total_stake = aggregate_total_stake(&stakes);
            let genesis_seed = [0u8; 32];
            let vrf = evaluate_vrf(&genesis_seed, 0, &address, 0, Some(&vrf_keypair.secret))?;
            let header = BlockHeader::new(
                0,
                hex::encode([0u8; 32]),
                hex::encode(tx_root),
                state_root_hex.clone(),
                hex::encode(commitments.utxo_root),
                hex::encode(commitments.reputation_root),
                hex::encode(commitments.timetoke_root),
                hex::encode(commitments.zsi_root),
                hex::encode(commitments.proof_root),
                total_stake.to_string(),
                vrf.randomness.to_string(),
                vrf_public_key_to_hex(&vrf_keypair.public),
                vrf.preoutput.clone(),
                vrf.proof.clone(),
                address.clone(),
                Tier::Tl5.to_string(),
                0,
            );
            let pruning_proof = PruningProof::from_previous(None, &header);
            let transactions: Vec<SignedTransaction> = Vec::new();
            let transaction_proofs: Vec<ChainProof> = Vec::new();
            let identity_proofs: Vec<ChainProof> = Vec::new();
            let LocalProofArtifacts {
                bundle: stark_bundle,
                consensus_proof,
                module_witnesses,
                mut proof_artifacts,
            } = NodeInner::generate_local_block_proofs(
                &storage,
                &ledger,
                &header,
                &commitments,
                &pruning_proof,
                &[],
                &transactions,
                transaction_proofs,
                &identity_proofs,
                &[],
                None,
                None,
                config.max_proof_size_bytes,
            )?;
            debug_assert!(
                consensus_proof.is_none(),
                "genesis consensus proof should not be generated",
            );
            #[cfg(feature = "backend-rpp-stark")]
            if let Err(err) = verifier_registry.verify_rpp_stark_block_bundle(&stark_bundle) {
                error!(?err, "genesis block bundle rejected by RPP-STARK verifier");
                return Err(err);
            }
            let recursive_proof =
                RecursiveProof::genesis(&header, &pruning_proof, &stark_bundle.recursive_proof)?;
            let signature = sign_message(&keypair, &header.canonical_bytes());
            let consensus_certificate = ConsensusCertificate::genesis();
            let genesis_block = Block::new(
                header,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                module_witnesses,
                proof_artifacts,
                pruning_proof,
                recursive_proof,
                stark_bundle,
                signature,
                consensus_certificate,
                None,
            );
            genesis_block.verify(None, &keypair.public)?;
            let genesis_metadata = BlockMetadata::from(&genesis_block);
            storage.store_block(&genesis_block, &genesis_metadata)?;
            tip_metadata = Some(genesis_metadata);
        }

        if accounts.is_empty() {
            accounts = storage.load_accounts()?;
        }

        let utxo_snapshot = storage.load_utxo_snapshot()?.unwrap_or_default();
        let mut ledger = Ledger::load(accounts, utxo_snapshot, config.epoch_length);
        ledger.set_reputation_params(reputation_params);
        ledger.set_timetoke_params(config.timetoke_params());
        ledger.configure_reward_pools(
            config.malachite.rewards.treasury_accounts(),
            config.malachite.rewards.witness_pool_weights(),
        );

        let node_pk_hex = hex::encode(keypair.public.to_bytes());
        if ledger.get_account(&address).is_none() {
            let mut account = Account::new(address.clone(), 0, Stake::default());
            let _ = account.ensure_wallet_binding(&node_pk_hex)?;
            ledger.upsert_account(account)?;
        }
        ledger.ensure_node_binding(&address, &node_pk_hex)?;

        let next_height = tip_metadata
            .as_ref()
            .map(|meta| meta.height.saturating_add(1))
            .unwrap_or(0);
        ledger.sync_epoch_for_height(next_height);
        let epoch_manager = VrfEpochManager::new(config.epoch_length, ledger.current_epoch());

        let (shutdown, _shutdown_rx) = broadcast::channel(1);
        let (pipeline_events, _) = broadcast::channel(256);
        let mempool_limit = config.mempool_limit;
        let queue_weights = config.queue_weights.clone();
        let consensus_telemetry = Arc::new(ConsensusTelemetry::new(runtime_metrics.clone()));
        let audit_exporter = AuditExporter::new(&config.data_dir.join("audits"))?;
        let inner = Arc::new(NodeInner {
            block_interval: Duration::from_millis(config.block_time_ms),
            config,
            mempool_limit: AtomicUsize::new(mempool_limit),
            queue_weights: RwLock::new(queue_weights),
            keypair,
            vrf_keypair,
            p2p_identity,
            address,
            storage,
            ledger,
            mempool: RwLock::new(VecDeque::new()),
            pending_transaction_metadata: RwLock::new(HashMap::new()),
            identity_mempool: RwLock::new(VecDeque::new()),
            uptime_mempool: RwLock::new(VecDeque::new()),
            vrf_mempool: RwLock::new(VrfSubmissionPool::new()),
            vrf_epoch: RwLock::new(epoch_manager),
            chain_tip: RwLock::new(ChainTip {
                height: 0,
                last_hash: [0u8; 32],
                pruning: None,
            }),
            vote_mempool: RwLock::new(VecDeque::new()),
            proposal_inbox: RwLock::new(HashMap::new()),
            consensus_rounds: RwLock::new(HashMap::new()),
            evidence_pool: RwLock::new(EvidencePool::default()),
            pruning_status: RwLock::new(None),
            vrf_metrics: RwLock::new(crate::vrf::VrfSelectionMetrics::default()),
            vrf_threshold: RwLock::new(VrfThresholdStatus::default()),
            verifiers: verifier_registry,
            shutdown,
            pipeline_events,
            worker_tasks: Mutex::new(Vec::new()),
            completion: Notify::new(),
            witness_channels: WitnessChannels::new(128),
            p2p_runtime: ParkingMutex::new(None),
            consensus_telemetry,
            audit_exporter,
            runtime_metrics: runtime_metrics.clone(),
        });
        {
            let weak_inner = Arc::downgrade(&inner);
            inner
                .witness_channels
                .set_backpressure_hook(Arc::new(move |topic, queue_depth| {
                    if let Some(inner) = weak_inner.upgrade() {
                        if let Some(runtime) = inner.p2p_runtime.lock().clone() {
                            let topic_clone = topic.clone();
                            let span = info_span!(
                                "runtime.gossip.backpressure",
                                topic = %topic_clone,
                                queue_depth
                            );
                            tokio::spawn(async move {
                                if let Err(err) = runtime
                                    .report_gossip_backpressure(topic_clone.clone(), queue_depth)
                                    .await
                                {
                                    warn!(
                                        target: "node",
                                        ?topic_clone,
                                        queue_depth,
                                        ?err,
                                        "failed to report gossip backpressure"
                                    );
                                }
                            }
                            .instrument(span));
                        }
                    }
                }));
        }
        debug!(peer_id = %inner.p2p_identity.peer_id(), "libp2p identity initialised");
        inner.bootstrap()?;
        Ok(Self { inner })
    }

    pub fn handle(&self) -> NodeHandle {
        NodeHandle {
            inner: self.inner.clone(),
        }
    }

    pub fn runtime_metrics(&self) -> Arc<RuntimeMetrics> {
        self.inner.runtime_metrics.clone()
    }

    pub fn subscribe_witness_gossip(&self, topic: GossipTopic) -> broadcast::Receiver<Vec<u8>> {
        self.inner.subscribe_witness_gossip(topic)
    }

    pub fn p2p_handle(&self) -> Option<P2pHandle> {
        self.inner.p2p_handle()
    }

    pub async fn start(self) -> ChainResult<()> {
        let inner = self.inner;
        let join = inner.spawn_runtime();
        let result = join
            .await
            .map_err(|err| ChainError::Config(format!("node runtime join error: {err}")));
        result
    }

    pub fn network_identity_profile(&self) -> ChainResult<NetworkIdentityProfile> {
        self.inner.network_identity_profile()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{GenesisAccount, NodeConfig};
    use crate::consensus::{
        classify_participants, evaluate_vrf, BftVote, BftVoteKind, ConsensusRound, SignedBftVote,
    };
    use crate::crypto::{
        address_from_public_key, generate_vrf_keypair, load_or_generate_keypair,
        vrf_public_key_from_hex, vrf_public_key_to_hex,
    };
    use crate::errors::ChainError;
    use crate::ledger::Ledger;
    use crate::proof_backend::Blake2sHasher;
    use crate::reputation::Tier;
    use crate::stwo::circuit::{
        identity::{IdentityCircuit, IdentityWitness},
        string_to_field, StarkCircuit,
    };
    use crate::stwo::fri::FriProver;
    use crate::stwo::params::StarkParameters;
    use crate::stwo::proof::{
        CommitmentSchemeProofData, FriProof, ProofKind, ProofPayload, StarkProof,
    };
    #[cfg(feature = "backend-rpp-stark")]
    use crate::types::RppStarkProof;
    use crate::types::{ChainProof, IdentityDeclaration, IdentityGenesis, IdentityProof};
    use crate::vrf::{self, PoseidonVrfInput, VrfProof, VrfSubmission, VrfSubmissionPool};
    use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signer};
    use malachite::Natural;
    use tempfile::tempdir;
    use std::sync::{Arc, Mutex};

    use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
    use tracing_subscriber::registry::LookupSpan;
    use tracing_subscriber::Registry;
    use tracing_test::traced_test;

    #[derive(Clone, Default)]
    struct RecordingLayer {
        spans: Arc<Mutex<Vec<String>>>,
    }

    impl RecordingLayer {
        fn names(&self) -> Vec<String> {
            self.spans.lock().expect("record spans").clone()
        }
    }

    impl<S> Layer<S> for RecordingLayer
    where
        S: tracing::Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::Id,
            _ctx: Context<'_, S>,
        ) {
            self.spans
                .lock()
                .expect("record span name")
                .push(attrs.metadata().name().to_string());
        }
    }

    #[test]
    fn wallet_flow_span_emits_runtime_span() {
        let recorder = RecordingLayer::default();
        let subscriber = Registry::default().with(recorder.clone());
        tracing::subscriber::with_default(subscriber, || {
            let address: Address = "wallet-span".into();
            let span = wallet_rpc_flow_span("submit", &address, "hash-span");
            let _guard = span.enter();
            info!("within wallet span");
        });
        assert!(recorder
            .names()
            .iter()
            .any(|name| name == "runtime.wallet.rpc"));
    }

    #[test]
    fn proof_operation_span_emits_runtime_span() {
        let recorder = RecordingLayer::default();
        let subscriber = Registry::default().with(recorder.clone());
        tracing::subscriber::with_default(subscriber, || {
            let span = proof_operation_span(
                "prove_state",
                ProofSystemKind::Stwo,
                Some(42),
                Some("block-hash"),
            );
            let _guard = span.enter();
            info!("within proof span");
        });
        assert!(recorder
            .names()
            .iter()
            .any(|name| name == "runtime.proof.operation"));
    }

    fn seeded_keypair(seed: u8) -> Keypair {
        let secret = SecretKey::from_bytes(&[seed; 32]).expect("secret");
        let public = PublicKey::from(&secret);
        Keypair { secret, public }
    }

    fn sign_identity_vote(keypair: &Keypair, height: u64, hash: &str) -> SignedBftVote {
        let voter = address_from_public_key(&keypair.public);
        let vote = BftVote {
            round: 0,
            height,
            block_hash: hash.to_string(),
            voter: voter.clone(),
            kind: BftVoteKind::PreCommit,
        };
        let signature = keypair.sign(&vote.message_bytes());
        SignedBftVote {
            vote,
            public_key: hex::encode(keypair.public.to_bytes()),
            signature: hex::encode(signature.to_bytes()),
        }
    }

    fn sample_identity_declaration(ledger: &Ledger) -> IdentityDeclaration {
        ledger.sync_epoch_for_height(1);
        let pk_bytes = vec![1u8; 32];
        let wallet_pk = hex::encode(&pk_bytes);
        let wallet_addr = hex::encode::<[u8; 32]>(Blake2sHasher::hash(&pk_bytes).into());
        let epoch_nonce_bytes = ledger.current_epoch_nonce();
        let vrf_keypair = generate_vrf_keypair().expect("generate vrf keypair");
        let vrf = evaluate_vrf(
            &epoch_nonce_bytes,
            0,
            &wallet_addr,
            0,
            Some(&vrf_keypair.secret),
        )
        .expect("evaluate vrf");
        let commitment_proof = ledger.identity_commitment_proof(&wallet_addr);
        let genesis = IdentityGenesis {
            wallet_pk,
            wallet_addr,
            vrf_public_key: vrf_public_key_to_hex(&vrf_keypair.public),
            vrf_proof: vrf.clone(),
            epoch_nonce: hex::encode(epoch_nonce_bytes),
            state_root: hex::encode(ledger.state_root()),
            identity_root: hex::encode(ledger.identity_root()),
            initial_reputation: 0,
            commitment_proof: commitment_proof.clone(),
        };
        let parameters = StarkParameters::blueprint_default();
        let expected_commitment = genesis.expected_commitment().expect("commitment");
        let witness = IdentityWitness {
            wallet_pk: genesis.wallet_pk.clone(),
            wallet_addr: genesis.wallet_addr.clone(),
            vrf_tag: genesis.vrf_tag().to_string(),
            epoch_nonce: genesis.epoch_nonce.clone(),
            state_root: genesis.state_root.clone(),
            identity_root: genesis.identity_root.clone(),
            initial_reputation: genesis.initial_reputation,
            commitment: expected_commitment.clone(),
            identity_leaf: commitment_proof.leaf.clone(),
            identity_path: commitment_proof.siblings.clone(),
        };
        let circuit = IdentityCircuit::new(witness.clone());
        circuit.evaluate_constraints().expect("constraints");
        let trace = circuit
            .generate_trace(&parameters)
            .expect("trace generation");
        circuit
            .verify_air(&parameters, &trace)
            .expect("air verification");
        let inputs = vec![
            string_to_field(&parameters, &witness.wallet_addr),
            string_to_field(&parameters, &witness.vrf_tag),
            string_to_field(&parameters, &witness.identity_root),
            string_to_field(&parameters, &witness.state_root),
        ];
        let hasher = parameters.poseidon_hasher();
        let fri_prover = FriProver::new(&parameters);
        let air = circuit
            .define_air(&parameters, &trace)
            .expect("air definition");
        let fri_output = fri_prover.prove(&air, &trace, &inputs);
        let proof = StarkProof::new(
            ProofKind::Identity,
            ProofPayload::Identity(witness),
            inputs,
            trace,
            fri_output.commitment_proof,
            fri_output.fri_proof,
            &hasher,
        );
        IdentityDeclaration {
            genesis,
            proof: IdentityProof {
                commitment: expected_commitment,
                zk_proof: ChainProof::Stwo(proof),
            },
        }
    }

    fn attested_request(ledger: &Ledger, height: u64) -> AttestedIdentityRequest {
        let declaration = sample_identity_declaration(ledger);
        let identity_hash = hex::encode(declaration.hash().expect("hash"));
        let voters: Vec<Keypair> = (0..IDENTITY_ATTESTATION_QUORUM)
            .map(|idx| seeded_keypair(50 + idx as u8))
            .collect();
        let attested_votes = voters
            .iter()
            .map(|kp| sign_identity_vote(kp, height, &identity_hash))
            .collect();
        let gossip_confirmations = voters
            .iter()
            .take(IDENTITY_ATTESTATION_GOSSIP_MIN)
            .map(|kp| address_from_public_key(&kp.public))
            .collect();
        AttestedIdentityRequest {
            declaration,
            attested_votes,
            gossip_confirmations,
        }
    }

    fn temp_config() -> (tempfile::TempDir, NodeConfig) {
        let dir = tempdir().expect("tempdir");
        let base = dir.path();
        let mut config = NodeConfig::default();
        config.data_dir = base.join("data");
        config.key_path = base.join("node_key.toml");
        config.p2p_key_path = base.join("p2p_key.toml");
        config.vrf_key_path = base.join("vrf_key.toml");
        config.snapshot_dir = base.join("snapshots");
        config.proof_cache_dir = base.join("proofs");
        (dir, config)
    }

    #[test]
    fn node_accepts_valid_identity_attestation() {
        let (_tmp, config) = temp_config();
        let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
        let height = node.inner.chain_tip.read().height + 1;
        let request = attested_request(&node.inner.ledger, height);
        node.inner
            .validate_identity_attestation(&request, height)
            .expect("valid attestation accepted");
    }

    #[test]
    fn node_rejects_attestation_below_quorum() {
        let (_tmp, config) = temp_config();
        let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
        let height = node.inner.chain_tip.read().height + 1;
        let mut request = attested_request(&node.inner.ledger, height);
        request
            .attested_votes
            .truncate(IDENTITY_ATTESTATION_QUORUM - 1);
        let err = node
            .inner
            .validate_identity_attestation(&request, height)
            .expect_err("insufficient quorum rejected");
        match err {
            ChainError::Transaction(message) => {
                assert!(message.contains("quorum"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn node_rejects_attestation_with_insufficient_gossip() {
        let (_tmp, config) = temp_config();
        let node = Node::new(config, RuntimeMetrics::noop()).expect("node");
        let height = node.inner.chain_tip.read().height + 1;
        let mut request = attested_request(&node.inner.ledger, height);
        request
            .gossip_confirmations
            .truncate(IDENTITY_ATTESTATION_GOSSIP_MIN - 1);
        let err = node
            .inner
            .validate_identity_attestation(&request, height)
            .expect_err("insufficient gossip rejected");
        match err {
            ChainError::Transaction(message) => {
                assert!(message.contains("gossip"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn finalizes_external_block_from_remote_proposer() {
        let (_tmp_a, mut config_a) = temp_config();
        let (_tmp_b, mut config_b) = temp_config();

        config_a.rollout.feature_gates.pruning = false;
        config_b.rollout.feature_gates.pruning = false;
        config_a.rollout.feature_gates.consensus_enforcement = false;
        config_b.rollout.feature_gates.consensus_enforcement = false;

        let key_a = load_or_generate_keypair(&config_a.key_path).expect("generate key a");
        let key_b = load_or_generate_keypair(&config_b.key_path).expect("generate key b");
        let address_a = address_from_public_key(&key_a.public);
        let address_b = address_from_public_key(&key_b.public);

        let genesis_accounts = vec![
            GenesisAccount {
                address: address_a.clone(),
                balance: 1_000_000_000,
                stake: "1000".to_string(),
            },
            GenesisAccount {
                address: address_b.clone(),
                balance: 1_000_000_000,
                stake: "1000".to_string(),
            },
        ];
        config_a.genesis.accounts = genesis_accounts.clone();
        config_b.genesis.accounts = genesis_accounts;

        let node_a = Node::new(config_a, RuntimeMetrics::noop()).expect("node a");
        let node_b = Node::new(config_b, RuntimeMetrics::noop()).expect("node b");

        let height = node_a.inner.chain_tip.read().height + 1;
        let request = attested_request(&node_a.inner.ledger, height);
        node_a
            .inner
            .submit_identity(request)
            .expect("submit identity");
        node_a.inner.produce_block().expect("produce block");

        let block = node_a
            .inner
            .storage
            .read_block(height)
            .expect("read block")
            .expect("block exists");
        assert_eq!(block.header.proposer, address_a);

        let previous_hash_bytes =
            hex::decode(&block.header.previous_hash).expect("decode prev hash");
        let mut seed = [0u8; 32];
        if !previous_hash_bytes.is_empty() {
            seed.copy_from_slice(&previous_hash_bytes);
        }

        let accounts_snapshot = node_b.inner.ledger.accounts_snapshot();
        let (validators, observers) = classify_participants(&accounts_snapshot);
        let proposer_candidate = validators
            .iter()
            .find(|candidate| candidate.address == block.header.proposer)
            .expect("proposer candidate")
            .clone();

        node_b
            .inner
            .ledger
            .sync_epoch_for_height(block.header.height);
        let epoch = node_b.inner.ledger.current_epoch();

        let tier = match block.header.leader_tier.as_str() {
            "New" => Tier::Tl0,
            "Validated" => Tier::Tl1,
            "Available" => Tier::Tl2,
            "Committed" => Tier::Tl3,
            "Reliable" => Tier::Tl4,
            "Trusted" => Tier::Tl5,
            other => panic!("unexpected leader tier: {other}"),
        };
        let tier_seed = vrf::derive_tier_seed(
            &proposer_candidate.address,
            proposer_candidate.timetoke_hours,
        );
        let input = PoseidonVrfInput::new(seed, epoch, tier_seed);
        let randomness = Natural::from_str(&block.header.randomness).expect("parse randomness");
        let proof = VrfProof {
            randomness,
            preoutput: block.header.vrf_preoutput.clone(),
            proof: block.header.vrf_proof.clone(),
        };
        let public_key = if block.header.vrf_public_key.trim().is_empty() {
            None
        } else {
            Some(vrf_public_key_from_hex(&block.header.vrf_public_key).expect("vrf key"))
        };
        let mut pool = VrfSubmissionPool::new();
        pool.insert(VrfSubmission {
            address: block.header.proposer.clone(),
            public_key,
            input,
            proof,
            tier,
            timetoke_hours: block.header.leader_timetoke,
        });

        let mut round = ConsensusRound::new(
            block.header.height,
            block.consensus.round,
            seed,
            node_b.inner.config.validator_set_size(),
            validators,
            observers,
            &pool,
        );
        round.set_block_hash(block.hash.clone());
        for record in &block.consensus.pre_votes {
            round
                .register_prevote(&record.vote)
                .expect("register prevote");
        }
        for record in &block.consensus.pre_commits {
            round
                .register_precommit(&record.vote)
                .expect("register precommit");
        }
        assert!(round.commit_reached());

        let previous_block = if block.header.height == 0 {
            None
        } else {
            node_b
                .inner
                .storage
                .read_block(block.header.height - 1)
                .expect("read previous block")
        };

        let outcome = node_b
            .inner
            .finalize_block(FinalizationContext::External(ExternalFinalizationContext {
                round,
                block: block.clone(),
                previous_block,
                archived_votes: block.bft_votes.clone(),
            }))
            .expect("finalize external");

        let sealed = match outcome {
            FinalizationOutcome::Sealed { block: sealed, .. } => sealed,
            FinalizationOutcome::AwaitingQuorum => panic!("expected sealed block"),
        };
        assert_eq!(sealed.hash, block.hash);

        let tip_metadata = node_b
            .inner
            .storage
            .tip()
            .expect("tip metadata")
            .expect("metadata");
        assert_eq!(tip_metadata.height, block.header.height);
        assert_eq!(tip_metadata.new_state_root, block.header.state_root);

        let stored_record = node_b
            .inner
            .storage
            .read_block_record(block.header.height)
            .expect("read record")
            .expect("stored block");
        let stored_pruning = &stored_record.envelope.pruning_proof;
        assert_eq!(stored_pruning, &block.pruning_proof);
        let stored_consensus = &stored_record.envelope.consensus;
        assert_eq!(stored_consensus.round, block.consensus.round);
        assert_eq!(stored_consensus.total_power, block.consensus.total_power);
        assert_eq!(
            stored_consensus.pre_votes.len(),
            block.consensus.pre_votes.len()
        );
        assert_eq!(
            stored_consensus.pre_commits.len(),
            block.consensus.pre_commits.len()
        );

        assert_eq!(
            hex::encode(node_b.inner.ledger.state_root()),
            block.header.state_root
        );
        assert_eq!(node_b.inner.chain_tip.read().height, block.header.height);
    }

    #[test]
    #[traced_test]
    fn rejects_external_block_with_tampered_state_fri_proof() {
        let (_tmp_a, mut config_a) = temp_config();
        let (_tmp_b, mut config_b) = temp_config();

        config_a.rollout.feature_gates.pruning = false;
        config_b.rollout.feature_gates.pruning = false;
        config_a.rollout.feature_gates.consensus_enforcement = false;
        config_b.rollout.feature_gates.consensus_enforcement = false;

        let key_a = load_or_generate_keypair(&config_a.key_path).expect("generate key a");
        let key_b = load_or_generate_keypair(&config_b.key_path).expect("generate key b");
        let address_a = address_from_public_key(&key_a.public);
        let address_b = address_from_public_key(&key_b.public);

        let genesis_accounts = vec![
            GenesisAccount {
                address: address_a.clone(),
                balance: 1_000_000_000,
                stake: "1000".to_string(),
            },
            GenesisAccount {
                address: address_b.clone(),
                balance: 1_000_000_000,
                stake: "1000".to_string(),
            },
        ];
        config_a.genesis.accounts = genesis_accounts.clone();
        config_b.genesis.accounts = genesis_accounts;

        let node_a = Node::new(config_a, RuntimeMetrics::noop()).expect("node a");
        let node_b = Node::new(config_b, RuntimeMetrics::noop()).expect("node b");

        let height = node_a.inner.chain_tip.read().height + 1;
        let request = attested_request(&node_a.inner.ledger, height);
        node_a
            .inner
            .submit_identity(request)
            .expect("submit identity");
        node_a.inner.produce_block().expect("produce block");

        let block = node_a
            .inner
            .storage
            .read_block(height)
            .expect("read block")
            .expect("block exists");
        assert_eq!(block.header.proposer, address_a);

        let previous_hash_bytes =
            hex::decode(&block.header.previous_hash).expect("decode prev hash");
        let mut seed = [0u8; 32];
        if !previous_hash_bytes.is_empty() {
            seed.copy_from_slice(&previous_hash_bytes);
        }

        let accounts_snapshot = node_b.inner.ledger.accounts_snapshot();
        let (validators, observers) = classify_participants(&accounts_snapshot);
        let proposer_candidate = validators
            .iter()
            .find(|candidate| candidate.address == block.header.proposer)
            .expect("proposer candidate")
            .clone();

        node_b
            .inner
            .ledger
            .sync_epoch_for_height(block.header.height);
        let epoch = node_b.inner.ledger.current_epoch();

        let tier = match block.header.leader_tier.as_str() {
            "New" => Tier::Tl0,
            "Validated" => Tier::Tl1,
            "Available" => Tier::Tl2,
            "Committed" => Tier::Tl3,
            "Reliable" => Tier::Tl4,
            "Trusted" => Tier::Tl5,
            other => panic!("unexpected leader tier: {other}"),
        };
        let tier_seed = vrf::derive_tier_seed(
            &proposer_candidate.address,
            proposer_candidate.timetoke_hours,
        );
        let input = PoseidonVrfInput::new(seed, epoch, tier_seed);
        let randomness = Natural::from_str(&block.header.randomness).expect("parse randomness");
        let proof = VrfProof {
            randomness,
            preoutput: block.header.vrf_preoutput.clone(),
            proof: block.header.vrf_proof.clone(),
        };
        let public_key = if block.header.vrf_public_key.trim().is_empty() {
            None
        } else {
            Some(vrf_public_key_from_hex(&block.header.vrf_public_key).expect("vrf key"))
        };
        let mut pool = VrfSubmissionPool::new();
        pool.insert(VrfSubmission {
            address: block.header.proposer.clone(),
            public_key,
            input,
            proof,
            tier,
            timetoke_hours: block.header.leader_timetoke,
        });

        let mut round = ConsensusRound::new(
            block.header.height,
            block.consensus.round,
            seed,
            node_b.inner.config.validator_set_size(),
            validators,
            observers,
            &pool,
        );
        round.set_block_hash(block.hash.clone());
        for record in &block.consensus.pre_votes {
            round
                .register_prevote(&record.vote)
                .expect("register prevote");
        }
        for record in &block.consensus.pre_commits {
            round
                .register_precommit(&record.vote)
                .expect("register precommit");
        }
        assert!(round.commit_reached());

        let mut tampered_block = block.clone();
        let tampered_state_proof = match tampered_block.stark.state_proof.clone() {
            ChainProof::Stwo(mut stark) => {
                stark.commitment_proof = CommitmentSchemeProofData::default();
                stark.fri_proof = FriProof::default();
                ChainProof::Stwo(stark)
            }
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => panic!("expected STWO state proof"),
        };
        tampered_block.stark.state_proof = tampered_state_proof;

        let previous_block = if tampered_block.header.height == 0 {
            None
        } else {
            node_b
                .inner
                .storage
                .read_block(tampered_block.header.height - 1)
                .expect("read previous block")
        };

        let tip_before = node_b.inner.storage.tip().expect("tip before");
        let chain_tip_before = node_b.inner.chain_tip.read().clone();
        let epoch_before = node_b.inner.ledger.current_epoch();

        let result = node_b.inner.finalize_block(FinalizationContext::External(
            ExternalFinalizationContext {
                round,
                block: tampered_block.clone(),
                previous_block,
                archived_votes: tampered_block.bft_votes.clone(),
            },
        ));

        let err = match result {
            Err(err) => err,
            Ok(_) => panic!("expected tampered block to be rejected"),
        };
        match err {
            ChainError::Crypto(message) => {
                assert!(message.contains("fri proof mismatch"));
            }
            other => panic!("unexpected error: {other:?}"),
        }

        assert!(logs_contain("external block proof verification failed"));

        let tip_after = node_b.inner.storage.tip().expect("tip after");
        match (tip_before, tip_after) {
            (None, None) => {}
            (Some(before), Some(after)) => {
                assert_eq!(after.height, before.height);
                assert_eq!(after.new_state_root, before.new_state_root);
            }
            (before, after) => {
                panic!("tip changed after failed finalization: before={before:?} after={after:?}")
            }
        }

        let chain_tip_after = node_b.inner.chain_tip.read().clone();
        assert_eq!(chain_tip_after.height, chain_tip_before.height);
        assert_eq!(chain_tip_after.last_hash, chain_tip_before.last_hash);

        assert_eq!(node_b.inner.ledger.current_epoch(), epoch_before);

        let missing = node_b
            .inner
            .storage
            .read_block(tampered_block.header.height)
            .expect("read tampered height");
        assert!(missing.is_none());
    }
}

#[cfg(test)]
mod double_spend_tests {
    use super::is_double_spend;
    use crate::errors::ChainError;

    #[test]
    fn detects_spent_input_error() {
        let err = ChainError::Transaction("transaction input already spent".into());
        assert!(is_double_spend(&err));
    }

    #[test]
    fn detects_missing_input_error() {
        let err = ChainError::Transaction("transaction input not found".into());
        assert!(is_double_spend(&err));
    }

    #[test]
    fn ignores_other_transaction_errors() {
        let err = ChainError::Transaction("insufficient balance".into());
        assert!(!is_double_spend(&err));
    }

    #[test]
    fn ignores_non_transaction_errors() {
        let err = ChainError::Config("some other error".into());
        assert!(!is_double_spend(&err));
    }
}

impl NodeHandle {
    pub async fn stop(&self) -> ChainResult<()> {
        self.inner.stop().await
    }

    pub fn subscribe_pipeline(&self) -> broadcast::Receiver<PipelineObservation> {
        self.inner.subscribe_pipeline()
    }

    pub fn finalize_block(
        &self,
        ctx: ExternalFinalizationContext,
    ) -> ChainResult<FinalizationOutcome> {
        self.inner
            .finalize_block(FinalizationContext::External(ctx))
    }

    #[instrument(
        name = "node.submit_transaction",
        skip(self, bundle),
        fields(hash = tracing::field::Empty),
        err
    )]
    pub fn submit_transaction(&self, bundle: TransactionProofBundle) -> ChainResult<String> {
        let hash = bundle.hash();
        Span::current().record("hash", &display(&hash));
        self.inner.submit_transaction(bundle)
    }

    pub fn subscribe_witness_gossip(&self, topic: GossipTopic) -> broadcast::Receiver<Vec<u8>> {
        self.inner.subscribe_witness_gossip(topic)
    }

    pub fn p2p_handle(&self) -> Option<P2pHandle> {
        self.inner.p2p_handle()
    }

    pub async fn attach_p2p(&self, handle: P2pHandle) {
        self.inner.initialise_p2p_runtime(handle, None).await;
    }

    pub fn fanout_witness_gossip(&self, topic: GossipTopic, payload: &[u8]) {
        self.inner.ingest_witness_bytes(topic, payload.to_vec());
    }

    pub fn submit_identity(&self, request: AttestedIdentityRequest) -> ChainResult<String> {
        self.inner.submit_identity(request)
    }

    #[instrument(
        name = "node.consensus.submit_vote",
        skip(self, vote),
        fields(
            height = vote.vote.height,
            round = vote.vote.round,
            voter = %vote.vote.voter,
            kind = ?vote.vote.kind
        )
    )]
    pub fn submit_vote(&self, vote: SignedBftVote) -> ChainResult<String> {
        self.inner.submit_vote(vote)
    }

    pub fn submit_block_proposal(&self, block: Block) -> ChainResult<String> {
        self.inner.submit_block_proposal(block)
    }

    pub fn submit_vrf_submission(&self, submission: VrfSubmission) -> ChainResult<()> {
        self.inner.submit_vrf_submission(submission)
    }

    pub fn submit_uptime_proof(&self, proof: UptimeProof) -> ChainResult<u64> {
        self.inner.submit_uptime_proof(proof)
    }

    pub fn get_block(&self, height: u64) -> ChainResult<Option<Block>> {
        self.inner.get_block(height)
    }

    pub fn latest_block(&self) -> ChainResult<Option<Block>> {
        self.inner.latest_block()
    }

    pub fn get_account(&self, address: &str) -> ChainResult<Option<Account>> {
        self.inner.get_account(address)
    }

    pub fn node_status(&self) -> ChainResult<NodeStatus> {
        self.inner.node_status()
    }

    pub fn mempool_status(&self) -> ChainResult<MempoolStatus> {
        self.inner.mempool_status()
    }

    pub fn update_mempool_limit(&self, limit: usize) -> ChainResult<()> {
        self.inner.update_mempool_limit(limit)
    }

    pub fn mempool_limit(&self) -> usize {
        self.inner.mempool_limit()
    }

    pub fn queue_weights(&self) -> QueueWeightsConfig {
        self.inner.queue_weights()
    }

    pub fn update_queue_weights(&self, weights: QueueWeightsConfig) -> ChainResult<()> {
        self.inner.update_queue_weights(weights)
    }

    pub fn rollout_status(&self) -> RolloutStatus {
        self.inner.rollout_status()
    }

    pub fn consensus_status(&self) -> ChainResult<ConsensusStatus> {
        self.inner.consensus_status()
    }

    pub fn vrf_threshold(&self) -> VrfThresholdStatus {
        self.inner.vrf_threshold()
    }

    pub fn vrf_status(&self, address: &str) -> ChainResult<VrfStatus> {
        self.inner.vrf_status(address)
    }

    pub fn vrf_history(&self, epoch: Option<u64>) -> ChainResult<Vec<VrfHistoryRecord>> {
        self.inner.vrf_history(epoch)
    }

    pub fn slashing_events(&self, limit: usize) -> ChainResult<Vec<SlashingEvent>> {
        self.inner.slashing_events(limit)
    }

    pub fn reputation_audit(&self, address: &str) -> ChainResult<Option<ReputationAudit>> {
        self.inner.reputation_audit(address)
    }

    pub fn audit_slashing_stream(&self, limit: usize) -> ChainResult<Vec<SlashingEvent>> {
        self.inner.recent_slashing_audits(limit)
    }

    pub fn audit_reputation_stream(&self, limit: usize) -> ChainResult<Vec<ReputationAudit>> {
        self.inner.recent_reputation_audits(limit)
    }

    pub fn slash_validator(&self, address: &str, reason: SlashingReason) -> ChainResult<()> {
        self.inner.slash_validator(address, reason)
    }

    pub fn bft_membership(&self) -> ChainResult<BftMembership> {
        self.inner.bft_membership()
    }

    pub fn timetoke_snapshot(&self) -> ChainResult<Vec<TimetokeRecord>> {
        self.inner.timetoke_snapshot()
    }

    pub fn sync_timetoke_records(&self, records: Vec<TimetokeRecord>) -> ChainResult<Vec<Address>> {
        self.inner.sync_timetoke_records(records)
    }

    pub fn address(&self) -> &str {
        &self.inner.address
    }

    pub fn storage(&self) -> Storage {
        self.inner.storage.clone()
    }

    pub fn vrf_secrets_config(&self) -> SecretsConfig {
        self.inner.config.secrets.clone()
    }

    pub fn vrf_key_path(&self) -> PathBuf {
        self.inner.config.vrf_key_path.clone()
    }

    pub fn state_root(&self) -> ChainResult<String> {
        Ok(hex::encode(self.inner.ledger.state_root()))
    }

    pub fn block_proofs(&self, height: u64) -> ChainResult<Option<BlockProofArtifactsView>> {
        self.inner.block_proofs(height)
    }

    pub fn validator_telemetry(&self) -> ChainResult<ValidatorTelemetryView> {
        self.inner.validator_telemetry()
    }

    pub async fn meta_telemetry_snapshot(&self) -> ChainResult<MetaTelemetryReport> {
        self.inner.meta_telemetry_snapshot().await
    }

    pub async fn p2p_censorship_report(&self) -> ChainResult<P2pCensorshipReport> {
        self.inner.p2p_censorship_report().await
    }

    pub async fn reload_access_lists(
        &self,
        allowlist: Vec<AllowlistedPeer>,
        blocklist: Vec<NetworkPeerId>,
    ) -> ChainResult<()> {
        self.inner.reload_access_lists(allowlist, blocklist).await
    }

    pub fn run_pruning_cycle(&self, chunk_size: usize) -> ChainResult<Option<PruningJobStatus>> {
        self.inner.run_pruning_cycle(chunk_size)
    }

    pub fn pruning_job_status(&self) -> Option<PruningJobStatus> {
        self.inner.pruning_job_status()
    }

    pub fn state_sync_plan(&self, chunk_size: usize) -> ChainResult<StateSyncPlan> {
        self.inner.state_sync_plan(chunk_size)
    }

    pub fn network_state_sync_plan(&self, chunk_size: usize) -> ChainResult<NetworkStateSyncPlan> {
        self.inner.network_state_sync_plan(chunk_size)
    }

    pub fn network_state_sync_chunk(
        &self,
        chunk_size: usize,
        start_height: u64,
    ) -> ChainResult<NetworkStateSyncChunk> {
        self.inner
            .network_state_sync_chunk(chunk_size, start_height)
    }

    pub fn reconstruction_plan(&self, start_height: u64) -> ChainResult<ReconstructionPlan> {
        self.inner.reconstruction_plan(start_height)
    }

    pub fn verify_proof_chain(&self) -> ChainResult<()> {
        self.inner.verify_proof_chain()
    }

    pub fn reconstruct_block<P: PayloadProvider>(
        &self,
        height: u64,
        provider: &P,
    ) -> ChainResult<Block> {
        self.inner.reconstruct_block(height, provider)
    }

    pub fn reconstruct_range<P: PayloadProvider>(
        &self,
        start_height: u64,
        end_height: u64,
        provider: &P,
    ) -> ChainResult<Vec<Block>> {
        self.inner
            .reconstruct_range(start_height, end_height, provider)
    }

    pub fn execute_reconstruction_plan<P: PayloadProvider>(
        &self,
        plan: &ReconstructionPlan,
        provider: &P,
    ) -> ChainResult<Vec<Block>> {
        self.inner.execute_reconstruction_plan(plan, provider)
    }

    pub fn stream_state_sync_chunks(
        &self,
        store: &SnapshotStore,
        root: &Hash,
    ) -> ChainResult<SnapshotChunkStream> {
        self.inner.stream_state_sync_chunks(store, root)
    }

    pub fn state_sync_chunk_by_index(
        &self,
        store: &SnapshotStore,
        root: &Hash,
        index: u64,
    ) -> ChainResult<SnapshotChunk> {
        self.inner.state_sync_chunk_by_index(store, root, index)
    }

    pub fn subscribe_light_client_heads(
        &self,
    ) -> ChainResult<watch::Receiver<Option<LightClientHead>>> {
        self.inner.subscribe_light_client_heads()
    }

    pub fn latest_light_client_head(&self) -> ChainResult<Option<LightClientHead>> {
        self.inner.latest_light_client_head()
    }
}

impl NodeInner {
    fn subscribe_witness_gossip(&self, topic: GossipTopic) -> broadcast::Receiver<Vec<u8>> {
        self.witness_channels.subscribe(topic)
    }

    fn emit_witness_bytes(&self, topic: GossipTopic, payload: Vec<u8>) {
        self.witness_channels.publish_local(topic, payload);
    }

    #[instrument(
        name = "node.gossip.emit_witness",
        skip(self, payload),
        fields(topic = ?topic)
    )]
    fn emit_witness_json<T: Serialize>(&self, topic: GossipTopic, payload: &T) {
        if matches!(topic, GossipTopic::Blocks | GossipTopic::Votes) {
            self.consensus_telemetry
                .record_witness_event(format!("{topic:?}"));
            self.update_runtime_metrics();
        }
        match serde_json::to_vec(payload) {
            Ok(bytes) => self.emit_witness_bytes(topic, bytes),
            Err(err) => debug!(?err, ?topic, "failed to encode witness gossip payload"),
        }
    }

    fn persist_timetoke_accounts(&self, addresses: &[Address]) -> ChainResult<()> {
        for address in addresses {
            if let Some(account) = self.ledger.get_account(address) {
                self.storage.persist_account(&account)?;
            }
        }
        Ok(())
    }

    fn emit_timetoke_meta(&self, records: &[TimetokeRecord]) {
        if records.is_empty() {
            return;
        }
        let commitments = self.ledger.global_commitments();
        let payload = TimetokeDeltaBroadcast {
            timetoke_root: hex::encode(commitments.timetoke_root),
            records: records.to_vec(),
        };
        self.emit_witness_json(GossipTopic::Meta, &payload);
    }

    fn apply_remote_timetoke_delta(
        &self,
        peer: &PeerId,
        delta: TimetokeDeltaBroadcast,
    ) -> ChainResult<()> {
        let updated = self.ledger.sync_timetoke_records(&delta.records)?;
        self.persist_timetoke_accounts(&updated)?;
        if !updated.is_empty() {
            if let Ok(bytes) = serde_json::to_vec(&updated) {
                self.ingest_witness_bytes(GossipTopic::Snapshots, bytes);
            }
        }
        let commitments = self.ledger.global_commitments();
        let local_root = hex::encode(commitments.timetoke_root);
        if local_root != delta.timetoke_root {
            warn!(
                target: "node",
                %peer,
                expected = %delta.timetoke_root,
                actual = %local_root,
                "timetoke root mismatch after applying delta"
            );
        }
        Ok(())
    }

    fn emit_state_sync_artifacts(&self) {
        if !self.config.rollout.feature_gates.reconstruction {
            return;
        }
        let engine = ReconstructionEngine::new(self.storage.clone());
        let plan = match engine.state_sync_plan(DEFAULT_STATE_SYNC_CHUNK) {
            Ok(plan) => plan,
            Err(err) => {
                warn!(?err, "failed to build state sync plan for gossip");
                return;
            }
        };
        let summary = match plan.to_network_plan() {
            Ok(summary) => summary,
            Err(err) => {
                warn!(?err, "failed to encode state sync plan for gossip");
                return;
            }
        };
        self.emit_witness_json(GossipTopic::Snapshots, &summary);

        match plan.chunk_messages() {
            Ok(chunks) => {
                for chunk in chunks {
                    self.emit_witness_json(GossipTopic::Snapshots, &chunk);
                }
            }
            Err(err) => warn!(?err, "failed to encode state sync chunks for gossip"),
        }

        match plan.light_client_messages() {
            Ok(updates) => {
                for update in updates {
                    self.emit_witness_json(GossipTopic::Snapshots, &update);
                }
            }
            Err(err) => warn!(?err, "failed to encode light client updates for gossip"),
        }
    }

    fn ingest_witness_bytes(&self, topic: GossipTopic, payload: Vec<u8>) {
        self.witness_channels.ingest_remote(topic, payload);
    }

    fn attach_witness_publisher(&self, publisher: mpsc::Sender<(GossipTopic, Vec<u8>)>) {
        self.witness_channels.attach_publisher(publisher);
    }

    fn runtime_config(&self) -> ChainResult<P2pRuntimeConfig> {
        let mut config = P2pRuntimeConfig::from(&self.config);
        let profile = self.network_identity_profile()?;
        config.identity = Some(RuntimeIdentityProfile::from(profile));
        config.metrics = self.runtime_metrics.clone();
        Ok(config)
    }

    fn runtime_metrics(&self) -> ChainResult<P2pMetrics> {
        let status = self.node_status()?;
        let reputation_score = self
            .ledger
            .get_account(&self.address)
            .map(|account| account.reputation.score)
            .unwrap_or_default();
        let consensus_snapshot = self.consensus_telemetry.snapshot();
        self.runtime_metrics.record_block_height(status.height);
        Ok(P2pMetrics {
            block_height: status.height,
            block_hash: status.last_hash,
            transaction_count: status.pending_transactions,
            reputation_score,
            verifier_metrics: self.verifiers.metrics_snapshot(),
            round_latencies_ms: consensus_snapshot.round_latencies_ms,
            leader_changes: consensus_snapshot.leader_changes,
            quorum_latency_ms: consensus_snapshot.quorum_latency_ms,
            witness_events: consensus_snapshot.witness_events,
            slashing_events: consensus_snapshot.slashing_events,
            failed_votes: consensus_snapshot.failed_votes,
        })
    }

    fn update_runtime_metrics(&self) {
        if let Some(handle) = self.p2p_runtime.lock().clone() {
            match self.runtime_metrics() {
                Ok(metrics) => handle.update_metrics(metrics),
                Err(err) => debug!(?err, "failed to collect runtime metrics"),
            }
        }
    }

    fn subscribe_pipeline(&self) -> broadcast::Receiver<PipelineObservation> {
        self.pipeline_events.subscribe()
    }

    fn publish_pipeline_event(&self, event: PipelineObservation) {
        let _ = self.pipeline_events.send(event);
    }

    async fn meta_telemetry_snapshot(&self) -> ChainResult<MetaTelemetryReport> {
        let handle = self
            .p2p_handle()
            .ok_or_else(|| ChainError::Config("p2p runtime not initialised".into()))?;
        handle
            .meta_telemetry_snapshot()
            .await
            .map_err(|err| ChainError::Config(format!("failed to collect meta telemetry: {err}")))
    }

    async fn p2p_censorship_report(&self) -> ChainResult<P2pCensorshipReport> {
        let handle = self
            .p2p_handle()
            .ok_or_else(|| ChainError::Config("p2p runtime not initialised".into()))?;
        let snapshot = handle.heuristics_snapshot().await.map_err(|err| {
            ChainError::Config(format!("failed to collect p2p heuristics: {err}"))
        })?;
        let entries = snapshot
            .into_iter()
            .map(|(peer, counters)| P2pCensorshipEntry {
                peer: peer.to_base58(),
                vote_timeouts: counters.vote_timeouts,
                proof_relay_misses: counters.proof_relay_misses,
                gossip_backpressure_events: counters.gossip_backpressure_events,
            })
            .collect();
        Ok(P2pCensorshipReport { entries })
    }

    async fn reload_access_lists(
        &self,
        allowlist: Vec<AllowlistedPeer>,
        blocklist: Vec<NetworkPeerId>,
    ) -> ChainResult<()> {
        let handle = self
            .p2p_handle()
            .ok_or_else(|| ChainError::Config("p2p runtime not initialised".into()))?;
        handle
            .reload_access_lists(allowlist, blocklist)
            .await
            .map_err(|err| ChainError::Config(format!("failed to reload access lists: {err}")))
    }

    fn p2p_handle(&self) -> Option<P2pHandle> {
        self.p2p_runtime.lock().clone()
    }

    async fn initialise_p2p_runtime(
        self: &Arc<Self>,
        handle: P2pHandle,
        runtime_task: Option<JoinHandle<()>>,
    ) {
        {
            let mut slot = self.p2p_runtime.lock();
            *slot = Some(handle.clone());
        }
        let (publisher_tx, mut publisher_rx) = mpsc::channel::<(GossipTopic, Vec<u8>)>(128);
        self.attach_witness_publisher(publisher_tx);
        self.update_runtime_metrics();

        let mut publish_shutdown = self.subscribe_shutdown();
        let publisher_handle = handle.clone();
        let publisher_span = info_span!("runtime.gossip.publish", component = "witness");
        self.spawn_worker(tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = publish_shutdown.recv() => {
                        match result {
                            Ok(_) | Err(broadcast::error::RecvError::Closed) => break,
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        }
                    }
                    maybe_message = publisher_rx.recv() => {
                        let Some((topic, payload)) = maybe_message else {
                            break;
                        };
                        if let Err(err) = publisher_handle.publish_gossip(topic, payload).await {
                            warn!(?err, ?topic, "failed to publish witness gossip");
                        }
                    }
                }
            }
        }
        .instrument(publisher_span)))
        .await;

        let mut event_shutdown = self.subscribe_shutdown();
        let mut events = handle.subscribe();
        let ingest = Arc::clone(self);
        let event_span = info_span!("runtime.gossip.ingest", component = "network_events");
        self.spawn_worker(tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = event_shutdown.recv() => {
                        match result {
                            Ok(_) | Err(broadcast::error::RecvError::Closed) => break,
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        }
                    }
                    event = events.recv() => match event {
                        Ok(NodeEvent::BlockProposal { peer, block }) => {
                            if let Err(err) = ingest.submit_block_proposal(block) {
                                warn!(?err, %peer, "failed to ingest block proposal from gossip");
                            }
                        }
                        Ok(NodeEvent::BlockRejected { peer, block, reason }) => {
                            ingest.handle_invalid_block_gossip(&peer, block, &reason);
                        }
                        Ok(NodeEvent::Vote { peer, vote }) => {
                            if let Err(err) = ingest.submit_vote(vote) {
                                warn!(?err, %peer, "failed to ingest vote from gossip");
                            }
                        }
                        Ok(NodeEvent::VoteRejected { peer, vote, reason }) => {
                            ingest.handle_invalid_vote_gossip(&peer, vote, &reason);
                        }
                        Ok(NodeEvent::VrfSubmission { peer, submission }) => {
                            if let Err(err) = ingest.submit_vrf_submission(submission) {
                                warn!(?err, %peer, "failed to ingest VRF submission from gossip");
                            }
                        }
                        Ok(NodeEvent::Evidence { evidence, .. }) => {
                            ingest.apply_evidence(evidence);
                        }
                        Ok(NodeEvent::TimetokeDelta { peer, delta }) => {
                            if let Err(err) = ingest.apply_remote_timetoke_delta(&peer, delta) {
                                warn!(?err, %peer, "failed to apply timetoke delta from gossip");
                            }
                        }
                        Ok(NodeEvent::Gossip { topic, data, .. }) => {
                            ingest.ingest_witness_bytes(topic, data);
                        }
                        Ok(_) => {}
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(skipped, "lagged on gossip event stream");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                }
            }
        }
        .instrument(event_span)))
        .await;

        if let Some(task) = runtime_task {
            self.spawn_worker(task).await;
        }
    }

    fn mempool_limit(&self) -> usize {
        self.mempool_limit.load(Ordering::Relaxed)
    }

    fn update_mempool_limit(&self, limit: usize) -> ChainResult<()> {
        if limit == 0 {
            return Err(ChainError::Config(
                "node configuration requires mempool_limit to be greater than 0".into(),
            ));
        }
        self.mempool_limit.store(limit, Ordering::SeqCst);
        Ok(())
    }

    fn queue_weights(&self) -> QueueWeightsConfig {
        self.queue_weights.read().clone()
    }

    fn update_queue_weights(&self, weights: QueueWeightsConfig) -> ChainResult<()> {
        weights.validate()?;
        *self.queue_weights.write() = weights;
        Ok(())
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn verify_rpp_stark_with_metrics(
        &self,
        proof_kind: ProofVerificationKind,
        proof: &ChainProof,
    ) -> ChainResult<RppStarkVerificationReport> {
        let started = Instant::now();
        match self
            .verifiers
            .verify_rpp_stark_with_report(proof, proof_kind.as_str())
        {
            Ok(report) => {
                self.emit_rpp_stark_metrics(
                    ProofVerificationBackend::RppStark,
                    proof_kind,
                    proof,
                    &report,
                    started.elapsed(),
                );
                Ok(report)
            }
            Err(err) => {
                self.emit_rpp_stark_failure_metrics(
                    ProofVerificationBackend::RppStark,
                    proof_kind,
                    proof,
                    started.elapsed(),
                    &err,
                );
                Err(err)
            }
        }
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn emit_rpp_stark_metrics(
        &self,
        backend: ProofVerificationBackend,
        proof_kind: ProofVerificationKind,
        proof: &ChainProof,
        report: &RppStarkVerificationReport,
        duration: Duration,
    ) {
        let flags = report.flags();
        let proof_metrics = self.runtime_metrics.proofs();
        proof_metrics.observe_verification(backend, proof_kind, duration);
        proof_metrics.observe_verification_total_bytes(backend, proof_kind, report.total_bytes());
        proof_metrics.observe_verification_stage(
            backend,
            proof_kind,
            ProofVerificationStage::Params,
            ProofVerificationOutcome::from_bool(flags.params()),
        );
        proof_metrics.observe_verification_stage(
            backend,
            proof_kind,
            ProofVerificationStage::Public,
            ProofVerificationOutcome::from_bool(flags.public()),
        );
        proof_metrics.observe_verification_stage(
            backend,
            proof_kind,
            ProofVerificationStage::Merkle,
            ProofVerificationOutcome::from_bool(flags.merkle()),
        );
        proof_metrics.observe_verification_stage(
            backend,
            proof_kind,
            ProofVerificationStage::Fri,
            ProofVerificationOutcome::from_bool(flags.fri()),
        );
        proof_metrics.observe_verification_stage(
            backend,
            proof_kind,
            ProofVerificationStage::Composition,
            ProofVerificationOutcome::from_bool(flags.composition()),
        );

        if let Ok(artifact) = proof.expect_rpp_stark() {
            let verify_duration_ms = duration.as_millis().min(u128::from(u64::MAX)) as u64;
            let params_bytes = u64::try_from(artifact.params_len()).unwrap_or(u64::MAX);
            let public_inputs_bytes =
                u64::try_from(artifact.public_inputs_len()).unwrap_or(u64::MAX);
            let payload_bytes = u64::try_from(artifact.proof_len()).unwrap_or(u64::MAX);

            proof_metrics.observe_verification_params_bytes(backend, proof_kind, params_bytes);
            proof_metrics.observe_verification_public_inputs_bytes(
                backend,
                proof_kind,
                public_inputs_bytes,
            );
            proof_metrics.observe_verification_payload_bytes(backend, proof_kind, payload_bytes);

            info!(
                target = "proofs",
                proof_backend = "rpp-stark",
                proof_kind = proof_kind.as_str(),
                valid = report.is_verified(),
                params_ok = flags.params(),
                public_ok = flags.public(),
                merkle_ok = flags.merkle(),
                fri_ok = flags.fri(),
                composition_ok = flags.composition(),
                proof_bytes = report.total_bytes(),
                params_bytes,
                public_inputs_bytes,
                payload_bytes,
                verify_duration_ms,
                trace_queries = ?report.trace_query_indices(),
                report = %report,
                "rpp-stark proof verification"
            );
            info!(
                target = "telemetry",
                proof_backend = "rpp-stark",
                proof_kind = proof_kind.as_str(),
                valid = report.is_verified(),
                params_ok = flags.params(),
                public_ok = flags.public(),
                merkle_ok = flags.merkle(),
                fri_ok = flags.fri(),
                composition_ok = flags.composition(),
                proof_bytes = report.total_bytes(),
                params_bytes,
                public_inputs_bytes,
                payload_bytes,
                verify_duration_ms,
                "rpp-stark proof verification"
            );
        }
    }

    #[cfg(feature = "backend-rpp-stark")]
    fn emit_rpp_stark_failure_metrics(
        &self,
        backend: ProofVerificationBackend,
        proof_kind: ProofVerificationKind,
        proof: &ChainProof,
        duration: Duration,
        error: &ChainError,
    ) {
        let verify_duration_ms = duration.as_millis().min(u128::from(u64::MAX)) as u64;
        let proof_metrics = self.runtime_metrics.proofs();
        proof_metrics.observe_verification(backend, proof_kind, duration);
        if let Ok(artifact) = proof.expect_rpp_stark() {
            let params_bytes = u64::try_from(artifact.params_len()).unwrap_or(u64::MAX);
            let public_inputs_bytes =
                u64::try_from(artifact.public_inputs_len()).unwrap_or(u64::MAX);
            let payload_bytes = u64::try_from(artifact.proof_len()).unwrap_or(u64::MAX);
            let proof_bytes = u64::try_from(artifact.total_len()).unwrap_or(u64::MAX);

            proof_metrics.observe_verification_total_bytes(backend, proof_kind, proof_bytes);
            proof_metrics.observe_verification_params_bytes(backend, proof_kind, params_bytes);
            proof_metrics.observe_verification_public_inputs_bytes(
                backend,
                proof_kind,
                public_inputs_bytes,
            );
            proof_metrics.observe_verification_payload_bytes(backend, proof_kind, payload_bytes);

            warn!(
                target = "proofs",
                proof_backend = "rpp-stark",
                proof_kind = proof_kind.as_str(),
                valid = false,
                proof_bytes,
                params_bytes,
                public_inputs_bytes,
                payload_bytes,
                verify_duration_ms,
                error = %error,
                "rpp-stark proof verification failed"
            );
            warn!(
                target = "telemetry",
                proof_backend = "rpp-stark",
                proof_kind = proof_kind.as_str(),
                valid = false,
                proof_bytes,
                params_bytes,
                public_inputs_bytes,
                payload_bytes,
                verify_duration_ms,
                error = %error,
                "rpp-stark proof verification failed"
            );
        } else {
            warn!(
                target = "proofs",
                proof_backend = "rpp-stark",
                proof_kind = proof_kind.as_str(),
                valid = false,
                verify_duration_ms,
                error = %error,
                "rpp-stark proof verification failed"
            );
            warn!(
                target = "telemetry",
                proof_backend = "rpp-stark",
                proof_kind = proof_kind.as_str(),
                valid = false,
                verify_duration_ms,
                error = %error,
                "rpp-stark proof verification failed"
            );
        }
    }

    fn spawn_runtime(self: &Arc<Self>) -> JoinHandle<()> {
        let runner = Arc::clone(self);
        let shutdown = runner.subscribe_shutdown();
        let run_span = info_span!("runtime.node.run");
        let run_task = tokio::spawn(async move { runner.run(shutdown).await }.instrument(run_span));

        let completion = Arc::clone(self);
        let completion_span = info_span!("runtime.node.run.join");
        tokio::spawn(async move {
            match run_task.await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    warn!(?err, "node runtime exited with error");
                }
                Err(err) => {
                    warn!(?err, "node runtime join error");
                }
            }
            completion.drain_worker_tasks().await;
            completion.completion.notify_waiters();
        }
        .instrument(completion_span))
    }

    pub async fn start(
        config: NodeConfig,
        runtime_metrics: Arc<RuntimeMetrics>,
    ) -> ChainResult<(NodeHandle, JoinHandle<()>)> {
        let node = Node::new(config, Arc::clone(&runtime_metrics))?;
        let handle = node.handle();
        let runtime_config = handle.inner.runtime_config()?;
        let (p2p_inner, p2p_handle) =
            P2pRuntime::new(runtime_config).map_err(|err: P2pError| {
                ChainError::Config(format!("failed to initialise p2p runtime: {err}"))
            })?;
        let p2p_span = info_span!("runtime.p2p.run");
        let p2p_task = tokio::spawn(async move {
            if let Err(err) = p2p_inner.run().await {
                warn!(?err, "p2p runtime exited with error");
            }
        }
        .instrument(p2p_span));
        handle
            .inner
            .initialise_p2p_runtime(p2p_handle, Some(p2p_task))
            .await;
        let join = handle.inner.spawn_runtime();
        Ok((handle, join))
    }

    pub async fn stop(&self) -> ChainResult<()> {
        self.signal_shutdown();
        if let Some(runtime) = self.inner.p2p_runtime.lock().clone() {
            let _ = runtime.shutdown().await;
        }
        self.completion.notified().await;
        self.drain_worker_tasks().await;
        Ok(())
    }

    async fn run(self: Arc<Self>, mut shutdown: broadcast::Receiver<()>) -> ChainResult<()> {
        info!(
            address = %self.address,
            channel = ?self.config.rollout.release_channel,
            ?self.config.rollout.feature_gates,
            telemetry_enabled = self.config.rollout.telemetry.enabled,
            "starting node"
        );
        let mut ticker = time::interval(self.block_interval);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(err) = self.produce_block() {
                        warn!(?err, "block production failed");
                    }
                }
                result = shutdown.recv() => {
                    match result {
                        Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {
                            info!("node shutdown signal received");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            info!("node shutdown channel closed");
                        }
                    }
                    break;
                }
            }
        }
        Ok(())
    }

    async fn spawn_worker(&self, handle: JoinHandle<()>) {
        let mut workers = self.worker_tasks.lock().await;
        workers.push(handle);
    }

    async fn drain_worker_tasks(&self) {
        let mut workers = self.worker_tasks.lock().await;
        while let Some(handle) = workers.pop() {
            if let Err(err) = handle.await {
                if !err.is_cancelled() {
                    warn!(?err, "node worker task terminated unexpectedly");
                }
            }
        }
    }

    fn subscribe_shutdown(&self) -> broadcast::Receiver<()> {
        self.shutdown.subscribe()
    }

    fn signal_shutdown(&self) {
        let _ = self.shutdown.send(());
    }

    fn validator_telemetry(&self) -> ChainResult<ValidatorTelemetryView> {
        let rollout = self.rollout_status();
        let node = self.node_status()?;
        let consensus = ValidatorConsensusTelemetry::from(self.consensus_status()?);
        let mempool = ValidatorMempoolTelemetry::from(&node);
        let verifier_metrics = self.verifiers.metrics_snapshot();

        Ok(ValidatorTelemetryView {
            rollout,
            node,
            consensus,
            mempool,
            timetoke_params: self.ledger.timetoke_params(),
            verifier_metrics,
            pruning: self.pruning_status.read().clone(),
            vrf_threshold: self.vrf_threshold(),
        })
    }

    fn block_proofs(&self, height: u64) -> ChainResult<Option<BlockProofArtifactsView>> {
        let stored = self.storage.read_block_record(height)?;
        Ok(stored.map(|record| {
            let envelope = record.envelope;
            BlockProofArtifactsView {
                hash: envelope.hash.clone(),
                height,
                pruning_proof: envelope.pruning_proof.clone(),
                recursive_proof: envelope.recursive_proof.clone(),
                stark: envelope.stark.clone(),
                module_witnesses: envelope.module_witnesses.clone(),
                proof_artifacts: envelope.proof_artifacts.clone(),
                consensus_proof: envelope.consensus_proof.clone(),
                pruned: envelope.pruned,
            }
        }))
    }

    fn bft_membership(&self) -> ChainResult<BftMembership> {
        let accounts_snapshot = self.ledger.accounts_snapshot();
        let (validators, observers) = classify_participants(&accounts_snapshot);
        let validator_entries = validators
            .into_iter()
            .map(|candidate| ValidatorMembershipEntry {
                address: candidate.address,
                stake: candidate.stake,
                reputation_score: candidate.reputation_score,
                tier: candidate.tier,
                timetoke_hours: candidate.timetoke_hours,
            })
            .collect();
        let observer_entries = observers
            .into_iter()
            .map(|observer| ObserverMembershipEntry {
                address: observer.address,
                tier: observer.tier,
            })
            .collect();
        let epoch_info = self.ledger.epoch_info();
        let node_status = self.node_status()?;
        Ok(BftMembership {
            height: node_status.height,
            epoch: epoch_info.epoch,
            epoch_nonce: epoch_info.epoch_nonce,
            validators: validator_entries,
            observers: observer_entries,
        })
    }

    fn reconstruction_plan(&self, start_height: u64) -> ChainResult<ReconstructionPlan> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let engine = ReconstructionEngine::with_snapshot_dir(
            self.storage.clone(),
            self.config.snapshot_dir.clone(),
        );
        let plan = engine.plan_from_height(start_height)?;
        if let Some(path) = engine.persist_plan(&plan)? {
            info!(?path, "persisted reconstruction plan snapshot");
        }
        Ok(plan)
    }

    fn run_pruning_cycle(&self, chunk_size: usize) -> ChainResult<Option<PruningJobStatus>> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Ok(None);
        }
        let engine = ReconstructionEngine::with_snapshot_dir(
            self.storage.clone(),
            self.config.snapshot_dir.clone(),
        );
        let state_sync_plan = engine.state_sync_plan(chunk_size)?;
        let reconstruction_plan = engine.full_plan()?;
        let persisted_path = engine.persist_plan(&reconstruction_plan)?;
        let mut missing_heights = Vec::new();
        for chunk in &state_sync_plan.chunks {
            for request in &chunk.requests {
                missing_heights.push(request.height);
            }
        }
        let mut stored_proofs = Vec::new();
        for height in &missing_heights {
            match self.storage.read_block_record(*height)? {
                Some(record) => {
                    self.storage
                        .persist_pruning_proof(*height, &record.envelope.pruning_proof)?;
                    stored_proofs.push(*height);
                }
                None => {
                    warn!(height, "missing block record for pruning proof persistence");
                }
            }
        }
        let last_updated = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let status = PruningJobStatus {
            plan: state_sync_plan,
            missing_heights,
            persisted_path: persisted_path.map(|path| path.to_string_lossy().to_string()),
            stored_proofs,
            last_updated,
        };
        if let Some(path) = status.persisted_path.as_ref() {
            info!(?path, "persisted pruning snapshot plan");
        }
        if !status.missing_heights.is_empty() {
            debug!(
                heights = ?status.missing_heights,
                proofs = status.stored_proofs.len(),
                "pruning cycle identified missing history"
            );
        }
        {
            let mut slot = self.pruning_status.write();
            *slot = Some(status.clone());
        }
        self.emit_witness_json(GossipTopic::Snapshots, &status);
        Ok(Some(status))
    }

    fn pruning_job_status(&self) -> Option<PruningJobStatus> {
        self.pruning_status.read().clone()
    }

    fn state_sync_plan(&self, chunk_size: usize) -> ChainResult<StateSyncPlan> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let engine = ReconstructionEngine::new(self.storage.clone());
        engine.state_sync_plan(chunk_size)
    }

    fn network_state_sync_plan(&self, chunk_size: usize) -> ChainResult<NetworkStateSyncPlan> {
        let plan = self.state_sync_plan(chunk_size)?;
        plan.to_network_plan()
    }

    fn network_state_sync_chunk(
        &self,
        chunk_size: usize,
        start_height: u64,
    ) -> ChainResult<NetworkStateSyncChunk> {
        let plan = self.state_sync_plan(chunk_size)?;
        plan.chunk_message_for(start_height)
    }

    fn stream_state_sync_chunks(
        &self,
        store: &SnapshotStore,
        root: &Hash,
    ) -> ChainResult<SnapshotChunkStream> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        runtime_stream_state_sync_chunks(store, root)
            .map_err(|err| ChainError::Config(format!("failed to stream state sync chunks: {err}")))
    }

    fn state_sync_chunk_by_index(
        &self,
        store: &SnapshotStore,
        root: &Hash,
        index: u64,
    ) -> ChainResult<SnapshotChunk> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        runtime_state_sync_chunk_by_index(store, root, index).map_err(|err| {
            ChainError::Config(format!(
                "failed to fetch state sync chunk {index} for snapshot {root:?}: {err}"
            ))
        })
    }

    /// Returns a clone of the light client head subscription channel for external observers.
    ///
    /// The returned [`watch::Receiver`] is independent from the node's internal runtime handle,
    /// allowing callers to await updates without holding any locks on [`NodeInner`]. The
    /// underlying channel is multi-consumer, so each subscriber should clone the receiver before
    /// spawning tasks that await notifications.
    fn subscribe_light_client_heads(
        &self,
    ) -> ChainResult<watch::Receiver<Option<LightClientHead>>> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let handle = self
            .p2p_handle()
            .ok_or_else(|| ChainError::Config("p2p runtime not initialised".into()))?;
        Ok(handle.subscribe_light_client_heads())
    }

    fn latest_light_client_head(&self) -> ChainResult<Option<LightClientHead>> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let handle = self
            .p2p_handle()
            .ok_or_else(|| ChainError::Config("p2p runtime not initialised".into()))?;
        Ok(handle.latest_light_client_head())
    }

    fn verify_proof_chain(&self) -> ChainResult<()> {
        if !self.config.rollout.feature_gates.recursive_proofs {
            return Err(ChainError::Config(
                "recursive proof verification disabled by rollout".into(),
            ));
        }
        let engine = ReconstructionEngine::new(self.storage.clone());
        match engine.verify_proof_chain() {
            Ok(result) => Ok(result),
            Err(err) => {
                warn!(?err, "proof chain verification failed");
                Err(err)
            }
        }
    }

    fn reconstruct_block<P: PayloadProvider>(
        &self,
        height: u64,
        provider: &P,
    ) -> ChainResult<Block> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let engine = ReconstructionEngine::new(self.storage.clone());
        engine.reconstruct_block(height, provider)
    }

    fn reconstruct_range<P: PayloadProvider>(
        &self,
        start_height: u64,
        end_height: u64,
        provider: &P,
    ) -> ChainResult<Vec<Block>> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let engine = ReconstructionEngine::new(self.storage.clone());
        engine.reconstruct_range(start_height, end_height, provider)
    }

    fn execute_reconstruction_plan<P: PayloadProvider>(
        &self,
        plan: &ReconstructionPlan,
        provider: &P,
    ) -> ChainResult<Vec<Block>> {
        if !self.config.rollout.feature_gates.reconstruction {
            return Err(ChainError::Config(
                "reconstruction feature gate disabled".into(),
            ));
        }
        let engine = ReconstructionEngine::new(self.storage.clone());
        engine.execute_plan(plan, provider)
    }

    #[instrument(
        name = "runtime.wallet.rpc.submit_transaction",
        skip(self, bundle),
        fields(tx_hash = tracing::field::Empty, wallet = tracing::field::Empty),
        err
    )]
    fn submit_transaction(&self, bundle: TransactionProofBundle) -> ChainResult<String> {
        let tx_hash = bundle.hash();
        let wallet = bundle.transaction.payload.from.clone();
        let current = Span::current();
        current.record("tx_hash", &display(&tx_hash));
        current.record("wallet", &display(&wallet));
        let flow_span = wallet_rpc_flow_span("submit_transaction", &wallet, &tx_hash);
        let _guard = flow_span.enter();
        bundle.transaction.verify()?;
        if self.config.rollout.feature_gates.recursive_proofs {
            #[cfg(feature = "backend-rpp-stark")]
            {
                let verification = if let (Some(bytes), Some(inputs)) = (
                    bundle.stwo_proof_bytes(),
                    bundle.stwo_public_inputs(),
                ) {
                    let proof_bytes = ProofBytes(bytes.clone());
                    self.verifiers.verify_stwo_proof_bytes(&proof_bytes, inputs)
                } else {
                    match &bundle.proof {
                        ChainProof::RppStark(_) => self
                            .verify_rpp_stark_with_metrics(
                                ProofVerificationKind::Transaction,
                                &bundle.proof,
                            )
                            .map(|_| ()),
                        _ => self.verifiers.verify_transaction(&bundle.proof),
                    }
                };
                if let Err(err) = verification {
                    warn!(?err, "transaction proof rejected by verifier");
                    return Err(err);
                }
                if !matches!(bundle.proof, ChainProof::RppStark(_)) {
                    Self::ensure_transaction_payload(&bundle.proof, &bundle.transaction)?;
                }
            }
            #[cfg(not(feature = "backend-rpp-stark"))]
            {
                let verification = if let (Some(bytes), Some(inputs)) = (
                    bundle.stwo_proof_bytes(),
                    bundle.stwo_public_inputs(),
                ) {
                    let proof_bytes = ProofBytes(bytes.clone());
                    self.verifiers.verify_stwo_proof_bytes(&proof_bytes, inputs)
                } else {
                    self.verifiers.verify_transaction(&bundle.proof)
                };
                if let Err(err) = verification {
                    warn!(?err, "transaction proof rejected by verifier");
                    return Err(err);
                }
                Self::ensure_transaction_payload(&bundle.proof, &bundle.transaction)?;
            }
        }
        let mut mempool = self.mempool.write();
        if mempool.len() >= self.mempool_limit() {
            return Err(ChainError::Transaction("mempool full".into()));
        }
        let tx_payload = bundle.transaction.payload.clone();
        if mempool
            .iter()
            .any(|existing| existing.transaction.id == bundle.transaction.id)
        {
            return Err(ChainError::Transaction("transaction already queued".into()));
        }
        let metadata = PendingTransactionMetadata::from_bundle(&bundle);
        mempool.push_back(bundle);
        drop(mempool);
        {
            let mut metadata_store = self.pending_transaction_metadata.write();
            metadata_store.insert(tx_hash.clone(), metadata.clone());
        }
        let summary = PendingTransactionSummary {
            hash: tx_hash.clone(),
            from: tx_payload.from,
            to: tx_payload.to,
            amount: tx_payload.amount,
            fee: tx_payload.fee,
            nonce: tx_payload.nonce,
            proof: Some(metadata.proof.clone()),
            witness: metadata.witness.clone(),
            proof_payload: metadata.proof_payload.clone(),
            #[cfg(feature = "backend-rpp-stark")]
            public_inputs_digest: metadata.public_inputs_digest.clone(),
        };
        self.emit_witness_json(GossipTopic::WitnessProofs, &summary);
        Ok(tx_hash)
    }

    fn ensure_transaction_payload(
        proof: &ChainProof,
        expected: &SignedTransaction,
    ) -> ChainResult<()> {
        match proof {
            ChainProof::Stwo(stark) => match &stark.payload {
                ProofPayload::Transaction(witness) if &witness.signed_tx == expected => Ok(()),
                ProofPayload::Transaction(_) => Err(ChainError::Crypto(
                    "transaction proof does not match submitted transaction".into(),
                )),
                _ => Err(ChainError::Crypto(
                    "transaction proof payload mismatch".into(),
                )),
            },
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(value) => {
                let witness_value = value
                    .get("public_inputs")
                    .and_then(|inputs| inputs.get("witness"))
                    .cloned()
                    .ok_or_else(|| {
                        ChainError::Crypto(
                            "plonky3 transaction proof missing witness payload".into(),
                        )
                    })?;
                let witness: Plonky3TransactionWitness = serde_json::from_value(witness_value)
                    .map_err(|err| {
                        ChainError::Crypto(format!(
                            "failed to decode plonky3 transaction witness: {err}"
                        ))
                    })?;
                if &witness.transaction == expected {
                    Ok(())
                } else {
                    Err(ChainError::Crypto(
                        "transaction proof does not match submitted transaction".into(),
                    ))
                }
            }
        }
    }

    fn purge_transaction_metadata(&self, bundles: &[TransactionProofBundle]) {
        if bundles.is_empty() {
            return;
        }
        let mut metadata = self.pending_transaction_metadata.write();
        for bundle in bundles {
            metadata.remove(&bundle.hash());
        }
    }

    fn submit_identity(&self, request: AttestedIdentityRequest) -> ChainResult<String> {
        let next_height = self.chain_tip.read().height.saturating_add(1);
        self.ledger.sync_epoch_for_height(next_height);
        if self.config.rollout.feature_gates.recursive_proofs {
            if let Err(err) = self
                .verifiers
                .verify_identity(&request.declaration.proof.zk_proof)
            {
                warn!(
                    wallet = %request.declaration.genesis.wallet_addr,
                    ?err,
                    "identity proof rejected by verifier"
                );
                return Err(err);
            }
        }
        self.validate_identity_attestation(&request, next_height)?;
        let declaration = &request.declaration;
        let expected_epoch_nonce = hex::encode(self.ledger.current_epoch_nonce());
        if expected_epoch_nonce != declaration.genesis.epoch_nonce {
            return Err(ChainError::Transaction(
                "identity declaration references an outdated epoch nonce".into(),
            ));
        }

        let expected_state_root = hex::encode(self.ledger.state_root());
        if expected_state_root != declaration.genesis.state_root {
            return Err(ChainError::Transaction(
                "identity declaration references an outdated state root".into(),
            ));
        }
        let expected_identity_root = hex::encode(self.ledger.identity_root());
        if expected_identity_root != declaration.genesis.identity_root {
            return Err(ChainError::Transaction(
                "identity declaration references an outdated identity root".into(),
            ));
        }

        let hash = request.identity_hash()?;
        let mut mempool = self.identity_mempool.write();
        if mempool.len() >= self.mempool_limit() {
            return Err(ChainError::Transaction("identity mempool full".into()));
        }
        if mempool.iter().any(|existing| {
            existing.declaration.genesis.wallet_addr == declaration.genesis.wallet_addr
        }) {
            return Err(ChainError::Transaction(
                "identity for this wallet already queued".into(),
            ));
        }
        if mempool
            .iter()
            .any(|existing| existing.identity_hash().ok().as_deref() == Some(hash.as_str()))
        {
            return Err(ChainError::Transaction(
                "identity request already queued for attestation".into(),
            ));
        }
        mempool.push_back(request);
        Ok(hash)
    }

    #[instrument(
        name = "node.consensus.queue_vote",
        skip(self, vote),
        fields(
            height = vote.vote.height,
            round = vote.vote.round,
            voter = %vote.vote.voter,
            kind = ?vote.vote.kind
        )
    )]
    fn submit_vote(&self, vote: SignedBftVote) -> ChainResult<String> {
        if self.config.rollout.feature_gates.consensus_enforcement {
            vote.verify()?;
        }
        let next_height = self.chain_tip.read().height.saturating_add(1);
        if vote.vote.height < next_height {
            return Err(ChainError::Transaction(
                "vote references an already finalized height".into(),
            ));
        }
        if let Some(evidence) = self.evidence_pool.write().record_vote(&vote) {
            self.apply_evidence(evidence);
            return Err(ChainError::Transaction(
                "conflicting vote detected for validator".into(),
            ));
        }
        self.observe_consensus_round(vote.vote.height, vote.vote.round);
        let mut mempool = self.vote_mempool.write();
        if mempool.len() >= self.mempool_limit() {
            return Err(ChainError::Transaction("vote mempool full".into()));
        }
        let vote_hash = vote.hash();
        let vote_summary = serde_json::json!({
            "hash": vote_hash.clone(),
            "voter": vote.vote.voter.clone(),
            "height": vote.vote.height,
            "round": vote.vote.round,
            "kind": vote.vote.kind,
        });
        if mempool.iter().any(|existing| existing.hash() == vote_hash) {
            return Err(ChainError::Transaction("vote already queued".into()));
        }
        mempool.push_back(vote);
        self.emit_witness_json(GossipTopic::Votes, &vote_summary);
        Ok(vote_hash)
    }

    fn validate_identity_attestation(
        &self,
        request: &AttestedIdentityRequest,
        expected_height: u64,
    ) -> ChainResult<()> {
        request.declaration.verify()?;
        let identity_hash = request.identity_hash()?;
        let mut voters = HashSet::new();
        for vote in &request.attested_votes {
            if let Err(err) = vote.verify() {
                self.punish_invalid_identity(
                    &vote.vote.voter,
                    "invalid identity attestation signature",
                );
                return Err(err);
            }
            if vote.vote.block_hash != identity_hash {
                self.punish_invalid_identity(
                    &vote.vote.voter,
                    "identity attestation references mismatched hash",
                );
                return Err(ChainError::Transaction(
                    "identity attestation vote references mismatched request".into(),
                ));
            }
            if vote.vote.height != expected_height {
                self.punish_invalid_identity(
                    &vote.vote.voter,
                    "identity attestation references wrong height",
                );
                return Err(ChainError::Transaction(
                    "identity attestation vote references unexpected height".into(),
                ));
            }
            if vote.vote.kind != BftVoteKind::PreCommit {
                self.punish_invalid_identity(
                    &vote.vote.voter,
                    "identity attestation wrong vote kind",
                );
                return Err(ChainError::Transaction(
                    "identity attestation must be composed of pre-commit votes".into(),
                ));
            }
            if !voters.insert(vote.vote.voter.clone()) {
                return Err(ChainError::Transaction(
                    "duplicate attestation vote detected for identity request".into(),
                ));
            }
        }
        if voters.len() < IDENTITY_ATTESTATION_QUORUM {
            return Err(ChainError::Transaction(
                "insufficient quorum power for identity attestation".into(),
            ));
        }
        let mut gossip = HashSet::new();
        for address in &request.gossip_confirmations {
            gossip.insert(address.clone());
        }
        if gossip.len() < IDENTITY_ATTESTATION_GOSSIP_MIN {
            return Err(ChainError::Transaction(
                "insufficient gossip confirmations for identity attestation".into(),
            ));
        }
        Ok(())
    }

    fn punish_invalid_identity(&self, address: &str, context: &str) {
        if !self.config.rollout.feature_gates.consensus_enforcement {
            return;
        }
        if let Err(err) = self.slash_validator(address, SlashingReason::InvalidIdentity) {
            warn!(
                offender = %address,
                ?err,
                context,
                "failed to slash validator for invalid identity attestation"
            );
        }
    }

    fn punish_invalid_proof(&self, address: &Address, height: u64, round: u64) {
        if !self.config.rollout.feature_gates.consensus_enforcement {
            return;
        }
        let evidence = {
            let mut pool = self.evidence_pool.write();
            pool.record_invalid_proof(address, height, round)
        };
        self.apply_evidence(evidence);
    }

    fn handle_invalid_block_gossip(&self, peer: &PeerId, block: Block, reason: &str) {
        warn!(
            target: "node",
            %peer,
            height = block.header.height,
            round = block.consensus.round,
            proposer = %block.header.proposer,
            reason = %reason,
            "invalid block gossip detected"
        );
        let evidence = {
            let mut pool = self.evidence_pool.write();
            pool.record_invalid_proposal(
                &block.header.proposer,
                block.header.height,
                block.consensus.round,
                Some(block.hash.clone()),
            )
        };
        self.apply_evidence(evidence);
    }

    fn handle_invalid_vote_gossip(&self, peer: &PeerId, vote: SignedBftVote, reason: &str) {
        warn!(
            target: "node",
            %peer,
            height = vote.vote.height,
            round = vote.vote.round,
            voter = %vote.vote.voter,
            reason = %reason,
            "invalid vote gossip detected"
        );
        self.punish_invalid_proof(&vote.vote.voter, vote.vote.height, vote.vote.round);
        self.consensus_telemetry
            .record_failed_vote(format!("invalid_gossip:{reason}"));
        self.update_runtime_metrics();
    }

    fn record_double_spend_if_applicable(&self, block: &Block, round: u64, err: &ChainError) {
        if !self.config.rollout.feature_gates.consensus_enforcement {
            return;
        }
        if !is_double_spend(err) {
            return;
        }
        let evidence = {
            let mut pool = self.evidence_pool.write();
            pool.record_invalid_proposal(
                &block.header.proposer,
                block.header.height,
                round,
                Some(block.hash.clone()),
            )
        };
        self.apply_evidence(evidence);
    }

    fn submit_block_proposal(&self, block: Block) -> ChainResult<String> {
        let height = block.header.height;
        let round = block.consensus.round;
        let proposer = block.header.proposer.clone();
        let previous_block = if height == 0 {
            None
        } else {
            self.storage.read_block(height - 1)?
        };
        let proposer_key = self.ledger.validator_public_key(&proposer)?;
        match block.verify_without_stark(previous_block.as_ref(), &proposer_key) {
            Ok(()) => {
                let hash = block.hash.clone();
                self.observe_consensus_round(height, round);
                let mut inbox = self.proposal_inbox.write();
                let block_summary = serde_json::json!({
                    "hash": hash.clone(),
                    "height": block.header.height,
                    "round": block.consensus.round,
                    "proposer": block.header.proposer.clone(),
                });
                inbox.insert((height, proposer), VerifiedProposal { block });
                self.emit_witness_json(GossipTopic::Blocks, &block_summary);
                Ok(hash)
            }
            Err(err) => {
                let evidence = self.evidence_pool.write().record_invalid_proposal(
                    &proposer,
                    height,
                    round,
                    Some(block.hash.clone()),
                );
                self.apply_evidence(evidence);
                Err(err)
            }
        }
    }

    #[instrument(
        name = "node.consensus.apply_evidence",
        skip(self, evidence),
        fields(
            address = %evidence.address,
            height = evidence.height,
            round = evidence.round,
            kind = ?evidence.kind
        )
    )]
    fn apply_evidence(&self, evidence: EvidenceRecord) {
        let (reason, reason_label) = match evidence.kind {
            EvidenceKind::DoubleSignPrevote | EvidenceKind::DoubleSignPrecommit => {
                (SlashingReason::ConsensusFault, "double-sign")
            }
            EvidenceKind::InvalidProof => (SlashingReason::InvalidVote, "invalid-proof"),
            EvidenceKind::InvalidProposal => (SlashingReason::ConsensusFault, "invalid-proposal"),
        };
        if let Err(err) = self.slash_validator(&evidence.address, reason) {
            warn!(
                address = %evidence.address,
                ?err,
                reason = reason_label,
                "failed to apply slashing evidence"
            );
            return;
        }
        debug!(
            address = %evidence.address,
            height = evidence.height,
            round = evidence.round,
            reason = reason_label,
            "recorded consensus evidence"
        );
        self.emit_witness_json(GossipTopic::WitnessMeta, &evidence);
        if let Some(vote_kind) = evidence.vote_kind {
            let mut mempool = self.vote_mempool.write();
            mempool.retain(|vote| {
                !(vote.vote.voter == evidence.address
                    && vote.vote.height == evidence.height
                    && vote.vote.round == evidence.round
                    && vote.vote.kind == vote_kind)
            });
        }
    }

    fn submit_vrf_submission(&self, submission: VrfSubmission) -> ChainResult<()> {
        let address = submission.address.clone();
        let epoch = submission.input.epoch;
        verify_submission(&submission)?;
        {
            let mut epoch_manager = self.vrf_epoch.write();
            if !epoch_manager.register_submission(&submission) {
                debug!(address = %address, epoch, "duplicate VRF submission ignored");
                return Ok(());
            }
        }
        let mut pool = self.vrf_mempool.write();
        if let Some(existing) = pool.get(&address) {
            if existing.input != submission.input {
                debug!(
                    address = %address,
                    prev_epoch = existing.input.epoch,
                    new_epoch = epoch,
                    "updated VRF submission"
                );
            }
        } else {
            debug!(address = %address, epoch, "recorded VRF submission");
        }
        let local_payload = if address == self.address {
            Some(submission_to_gossip(&submission))
        } else {
            None
        };
        vrf::submit_vrf(&mut pool, submission);
        if let Some(payload) = local_payload {
            self.emit_witness_json(GossipTopic::VrfProofs, &payload);
        }
        Ok(())
    }

    fn submit_uptime_proof(&self, proof: UptimeProof) -> ChainResult<u64> {
        let credited = self.ledger.apply_uptime_proof(&proof)?;
        if let Some(account) = self.ledger.get_account(&proof.wallet_address) {
            self.storage.persist_account(&account)?;
        }
        {
            let mut queue = self.uptime_mempool.write();
            queue.push_back(RecordedUptimeProof {
                proof: proof.clone(),
                credited_hours: credited,
            });
        }
        Ok(credited)
    }

    fn timetoke_snapshot(&self) -> ChainResult<Vec<TimetokeRecord>> {
        let records = self.ledger.timetoke_snapshot();
        let addresses: Vec<Address> = records
            .iter()
            .map(|record| record.identity.clone())
            .collect();
        self.persist_timetoke_accounts(&addresses)?;
        self.emit_witness_json(GossipTopic::Snapshots, &records);
        self.emit_timetoke_meta(&records);
        Ok(records)
    }

    fn sync_timetoke_records(&self, records: Vec<TimetokeRecord>) -> ChainResult<Vec<Address>> {
        let updated = self.ledger.sync_timetoke_records(&records)?;
        self.persist_timetoke_accounts(&updated)?;
        if !updated.is_empty() {
            self.emit_witness_json(GossipTopic::Snapshots, &updated);
        }
        self.emit_timetoke_meta(&records);
        Ok(updated)
    }

    fn get_block(&self, height: u64) -> ChainResult<Option<Block>> {
        self.storage.read_block(height)
    }

    fn latest_block(&self) -> ChainResult<Option<Block>> {
        let tip_height = self.chain_tip.read().height;
        self.storage.read_block(tip_height)
    }

    fn get_account(&self, address: &str) -> ChainResult<Option<Account>> {
        Ok(self.ledger.get_account(address))
    }

    fn node_status(&self) -> ChainResult<NodeStatus> {
        let tip = self.chain_tip.read().clone();
        let epoch_info: EpochInfo = self.ledger.epoch_info();
        let metadata = self.storage.tip()?;
        Ok(NodeStatus {
            address: self.address.clone(),
            height: tip.height,
            last_hash: hex::encode(tip.last_hash),
            epoch: epoch_info.epoch,
            epoch_nonce: epoch_info.epoch_nonce,
            pending_transactions: self.mempool.read().len(),
            pending_identities: self.identity_mempool.read().len(),
            pending_votes: self.vote_mempool.read().len(),
            pending_uptime_proofs: self.uptime_mempool.read().len(),
            vrf_metrics: self.vrf_metrics.read().clone(),
            tip: metadata,
        })
    }

    fn vrf_threshold(&self) -> VrfThresholdStatus {
        self.vrf_threshold.read().clone()
    }

    fn mempool_status(&self) -> ChainResult<MempoolStatus> {
        let mempool = self.mempool.read();
        let metadata_store = self.pending_transaction_metadata.read();
        let transactions = mempool
            .iter()
            .map(|bundle| {
                let hash = bundle.hash();
                let payload = bundle.transaction.payload.clone();
                let metadata = metadata_store
                    .get(&hash)
                    .cloned()
                    .unwrap_or_else(|| PendingTransactionMetadata::from_bundle(bundle));
                PendingTransactionSummary {
                    hash,
                    from: payload.from,
                    to: payload.to,
                    amount: payload.amount,
                    fee: payload.fee,
                    nonce: payload.nonce,
                    proof: Some(metadata.proof),
                    witness: metadata.witness,
                    proof_payload: metadata.proof_payload,
                    #[cfg(feature = "backend-rpp-stark")]
                    public_inputs_digest: metadata.public_inputs_digest,
                }
            })
            .collect();
        let identities = self
            .identity_mempool
            .read()
            .iter()
            .map(|request| PendingIdentitySummary {
                wallet_addr: request.declaration.genesis.wallet_addr.clone(),
                commitment: request.declaration.commitment().to_string(),
                epoch_nonce: request.declaration.genesis.epoch_nonce.clone(),
                state_root: request.declaration.genesis.state_root.clone(),
                identity_root: request.declaration.genesis.identity_root.clone(),
                vrf_tag: request.declaration.genesis.vrf_tag().to_string(),
                attested_votes: request.attested_votes.len(),
                gossip_confirmations: request.gossip_confirmations.len(),
            })
            .collect();
        let votes = self
            .vote_mempool
            .read()
            .iter()
            .map(|vote| PendingVoteSummary {
                hash: vote.hash(),
                voter: vote.vote.voter.clone(),
                height: vote.vote.height,
                round: vote.vote.round,
                block_hash: vote.vote.block_hash.clone(),
                kind: vote.vote.kind,
            })
            .collect();
        let uptime_proofs = self
            .uptime_mempool
            .read()
            .iter()
            .map(|record| PendingUptimeSummary {
                identity: record.proof.wallet_address.clone(),
                window_start: record.proof.window_start,
                window_end: record.proof.window_end,
                credited_hours: record.credited_hours,
            })
            .collect();
        Ok(MempoolStatus {
            transactions,
            identities,
            votes,
            uptime_proofs,
            queue_weights: self.queue_weights(),
        })
    }

    fn rollout_status(&self) -> RolloutStatus {
        RolloutStatus {
            release_channel: self.config.rollout.release_channel,
            feature_gates: self.config.rollout.feature_gates.clone(),
            telemetry: TelemetryRuntimeStatus {
                enabled: self.config.rollout.telemetry.enabled,
                endpoint: self.config.rollout.telemetry.endpoint.clone(),
                sample_interval_secs: self.config.rollout.telemetry.sample_interval_secs,
                last_observed_height: None,
            },
        }
    }

    fn consensus_status(&self) -> ChainResult<ConsensusStatus> {
        let tip = self.chain_tip.read().clone();
        let block = self.storage.read_block(tip.height)?;
        let epoch_info = self.ledger.epoch_info();
        let pending_votes = self.vote_mempool.read().len();
        let telemetry = self.consensus_telemetry.snapshot();
        let (
            block_hash,
            proposer,
            round,
            total_power,
            quorum_threshold,
            pre_vote_power,
            pre_commit_power,
            commit_power,
            observers,
            quorum_reached,
        ) = if let Some(block) = block.as_ref() {
            let certificate = &block.consensus;
            let commit = Natural::from_str(&certificate.commit_power)
                .unwrap_or_else(|_| Natural::from(0u32));
            let quorum = Natural::from_str(&certificate.quorum_threshold)
                .unwrap_or_else(|_| Natural::from(0u32));
            (
                Some(block.hash.clone()),
                Some(block.header.proposer.clone()),
                certificate.round,
                certificate.total_power.clone(),
                certificate.quorum_threshold.clone(),
                certificate.pre_vote_power.clone(),
                certificate.pre_commit_power.clone(),
                certificate.commit_power.clone(),
                certificate.observers,
                commit >= quorum && commit > Natural::from(0u32),
            )
        } else {
            (
                None,
                None,
                0,
                "0".to_string(),
                "0".to_string(),
                "0".to_string(),
                "0".to_string(),
                "0".to_string(),
                0,
                false,
            )
        };

        Ok(ConsensusStatus {
            height: tip.height,
            block_hash,
            proposer,
            round,
            total_power,
            quorum_threshold,
            pre_vote_power,
            pre_commit_power,
            commit_power,
            quorum_reached,
            observers,
            epoch: epoch_info.epoch,
            epoch_nonce: epoch_info.epoch_nonce,
            pending_votes,
            round_latencies_ms: telemetry.round_latencies_ms,
            leader_changes: telemetry.leader_changes,
            quorum_latency_ms: telemetry.quorum_latency_ms,
            witness_events: telemetry.witness_events,
            slashing_events: telemetry.slashing_events,
            failed_votes: telemetry.failed_votes,
        })
    }

    fn vrf_status(&self, address: &str) -> ChainResult<VrfStatus> {
        let epoch_info = self.ledger.epoch_info();
        let nonce = self.ledger.current_epoch_nonce();
        let proof = evaluate_vrf(
            &nonce,
            0,
            &address.to_string(),
            0,
            Some(&self.vrf_keypair.secret),
        )?;
        Ok(VrfStatus {
            address: address.to_string(),
            epoch: epoch_info.epoch,
            epoch_nonce: epoch_info.epoch_nonce,
            public_key: vrf_public_key_to_hex(&self.vrf_keypair.public),
            proof,
        })
    }

    fn vrf_history(&self, epoch: Option<u64>) -> ChainResult<Vec<VrfHistoryRecord>> {
        Ok(self.ledger.vrf_history(epoch))
    }

    fn slashing_events(&self, limit: usize) -> ChainResult<Vec<SlashingEvent>> {
        Ok(self.ledger.slashing_events(limit))
    }

    fn reputation_audit(&self, address: &str) -> ChainResult<Option<ReputationAudit>> {
        let audit = self.ledger.reputation_audit(address)?;
        Ok(audit.map(|mut audit| {
            self.sign_reputation_audit(&mut audit);
            audit
        }))
    }

    fn recent_slashing_audits(&self, limit: usize) -> ChainResult<Vec<SlashingEvent>> {
        self.audit_exporter.recent_slashing(limit)
    }

    fn recent_reputation_audits(&self, limit: usize) -> ChainResult<Vec<ReputationAudit>> {
        self.audit_exporter.recent_reputation(limit)
    }

    fn build_local_vote(
        &self,
        height: u64,
        round: u64,
        block_hash: &str,
        kind: BftVoteKind,
    ) -> SignedBftVote {
        let vote = BftVote {
            round,
            height,
            block_hash: block_hash.to_string(),
            voter: self.address.clone(),
            kind,
        };
        let signature = sign_message(&self.keypair, &vote.message_bytes());
        SignedBftVote {
            vote,
            public_key: hex::encode(self.keypair.public.to_bytes()),
            signature: signature_to_hex(&signature),
        }
    }

    fn gather_vrf_submissions(
        &self,
        epoch: u64,
        seed: [u8; 32],
        candidates: &[ValidatorCandidate],
    ) -> VrfSubmissionPool {
        let candidate_addresses: HashSet<Address> = candidates
            .iter()
            .map(|candidate| candidate.address.clone())
            .collect();
        let mut pool = {
            let mut mempool = self.vrf_mempool.write();
            mempool.retain(|address, submission| {
                submission.input.epoch == epoch
                    && submission.input.last_block_header == seed
                    && candidate_addresses.contains(address)
            });
            mempool.clone()
        };

        for candidate in candidates {
            if candidate.address != self.address {
                continue;
            }
            let tier_seed = vrf::derive_tier_seed(&candidate.address, candidate.timetoke_hours);
            let input = PoseidonVrfInput::new(seed, epoch, tier_seed);
            match vrf::generate_vrf(&input, &self.vrf_keypair.secret) {
                Ok(output) => {
                    let submission = VrfSubmission {
                        address: candidate.address.clone(),
                        public_key: Some(self.vrf_keypair.public.clone()),
                        input,
                        proof: VrfProof::from_output(&output),
                        tier: candidate.tier.clone(),
                        timetoke_hours: candidate.timetoke_hours,
                    };
                    vrf::submit_vrf(&mut pool, submission.clone());
                    if let Err(err) = self.submit_vrf_submission(submission) {
                        warn!(
                            address = %candidate.address,
                            ?err,
                            "failed to persist local VRF submission"
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        address = %candidate.address,
                        ?err,
                        "failed to produce local VRF submission"
                    );
                }
            }
        }
        pool
    }

    fn slash_validator(&self, address: &str, reason: SlashingReason) -> ChainResult<()> {
        let event = self
            .ledger
            .slash_validator(address, reason, Some(&self.keypair))?;
        self.audit_exporter.export_slashing(&event)?;
        self.consensus_telemetry
            .record_slashing(format!("{:?}", event.reason));
        self.update_runtime_metrics();
        self.maybe_refresh_local_identity(address);
        Ok(())
    }

    fn sign_reputation_audit(&self, audit: &mut ReputationAudit) {
        if audit.signature.is_some() {
            return;
        }
        let signature = sign_message(&self.keypair, audit.evidence_hash.as_bytes());
        audit.signature = Some(signature_to_hex(&signature));
    }

    fn maybe_refresh_local_identity(&self, address: &str) {
        if address != self.address {
            return;
        }
        self.update_runtime_metrics();
        self.refresh_local_network_identity();
    }

    fn refresh_local_network_identity(&self) {
        let profile = match self.network_identity_profile() {
            Ok(profile) => profile,
            Err(err) => {
                warn!(
                    ?err,
                    "failed to collect network identity profile for refresh"
                );
                return;
            }
        };
        let Some(handle) = self.p2p_runtime.lock().clone() else {
            debug!(tier = ?profile.tier, "p2p runtime not initialised; skipping identity refresh");
            return;
        };
        if tokio::runtime::Handle::try_current().is_err() {
            warn!(tier = ?profile.tier, "no async runtime available for identity refresh");
            return;
        }
        let tier = profile.tier;
        let runtime_profile = RuntimeIdentityProfile::from(profile);
        let refresh_span = info_span!("runtime.identity.refresh", tier = ?tier);
        tokio::spawn(async move {
            if let Err(err) = handle.update_identity(runtime_profile).await {
                warn!(?err, tier = ?tier, "failed to update libp2p identity profile");
            } else {
                debug!(tier = ?tier, "updated libp2p identity profile");
            }
        }
        .instrument(refresh_span));
    }

    fn drain_votes_for(&self, height: u64, block_hash: &str) -> Vec<SignedBftVote> {
        let mut mempool = self.vote_mempool.write();
        let mut retained = VecDeque::new();
        let mut matched = Vec::new();
        while let Some(vote) = mempool.pop_front() {
            if vote.vote.height == height && vote.vote.block_hash == block_hash {
                matched.push(vote);
            } else {
                retained.push_back(vote);
            }
        }
        *mempool = retained;
        matched
    }

    fn current_consensus_round(&self, height: u64) -> u64 {
        self.consensus_rounds
            .read()
            .get(&height)
            .copied()
            .unwrap_or(0)
    }

    fn observe_consensus_round(&self, height: u64, round: u64) {
        let mut rounds = self.consensus_rounds.write();
        let entry = rounds.entry(height).or_insert(round);
        if round > *entry {
            *entry = round;
        }
    }

    fn prune_consensus_rounds_below(&self, threshold_height: u64) {
        self.consensus_rounds
            .write()
            .retain(|&tracked_height, _| tracked_height >= threshold_height);
    }

    fn take_verified_proposal(&self, height: u64, proposer: &Address) -> Option<Block> {
        let mut inbox = self.proposal_inbox.write();
        inbox
            .remove(&(height, proposer.clone()))
            .map(|proposal| proposal.block)
    }

    #[cfg(feature = "prover-stwo")]
    fn map_backend_error(err: crate::proof_backend::BackendError) -> ChainError {
        match err {
            crate::proof_backend::BackendError::Failure(message) => ChainError::Crypto(message),
            crate::proof_backend::BackendError::Unsupported(context) => {
                ChainError::Crypto(format!("STWO backend unsupported: {context}"))
            }
            crate::proof_backend::BackendError::Serialization(err) => {
                ChainError::Crypto(format!("failed to encode STWO payload: {err}"))
            }
        }
    }

    #[cfg(feature = "prover-stwo")]
    #[allow(clippy::too_many_arguments)]
    fn generate_local_block_proofs(
        storage: &Storage,
        ledger: &Ledger,
        header: &BlockHeader,
        commitments: &GlobalStateCommitments,
        pruning_proof: &PruningProof,
        accepted_identities: &[AttestedIdentityRequest],
        transactions: &[SignedTransaction],
        transaction_proofs: Vec<ChainProof>,
        identity_proofs: &[ChainProof],
        uptime_proofs: &[UptimeProof],
        previous_block: Option<&Block>,
        consensus_certificate: Option<&ConsensusCertificate>,
        block_hash: Option<&str>,
        max_proof_size_bytes: usize,
    ) -> ChainResult<LocalProofArtifacts> {
        let prover = WalletProver::new(storage);
        let backend = StwoBackend::new();
        let backend_kind = ProofSystemKind::Stwo;

        let previous_state_root_hex = pruning_proof.snapshot_state_root_hex();
        let state_witness = {
            let span = proof_operation_span(
                "build_state_witness",
                backend_kind,
                Some(header.height),
                block_hash,
            );
            let _guard = span.enter();
            prover.build_state_witness(
                &previous_state_root_hex,
                &header.state_root,
                accepted_identities,
                transactions,
            )?
        };
        let state_bytes = WitnessBytes::encode(
            &WitnessHeader::new(ProofSystemKind::Stwo, "state"),
            &state_witness,
        )
        .map_err(Self::map_backend_error)?;
        let (state_pk, _) = backend
            .keygen_state(&StateCircuitDef::new("state"))
            .map_err(Self::map_backend_error)?;
        let state_proof_bytes = {
            let span = proof_operation_span(
                "prove_state_transition",
                backend_kind,
                Some(header.height),
                block_hash,
            );
            let _guard = span.enter();
            backend
                .prove_state(&state_pk, &state_bytes)
                .map_err(Self::map_backend_error)?
        };
        let state_stark = decode_state_proof(&state_proof_bytes).map_err(Self::map_backend_error)?;
        let state_chain_proof = ChainProof::Stwo(state_stark);

        let previous_transactions = previous_block
            .map(|block| block.transactions.clone())
            .unwrap_or_default();
        let previous_identities = previous_block
            .map(|block| block.identities.clone())
            .unwrap_or_default();
        let pruning_witness = {
            let span = proof_operation_span(
                "build_pruning_witness",
                backend_kind,
                Some(header.height),
                block_hash,
            );
            let _guard = span.enter();
            prover.build_pruning_witness(
                &previous_identities,
                &previous_transactions,
                pruning_proof,
                Vec::new(),
            )?
        };
        let pruning_bytes = WitnessBytes::encode(
            &WitnessHeader::new(ProofSystemKind::Stwo, "pruning"),
            &pruning_witness,
        )
        .map_err(Self::map_backend_error)?;
        let (pruning_pk, _) = backend
            .keygen_pruning(&PruningCircuitDef::new("pruning"))
            .map_err(Self::map_backend_error)?;
        let pruning_proof_bytes = {
            let span = proof_operation_span(
                "prove_pruning",
                backend_kind,
                Some(header.height),
                block_hash,
            );
            let _guard = span.enter();
            backend
                .prove_pruning(&pruning_pk, &pruning_bytes)
                .map_err(Self::map_backend_error)?
        };
        let pruning_stark =
            decode_pruning_proof(&pruning_proof_bytes).map_err(Self::map_backend_error)?;
        let pruning_chain_proof = ChainProof::Stwo(pruning_stark);

        let previous_recursive = previous_block.map(|block| &block.stark.recursive_proof);

        let uptime_chain_proofs: Vec<ChainProof> = uptime_proofs
            .iter()
            .map(|proof| {
                proof.proof.clone().ok_or_else(|| {
                    ChainError::Crypto("uptime proof missing zk proof payload".into())
                })
            })
            .collect::<ChainResult<_>>()?;

        let mut consensus_chain_proof = None;
        if let Some(certificate) = consensus_certificate {
            let block_hash = block_hash.expect("consensus block hash must be present");
            let consensus_witness = {
                let span = proof_operation_span(
                    "build_consensus_witness",
                    backend_kind,
                    Some(header.height),
                    Some(block_hash),
                );
                let _guard = span.enter();
                prover.build_consensus_witness(block_hash, certificate)?
            };
            let consensus_bytes = WitnessBytes::encode(
                &WitnessHeader::new(ProofSystemKind::Stwo, "consensus"),
                &consensus_witness,
            )
            .map_err(Self::map_backend_error)?;
            let (consensus_proof_bytes, _vk, _circuit) = {
                let span = proof_operation_span(
                    "prove_consensus",
                    backend_kind,
                    Some(header.height),
                    Some(block_hash),
                );
                let _guard = span.enter();
                backend
                    .prove_consensus(&consensus_bytes)
                    .map_err(Self::map_backend_error)?
            };
            let (_, consensus_stark) =
                decode_consensus_proof(&consensus_proof_bytes).map_err(Self::map_backend_error)?;
            consensus_chain_proof = Some(ChainProof::Stwo(consensus_stark));
        }

        let mut consensus_chain_proofs = Vec::new();
        if let Some(proof) = consensus_chain_proof.as_ref() {
            consensus_chain_proofs.push(proof.clone());
        }

        let recursive_witness = {
            let span = proof_operation_span(
                "build_recursive_witness",
                backend_kind,
                Some(header.height),
                block_hash,
            );
            let _guard = span.enter();
            prover.build_recursive_witness(
                previous_recursive,
                identity_proofs,
                &transaction_proofs,
                &uptime_chain_proofs,
                &consensus_chain_proofs,
                commitments,
                &state_chain_proof,
                &pruning_chain_proof,
                header.height,
            )?
        };
        let recursive_bytes = WitnessBytes::encode(
            &WitnessHeader::new(ProofSystemKind::Stwo, "recursive"),
            &recursive_witness,
        )
        .map_err(Self::map_backend_error)?;
        let (recursive_pk, _) = backend
            .keygen_recursive(&RecursiveCircuitDef::new("recursive"))
            .map_err(Self::map_backend_error)?;
        let recursive_proof_bytes = {
            let span = proof_operation_span(
                "prove_recursive",
                backend_kind,
                Some(header.height),
                block_hash,
            );
            let _guard = span.enter();
            backend
                .prove_recursive(&recursive_pk, &recursive_bytes)
                .map_err(Self::map_backend_error)?
        };
        let recursive_stark =
            decode_recursive_proof(&recursive_proof_bytes).map_err(Self::map_backend_error)?;
        let recursive_chain_proof = ChainProof::Stwo(recursive_stark);

        let bundle = BlockProofBundle::new(
            transaction_proofs,
            state_chain_proof.clone(),
            pruning_chain_proof.clone(),
            recursive_chain_proof.clone(),
        );

        let module_witnesses = ledger.drain_module_witnesses();
        let module_artifacts = ledger.stage_module_witnesses(&module_witnesses)?;
        let mut proof_artifacts =
            Self::collect_proof_artifacts(&bundle, max_proof_size_bytes)?;
        proof_artifacts.extend(module_artifacts);

        Ok(LocalProofArtifacts {
            bundle,
            consensus_proof: consensus_chain_proof,
            module_witnesses,
            proof_artifacts,
        })
    }

    #[cfg(not(feature = "prover-stwo"))]
    #[allow(clippy::too_many_arguments)]
    fn generate_local_block_proofs(
        storage: &Storage,
        ledger: &Ledger,
        header: &BlockHeader,
        commitments: &GlobalStateCommitments,
        pruning_proof: &PruningProof,
        accepted_identities: &[AttestedIdentityRequest],
        transactions: &[SignedTransaction],
        transaction_proofs: Vec<ChainProof>,
        identity_proofs: &[ChainProof],
        uptime_proofs: &[UptimeProof],
        previous_block: Option<&Block>,
        consensus_certificate: Option<&ConsensusCertificate>,
        block_hash: Option<&str>,
        max_proof_size_bytes: usize,
    ) -> ChainResult<LocalProofArtifacts> {
        let _ = (
            storage,
            ledger,
            header,
            commitments,
            pruning_proof,
            accepted_identities,
            transactions,
            transaction_proofs,
            identity_proofs,
            uptime_proofs,
            previous_block,
            consensus_certificate,
            block_hash,
            max_proof_size_bytes,
        );
        Err(ChainError::Crypto("STWO prover disabled".into()))
    }

    #[instrument(
        name = "node.proof.collect_artifacts",
        skip(self, bundle),
        fields(
            transaction_proofs = bundle.transaction_proofs.len(),
            max_bytes = max_bytes
        )
    )]
    fn collect_proof_artifacts(
        bundle: &BlockProofBundle,
        max_bytes: usize,
    ) -> ChainResult<Vec<ProofArtifact>> {
        let mut artifacts = Vec::new();
        for proof in &bundle.transaction_proofs {
            if let Some(artifact) = Self::proof_artifact(ProofModule::Utxo, proof, max_bytes)? {
                artifacts.push(artifact);
            }
        }
        if let Some(artifact) =
            Self::proof_artifact(ProofModule::BlockTransition, &bundle.state_proof, max_bytes)?
        {
            artifacts.push(artifact);
        }
        if let Some(artifact) =
            Self::proof_artifact(ProofModule::Consensus, &bundle.pruning_proof, max_bytes)?
        {
            artifacts.push(artifact);
        }
        if let Some(artifact) =
            Self::proof_artifact(ProofModule::Consensus, &bundle.recursive_proof, max_bytes)?
        {
            artifacts.push(artifact);
        }
        Ok(artifacts)
    }

    #[instrument(
        name = "node.proof.encode_artifact",
        skip(proof),
        fields(module = ?module, max_bytes = max_bytes)
    )]
    fn proof_artifact(
        module: ProofModule,
        proof: &ChainProof,
        max_bytes: usize,
    ) -> ChainResult<Option<ProofArtifact>> {
        match proof {
            ChainProof::Stwo(stark) => {
                let bytes = match hex::decode(&stark.commitment) {
                    Ok(bytes) => bytes,
                    Err(_) => return Ok(None),
                };
                let mut commitment = [0u8; 32];
                if bytes.len() >= 32 {
                    commitment.copy_from_slice(&bytes[..32]);
                } else {
                    commitment[..bytes.len()].copy_from_slice(&bytes);
                }
                let encoded = serde_json::to_vec(proof).map_err(|err| {
                    ChainError::Config(format!(
                        "failed to encode {:?} proof artifact: {err}",
                        module
                    ))
                })?;
                if encoded.len() > max_bytes {
                    return Err(ChainError::Config(format!(
                        "proof artifact for {:?} exceeds max_proof_size_bytes ({max_bytes})",
                        module
                    )));
                }
                Ok(Some(ProofArtifact {
                    module,
                    commitment,
                    proof: encoded,
                    verification_key: None,
                }))
            }
            #[cfg(feature = "backend-rpp-stark")]
            ChainProof::RppStark(stark) => {
                let digest = compute_public_digest(stark.public_inputs()).into_bytes();
                let encoded = serde_json::to_vec(stark).map_err(|err| {
                    ChainError::Config(format!(
                        "failed to encode {:?} proof artifact: {err}",
                        module
                    ))
                })?;
                if encoded.len() > max_bytes {
                    return Err(ChainError::Config(format!(
                        "proof artifact for {:?} exceeds max_proof_size_bytes ({max_bytes})",
                        module
                    )));
                }
                Ok(Some(ProofArtifact {
                    module,
                    commitment: digest,
                    proof: encoded,
                    verification_key: None,
                }))
            }
            #[cfg(feature = "backend-plonky3")]
            ChainProof::Plonky3(_) => Ok(None),
        }
    }

    #[instrument(
        name = "node.consensus.produce_block",
        skip(self),
        fields(
            height = tracing::field::Empty,
            round = tracing::field::Empty
        )
    )]
    fn produce_block(&self) -> ChainResult<()> {
        let span = Span::current();
        let mut identity_pending: Vec<AttestedIdentityRequest> = Vec::new();
        {
            let mut mempool = self.identity_mempool.write();
            while identity_pending.len() < self.config.max_block_identity_registrations {
                if let Some(request) = mempool.pop_front() {
                    identity_pending.push(request);
                } else {
                    break;
                }
            }
        }

        let mut pending: Vec<TransactionProofBundle> = Vec::new();
        {
            let mut mempool = self.mempool.write();
            while pending.len() < self.config.max_block_transactions {
                if let Some(tx) = mempool.pop_front() {
                    pending.push(tx);
                } else {
                    break;
                }
            }
        }
        self.purge_transaction_metadata(&pending);
        let has_uptime = !self.uptime_mempool.read().is_empty();
        if pending.is_empty() && identity_pending.is_empty() && !has_uptime {
            return Ok(());
        }
        let mut uptime_pending: Vec<RecordedUptimeProof> = Vec::new();
        {
            let mut mempool = self.uptime_mempool.write();
            while let Some(record) = mempool.pop_front() {
                uptime_pending.push(record);
            }
        }
        let tip_snapshot = self.chain_tip.read().clone();
        let height = tip_snapshot.height + 1;
        span.record("height", &height);
        self.prune_consensus_rounds_below(height);
        self.ledger.sync_epoch_for_height(height);
        let epoch = self.ledger.current_epoch();
        let accounts_snapshot = self.ledger.accounts_snapshot();
        let (validators, observers) = classify_participants(&accounts_snapshot);
        let vrf_pool = self.gather_vrf_submissions(epoch, tip_snapshot.last_hash, &validators);
        let round_number = self.current_consensus_round(height);
        span.record("round", &round_number);
        self.observe_consensus_round(height, round_number);
        let mut round = ConsensusRound::new(
            height,
            round_number,
            tip_snapshot.last_hash,
            self.config.validator_set_size(),
            validators,
            observers,
            &vrf_pool,
        );
        let round_metrics = round.vrf_metrics().clone();
        {
            let mut metrics = self.vrf_metrics.write();
            *metrics = round_metrics.clone();
        }
        {
            let mut threshold = self.vrf_threshold.write();
            *threshold = VrfThresholdStatus {
                epoch: round_metrics.latest_epoch,
                threshold: round_metrics.active_epoch_threshold.clone(),
                committee_target: round_metrics.target_validator_count,
                pool_entries: round_metrics.pool_entries,
                accepted_validators: round_metrics.accepted_validators,
                participation_rate: round_metrics.participation_rate,
            };
        }
        if let Some(epoch_value) = round_metrics.latest_epoch {
            if let Ok(bytes) = hex::decode(&round_metrics.entropy_beacon) {
                if bytes.len() == 32 {
                    let mut beacon = [0u8; 32];
                    beacon.copy_from_slice(&bytes);
                    self.vrf_epoch.write().record_entropy(epoch_value, beacon);
                }
            }
        }
        self.ledger
            .record_vrf_history(epoch, round.round(), round.vrf_audit());
        let selection = match round.select_proposer() {
            Some(selection) => selection,
            None => {
                warn!("no proposer could be selected");
                return Ok(());
            }
        };
        let round_id = round.round();
        self.consensus_telemetry
            .record_round_start(height, round_id, &selection.proposer);
        if selection.proposer != self.address {
            if let Some(proposal) = self.take_verified_proposal(height, &selection.proposer) {
                info!(
                    proposer = %selection.proposer,
                    height,
                    "processing verified external proposal"
                );
                let block_hash = proposal.hash.clone();
                round.set_block_hash(block_hash.clone());
                let local_prevote =
                    self.build_local_vote(height, round.round(), &block_hash, BftVoteKind::PreVote);
                if let Err(err) = round.register_prevote(&local_prevote) {
                    warn!(
                        ?err,
                        "failed to register local prevote for external proposal"
                    );
                    self.consensus_telemetry
                        .record_failed_vote("local_prevote".to_string());
                    self.update_runtime_metrics();
                }
                let local_precommit = self.build_local_vote(
                    height,
                    round.round(),
                    &block_hash,
                    BftVoteKind::PreCommit,
                );
                if let Err(err) = round.register_precommit(&local_precommit) {
                    warn!(
                        ?err,
                        "failed to register local precommit for external proposal"
                    );
                    self.consensus_telemetry
                        .record_failed_vote("local_precommit".to_string());
                    self.update_runtime_metrics();
                }
                let external_votes = self.drain_votes_for(height, &block_hash);
                for vote in &external_votes {
                    let result = match vote.vote.kind {
                        BftVoteKind::PreVote => round.register_prevote(vote),
                        BftVoteKind::PreCommit => round.register_precommit(vote),
                    };
                    if let Err(err) = result {
                        warn!(?err, voter = %vote.vote.voter, "rejecting invalid consensus vote");
                        if self.config.rollout.feature_gates.consensus_enforcement {
                            if let Err(slash_err) =
                                self.slash_validator(&vote.vote.voter, SlashingReason::InvalidVote)
                            {
                                warn!(
                                    ?slash_err,
                                    voter = %vote.vote.voter,
                                    "failed to slash validator for invalid vote"
                                );
                            }
                        }
                        self.consensus_telemetry
                            .record_failed_vote("external_vote".to_string());
                    }
                }
                if round.commit_reached() {
                    info!(height, proposer = %selection.proposer, "commit quorum observed externally");
                    self.consensus_telemetry.record_quorum(height, round_id);
                    let previous_block = if height == 0 {
                        None
                    } else {
                        self.storage.read_block(height - 1)?
                    };
                    let mut archived_votes = vec![local_prevote.clone(), local_precommit.clone()];
                    archived_votes.extend(external_votes.clone());
                    let finalization_ctx =
                        FinalizationContext::External(ExternalFinalizationContext {
                            round,
                            block: proposal,
                            previous_block,
                            archived_votes,
                        });
                    match self.finalize_block(finalization_ctx)? {
                        FinalizationOutcome::Sealed { block, tip_height } => {
                            let _ = (block, tip_height);
                            self.consensus_telemetry.record_round_end(height, round_id);
                            self.update_runtime_metrics();
                        }
                        FinalizationOutcome::AwaitingQuorum => {}
                    }
                    return Ok(());
                }
            } else {
                info!(
                    proposer = %selection.proposer,
                    height,
                    "no verified proposal available for external leader"
                );
            }
            return Ok(());
        }
        if round.total_power().clone() == Natural::from(0u32) {
            warn!("validator set has no voting power");
            return Ok(());
        }

        self.publish_pipeline_event(PipelineObservation::VrfLeadership {
            height,
            round: round.round(),
            proposer: selection.proposer.clone(),
            randomness: selection.randomness.to_string(),
            block_hash: None,
        });

        let mut accepted_identities: Vec<AttestedIdentityRequest> = Vec::new();
        for request in identity_pending {
            match self.ledger.register_identity(
                &request,
                height,
                IDENTITY_ATTESTATION_QUORUM,
                IDENTITY_ATTESTATION_GOSSIP_MIN,
            ) {
                Ok(_) => accepted_identities.push(request),
                Err(err) => {
                    warn!(?err, "dropping invalid identity declaration");
                    if self.config.rollout.feature_gates.consensus_enforcement {
                        if let Err(slash_err) =
                            self.slash_validator(&self.address, SlashingReason::InvalidIdentity)
                        {
                            warn!(?slash_err, "failed to slash proposer for invalid identity");
                        }
                    }
                }
            }
        }

        let identity_declarations: Vec<IdentityDeclaration> = accepted_identities
            .iter()
            .map(|request| request.declaration.clone())
            .collect();

        let mut accepted: Vec<TransactionProofBundle> = Vec::new();
        let mut total_fees: u64 = 0;
        for bundle in pending {
            match self
                .ledger
                .select_inputs_for_transaction(&bundle.transaction)
                .and_then(|inputs| self.ledger.apply_transaction(&bundle.transaction, &inputs))
            {
                Ok(fee) => {
                    total_fees = total_fees.saturating_add(fee);
                    accepted.push(bundle);
                }
                Err(err) => warn!(?err, "dropping invalid transaction"),
            }
        }

        if accepted.is_empty() && accepted_identities.is_empty() && uptime_pending.is_empty() {
            return Ok(());
        }

        let block_reward = BASE_BLOCK_REWARD.saturating_add(total_fees);
        self.ledger.distribute_consensus_rewards(
            &selection.proposer,
            round.validators(),
            block_reward,
            LEADER_BONUS_PERCENT,
        )?;

        let (transactions, transaction_proofs): (Vec<SignedTransaction>, Vec<_>) = accepted
            .into_iter()
            .map(|bundle| (bundle.transaction, bundle.proof))
            .unzip();

        let identity_proofs: Vec<ChainProof> = accepted_identities
            .iter()
            .map(|request| request.declaration.proof.zk_proof.clone())
            .collect();

        let mut uptime_proofs = Vec::new();
        let mut timetoke_updates = Vec::new();
        for record in uptime_pending {
            let RecordedUptimeProof {
                proof,
                credited_hours,
            } = record;
            timetoke_updates.push(TimetokeUpdate {
                identity: proof.wallet_address.clone(),
                window_start: proof.window_start,
                window_end: proof.window_end,
                credited_hours,
            });
            uptime_proofs.push(proof);
        }

        let mut touched_identities: HashSet<Address> = HashSet::new();
        for tx in &transactions {
            touched_identities.insert(tx.payload.from.clone());
            touched_identities.insert(tx.payload.to.clone());
        }
        for declaration in &identity_declarations {
            touched_identities.insert(declaration.genesis.wallet_addr.clone());
        }
        for update in &timetoke_updates {
            touched_identities.insert(update.identity.clone());
        }

        let mut reputation_updates = Vec::new();
        for identity in touched_identities {
            if let Some(mut audit) = self.ledger.reputation_audit(&identity)? {
                self.sign_reputation_audit(&mut audit);
                self.audit_exporter.export_reputation(&audit)?;
                reputation_updates.push(ReputationUpdate::from(audit));
            }
        }
        reputation_updates.sort_by(|a, b| a.identity.cmp(&b.identity));

        let mut operation_hashes = Vec::new();
        for declaration in &identity_declarations {
            operation_hashes.push(declaration.hash()?);
        }
        for tx in &transactions {
            operation_hashes.push(tx.hash());
        }
        for proof in &uptime_proofs {
            let encoded = serde_json::to_vec(proof).expect("serialize uptime proof");
            operation_hashes.push(Blake2sHasher::hash(&encoded).into());
        }
        for update in &timetoke_updates {
            let encoded = serde_json::to_vec(update).expect("serialize timetoke update");
            operation_hashes.push(Blake2sHasher::hash(&encoded).into());
        }
        for update in &reputation_updates {
            let encoded = serde_json::to_vec(update).expect("serialize reputation update");
            operation_hashes.push(Blake2sHasher::hash(&encoded).into());
        }
        let tx_root = compute_merkle_root(&mut operation_hashes);
        let commitments = self.ledger.global_commitments();
        let header = BlockHeader::new(
            height,
            hex::encode(tip_snapshot.last_hash),
            hex::encode(tx_root),
            hex::encode(commitments.global_state_root),
            hex::encode(commitments.utxo_root),
            hex::encode(commitments.reputation_root),
            hex::encode(commitments.timetoke_root),
            hex::encode(commitments.zsi_root),
            hex::encode(commitments.proof_root),
            selection.total_voting_power.to_string(),
            selection.randomness.to_string(),
            selection.vrf_public_key.clone(),
            selection.proof.preoutput.clone(),
            selection.proof.proof.clone(),
            self.address.clone(),
            selection.tier.to_string(),
            selection.timetoke_hours,
        );
        let block_hash_hex = hex::encode(header.hash());
        round.set_block_hash(block_hash_hex.clone());

        let local_prevote =
            self.build_local_vote(height, round.round(), &block_hash_hex, BftVoteKind::PreVote);
        round.register_prevote(&local_prevote)?;
        let local_precommit = self.build_local_vote(
            height,
            round.round(),
            &block_hash_hex,
            BftVoteKind::PreCommit,
        );
        round.register_precommit(&local_precommit)?;

        let external_votes = self.drain_votes_for(height, &block_hash_hex);
        for vote in &external_votes {
            let result = match vote.vote.kind {
                BftVoteKind::PreVote => round.register_prevote(vote),
                BftVoteKind::PreCommit => round.register_precommit(vote),
            };
            if let Err(err) = result {
                warn!(?err, voter = %vote.vote.voter, "rejecting invalid consensus vote");
                if self.config.rollout.feature_gates.consensus_enforcement {
                    if let Err(slash_err) =
                        self.slash_validator(&vote.vote.voter, SlashingReason::InvalidVote)
                    {
                        warn!(
                            ?slash_err,
                            voter = %vote.vote.voter,
                            "failed to slash validator for invalid vote"
                        );
                    }
                }
                self.consensus_telemetry
                    .record_failed_vote("external_vote".to_string());
                self.update_runtime_metrics();
            }
        }

        let mut recorded_votes = vec![local_prevote.clone(), local_precommit.clone()];
        recorded_votes.extend(external_votes.clone());

        let finalization_ctx = FinalizationContext::Local(LocalFinalizationContext {
            round,
            block_hash: block_hash_hex,
            header,
            parent_height: tip_snapshot.height,
            commitments,
            accepted_identities,
            transactions,
            transaction_proofs,
            identity_proofs,
            uptime_proofs,
            timetoke_updates,
            reputation_updates,
            recorded_votes,
        });

        match self.finalize_block(finalization_ctx)? {
            FinalizationOutcome::Sealed { block, tip_height } => {
                let _ = (block, tip_height);
                self.consensus_telemetry.record_quorum(height, round_id);
                self.consensus_telemetry.record_round_end(height, round_id);
                self.update_runtime_metrics();
            }
            FinalizationOutcome::AwaitingQuorum => {}
        }
        Ok(())
    }

    fn finalize_block(&self, ctx: FinalizationContext) -> ChainResult<FinalizationOutcome> {
        match ctx {
            FinalizationContext::Local(ctx) => self.finalize_local_block(ctx),
            FinalizationContext::External(ctx) => self.finalize_external_block(ctx),
        }
    }

    fn decode_commitment(value: &str) -> ChainResult<[u8; 32]> {
        let bytes = hex::decode(value)
            .map_err(|err| ChainError::Config(format!("invalid commitment encoding: {err}")))?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| ChainError::Config("commitment digest must be 32 bytes".into()))?;
        Ok(array)
    }

    fn commitments_from_header(header: &BlockHeader) -> ChainResult<GlobalStateCommitments> {
        Ok(GlobalStateCommitments {
            global_state_root: Self::decode_commitment(&header.state_root)?,
            utxo_root: Self::decode_commitment(&header.utxo_root)?,
            reputation_root: Self::decode_commitment(&header.reputation_root)?,
            timetoke_root: Self::decode_commitment(&header.timetoke_root)?,
            zsi_root: Self::decode_commitment(&header.zsi_root)?,
            proof_root: Self::decode_commitment(&header.proof_root)?,
        })
    }

    fn finalize_local_block(
        &self,
        ctx: LocalFinalizationContext,
    ) -> ChainResult<FinalizationOutcome> {
        let LocalFinalizationContext {
            round,
            block_hash,
            header,
            parent_height,
            commitments,
            accepted_identities,
            transactions,
            transaction_proofs,
            identity_proofs,
            uptime_proofs,
            timetoke_updates,
            reputation_updates,
            recorded_votes,
        } = ctx;

        if !round.commit_reached() {
            warn!("quorum not reached for commit");
            return Ok(FinalizationOutcome::AwaitingQuorum);
        }

        let height = header.height;
        let previous_block = self.storage.read_block(parent_height)?;
        let pruning_proof = PruningProof::from_previous(previous_block.as_ref(), &header);
        let participants = round.commit_participants();
        self.ledger
            .record_consensus_witness(height, round.round(), participants);
        let consensus_certificate = round.certificate();
        let LocalProofArtifacts {
            bundle: stark_bundle,
            consensus_proof,
            module_witnesses,
            proof_artifacts,
        } = NodeInner::generate_local_block_proofs(
            &self.storage,
            &self.ledger,
            &header,
            &commitments,
            &pruning_proof,
            &accepted_identities,
            &transactions,
            transaction_proofs,
            &identity_proofs,
            &uptime_proofs,
            previous_block.as_ref(),
            Some(&consensus_certificate),
            Some(&block_hash),
            self.config.max_proof_size_bytes,
        )?;
        let consensus_proof = consensus_proof.ok_or_else(|| {
            ChainError::Crypto("local consensus proof missing".into())
        })?;

        #[cfg(feature = "backend-rpp-stark")]
        if let Err(err) = self
            .verifiers
            .verify_rpp_stark_block_bundle(&stark_bundle)
        {
            error!(
                height,
                block_hash = %block_hash,
                ?err,
                "local block bundle rejected by RPP-STARK verifier"
            );
            return Err(err);
        }

        let state_proof = stark_bundle.state_proof.clone();
        #[cfg(feature = "backend-rpp-stark")]
        let state_result = match &state_proof {
            ChainProof::RppStark(_) => self
                .verify_rpp_stark_with_metrics(ProofVerificationKind::State, &state_proof)
                .map(|_| ()),
            _ => self.verifiers.verify_state(&state_proof),
        };
        #[cfg(not(feature = "backend-rpp-stark"))]
        let state_result = self.verifiers.verify_state(&state_proof);
        if let Err(err) = state_result {
            error!(
                height,
                block_hash = %block_hash,
                ?err,
                "local state proof rejected by verifier"
            );
            return Err(err);
        }

        let pruning_stark = stark_bundle.pruning_proof.clone();
        #[cfg(feature = "backend-rpp-stark")]
        let pruning_result = match &pruning_stark {
            ChainProof::RppStark(_) => self
                .verify_rpp_stark_with_metrics(ProofVerificationKind::Pruning, &pruning_stark)
                .map(|_| ()),
            _ => self.verifiers.verify_pruning(&pruning_stark),
        };
        #[cfg(not(feature = "backend-rpp-stark"))]
        let pruning_result = self.verifiers.verify_pruning(&pruning_stark);
        if let Err(err) = pruning_result {
            error!(
                height,
                block_hash = %block_hash,
                ?err,
                "local pruning proof rejected by verifier"
            );
            return Err(err);
        }

        let recursive_stark = stark_bundle.recursive_proof.clone();
        #[cfg(feature = "backend-rpp-stark")]
        let recursive_result = match &recursive_stark {
            ChainProof::RppStark(_) => self
                .verify_rpp_stark_with_metrics(
                    ProofVerificationKind::Recursive,
                    &recursive_stark,
                )
                .map(|_| ()),
            _ => self.verifiers.verify_recursive(&recursive_stark),
        };
        #[cfg(not(feature = "backend-rpp-stark"))]
        let recursive_result = self.verifiers.verify_recursive(&recursive_stark);
        if let Err(err) = recursive_result {
            error!(
                height,
                block_hash = %block_hash,
                ?err,
                "local recursive proof rejected by verifier"
            );
            return Err(err);
        }

        #[cfg(feature = "backend-rpp-stark")]
        let consensus_result = match &consensus_proof {
            ChainProof::RppStark(_) => self
                .verify_rpp_stark_with_metrics(ProofVerificationKind::Consensus, &consensus_proof)
                .map(|_| ()),
            _ => self.verifiers.verify_consensus(&consensus_proof),
        };
        #[cfg(not(feature = "backend-rpp-stark"))]
        let consensus_result = self.verifiers.verify_consensus(&consensus_proof);
        if let Err(err) = consensus_result {
            error!(
                height,
                block_hash = %block_hash,
                ?err,
                "local consensus proof rejected by verifier"
            );
            return Err(err);
        }

        let recursive_proof = match previous_block.as_ref() {
            Some(block) => RecursiveProof::extend(
                &block.recursive_proof,
                &header,
                &pruning_proof,
                &stark_bundle.recursive_proof,
            )?,
            None => {
                RecursiveProof::genesis(&header, &pruning_proof, &stark_bundle.recursive_proof)?
            }
        };
        let signature = sign_message(&self.keypair, &header.canonical_bytes());
        let state_proof_artifact = state_proof.clone();
        let block = Block::new(
            header,
            accepted_identities,
            transactions,
            uptime_proofs,
            timetoke_updates,
            reputation_updates,
            recorded_votes,
            module_witnesses,
            proof_artifacts,
            pruning_proof,
            recursive_proof,
            stark_bundle,
            signature,
            consensus_certificate,
            Some(consensus_proof),
        );
        block.verify(previous_block.as_ref(), &self.keypair.public)?;
        self.ledger.sync_epoch_for_height(height.saturating_add(1));
        let receipt = self.persist_accounts(height)?;
        let encoded_new_root = hex::encode(receipt.new_root);
        if encoded_new_root != block.header.state_root {
            return Err(ChainError::Config(
                "firewood state root does not match block header".into(),
            ));
        }
        let lifecycle = StateLifecycle::new(&self.storage);
        lifecycle.verify_transition(
            &state_proof_artifact,
            &receipt.previous_root,
            &receipt.new_root,
        )?;
        let mut metadata = BlockMetadata::from(&block);
        metadata.previous_state_root = hex::encode(receipt.previous_root);
        metadata.new_state_root = encoded_new_root;
        if let Some(firewood_proof) = receipt.pruning_proof.as_ref() {
            let pruning = PruningProof::from_envelope(firewood_proof.clone());
            metadata.pruning = Some(pruning.envelope_metadata());
        }
        let pruning_metadata = metadata
            .pruning
            .clone()
            .or_else(|| Some(block.pruning_proof.envelope_metadata()));
        {
            let span = storage_flush_span("store_block", block.header.height, &block.hash);
            let _guard = span.enter();
            self.storage.store_block(&block, &metadata)?;
        }
        if self.config.rollout.feature_gates.pruning && block.header.height > 0 {
            let span = storage_flush_span(
                "prune_block_payload",
                block.header.height - 1,
                &block.hash,
            );
            let _guard = span.enter();
            let _ = self.storage.prune_block_payload(block.header.height - 1)?;
        }
        let mut tip = self.chain_tip.write();
        tip.height = block.header.height;
        tip.last_hash = block.block_hash();
        tip.pruning = pruning_metadata;
        info!(height = tip.height, "sealed block");
        self.evidence_pool
            .write()
            .prune_below(block.header.height.saturating_add(1));
        self.prune_consensus_rounds_below(block.header.height.saturating_add(1));

        self.update_runtime_metrics();

        let block_hash = block.hash.clone();
        let event_round = block.consensus.round;
        let previous_root_hex = hex::encode(receipt.previous_root);
        let pruning_proof = receipt.pruning_proof.clone();
        self.publish_pipeline_event(PipelineObservation::BftFinalised {
            height,
            round: event_round,
            block_hash: block_hash.clone(),
            commitments,
            certificate: block.consensus.clone(),
        });
        self.publish_pipeline_event(PipelineObservation::FirewoodCommitment {
            height,
            round: event_round,
            block_hash,
            previous_root: previous_root_hex,
            new_root: encoded_new_root.clone(),
            pruning_proof,
        });

        self.emit_state_sync_artifacts();

        Ok(FinalizationOutcome::Sealed {
            tip_height: block.header.height,
            block,
        })
    }

    fn finalize_external_block(
        &self,
        ctx: ExternalFinalizationContext,
    ) -> ChainResult<FinalizationOutcome> {
        let ExternalFinalizationContext {
            round,
            mut block,
            mut previous_block,
            archived_votes,
        } = ctx;

        if !round.commit_reached() {
            warn!("quorum not reached for commit");
            return Ok(FinalizationOutcome::AwaitingQuorum);
        }

        let height = block.header.height;
        if previous_block.is_none() && height > 0 {
            previous_block = self.storage.read_block(height - 1)?;
        }

        let proposer_key = self.ledger.validator_public_key(&block.header.proposer)?;

        let mut recorded_votes = block.bft_votes.clone();
        let mut vote_index = HashSet::new();
        for vote in &recorded_votes {
            vote_index.insert((
                vote.vote.voter.clone(),
                vote.vote.kind,
                vote.vote.round,
                vote.vote.height,
                vote.vote.block_hash.clone(),
            ));
        }
        for vote in archived_votes {
            let key = (
                vote.vote.voter.clone(),
                vote.vote.kind,
                vote.vote.round,
                vote.vote.height,
                vote.vote.block_hash.clone(),
            );
            if vote_index.insert(key) {
                recorded_votes.push(vote);
            }
        }
        block.bft_votes = recorded_votes;

        block.verify_without_stark(previous_block.as_ref(), &proposer_key)?;

        let round_number = round.round();
        #[cfg(feature = "backend-rpp-stark")]
        let state_result = match &block.stark.state_proof {
            ChainProof::RppStark(_) => self
                .verify_rpp_stark_with_metrics(
                    ProofVerificationKind::State,
                    &block.stark.state_proof,
                )
                .map(|_| ()),
            _ => self.verifiers.verify_state(&block.stark.state_proof),
        };
        #[cfg(not(feature = "backend-rpp-stark"))]
        let state_result = self.verifiers.verify_state(&block.stark.state_proof);
        if let Err(err) = state_result {
            warn!(
                height,
                round = round_number,
                proposer = %block.header.proposer,
                ?err,
                proof_kind = "state",
                "external block proof verification failed"
            );
            self.punish_invalid_proof(&block.header.proposer, height, round_number);
            return Err(err);
        }
        #[cfg(feature = "backend-rpp-stark")]
        let pruning_result = match &block.stark.pruning_proof {
            ChainProof::RppStark(_) => self
                .verify_rpp_stark_with_metrics(
                    ProofVerificationKind::Pruning,
                    &block.stark.pruning_proof,
                )
                .map(|_| ()),
            _ => self.verifiers.verify_pruning(&block.stark.pruning_proof),
        };
        #[cfg(not(feature = "backend-rpp-stark"))]
        let pruning_result = self.verifiers.verify_pruning(&block.stark.pruning_proof);
        if let Err(err) = pruning_result {
            warn!(
                height,
                round = round_number,
                proposer = %block.header.proposer,
                ?err,
                proof_kind = "pruning",
                "external block proof verification failed"
            );
            self.punish_invalid_proof(&block.header.proposer, height, round_number);
            return Err(err);
        }
        #[cfg(feature = "backend-rpp-stark")]
        let recursive_result = match &block.stark.recursive_proof {
            ChainProof::RppStark(_) => self
                .verify_rpp_stark_with_metrics(
                    ProofVerificationKind::Recursive,
                    &block.stark.recursive_proof,
                )
                .map(|_| ()),
            _ => self
                .verifiers
                .verify_recursive(&block.stark.recursive_proof),
        };
        #[cfg(not(feature = "backend-rpp-stark"))]
        let recursive_result = self
            .verifiers
            .verify_recursive(&block.stark.recursive_proof);
        if let Err(err) = recursive_result {
            warn!(
                height,
                round = round_number,
                proposer = %block.header.proposer,
                ?err,
                proof_kind = "recursive",
                "external block proof verification failed"
            );
            self.punish_invalid_proof(&block.header.proposer, height, round_number);
            return Err(err);
        }
        if let Some(proof) = &block.consensus_proof {
            #[cfg(feature = "backend-rpp-stark")]
            let consensus_result = match proof {
                ChainProof::RppStark(_) => self
                    .verify_rpp_stark_with_metrics(ProofVerificationKind::Consensus, proof)
                    .map(|_| ()),
                _ => self.verifiers.verify_consensus(proof),
            };
            #[cfg(not(feature = "backend-rpp-stark"))]
            let consensus_result = self.verifiers.verify_consensus(proof);
            if let Err(err) = consensus_result {
                warn!(
                    height,
                    round = round_number,
                    proposer = %block.header.proposer,
                    ?err,
                    proof_kind = "consensus",
                    "external block proof verification failed"
                );
                self.punish_invalid_proof(&block.header.proposer, height, round_number);
                return Err(err);
            }
        }

        self.ledger.sync_epoch_for_height(height);

        let participants = round.commit_participants();
        self.ledger
            .record_consensus_witness(height, round_number, participants);

        for request in &block.identities {
            self.ledger.register_identity(
                request,
                height,
                IDENTITY_ATTESTATION_QUORUM,
                IDENTITY_ATTESTATION_GOSSIP_MIN,
            )?;
        }

        let mut total_fees: u64 = 0;
        for tx in &block.transactions {
            let inputs = match self.ledger.select_inputs_for_transaction(tx) {
                Ok(inputs) => inputs,
                Err(err) => {
                    self.record_double_spend_if_applicable(&block, round_number, &err);
                    return Err(err);
                }
            };
            let fee = match self.ledger.apply_transaction(tx, &inputs) {
                Ok(fee) => fee,
                Err(err) => {
                    self.record_double_spend_if_applicable(&block, round_number, &err);
                    return Err(err);
                }
            };
            total_fees = total_fees.saturating_add(fee);
        }

        for proof in &block.uptime_proofs {
            if let Err(err) = self.ledger.apply_uptime_proof(proof) {
                match err {
                    ChainError::Transaction(message)
                        if message == "uptime proof does not extend the recorded online window" =>
                    {
                        debug!(
                            identity = %proof.wallet_address,
                            "skipping previously applied uptime proof"
                        );
                    }
                    other => return Err(other),
                }
            }
        }

        let block_reward = BASE_BLOCK_REWARD.saturating_add(total_fees);
        self.ledger.distribute_consensus_rewards(
            &block.header.proposer,
            round.validators(),
            block_reward,
            LEADER_BONUS_PERCENT,
        )?;

        let produced_witnesses = self.ledger.drain_module_witnesses();
        let produced_bytes =
            bincode::serialize(&produced_witnesses).map_err(ChainError::Serialization)?;
        let block_bytes =
            bincode::serialize(&block.module_witnesses).map_err(ChainError::Serialization)?;
        if produced_bytes != block_bytes {
            return Err(ChainError::Config(
                "module witness bundle mismatch for external block".into(),
            ));
        }
        let module_artifacts = self.ledger.stage_module_witnesses(&produced_witnesses)?;
        for artifact in module_artifacts {
            if !block.proof_artifacts.iter().any(|existing| {
                existing.module == artifact.module
                    && existing.commitment == artifact.commitment
                    && existing.proof == artifact.proof
            }) {
                return Err(ChainError::Config(
                    "external block missing module proof artifact".into(),
                ));
            }
        }

        let mut touched_identities: HashSet<Address> = HashSet::new();
        for tx in &block.transactions {
            touched_identities.insert(tx.payload.from.clone());
            touched_identities.insert(tx.payload.to.clone());
        }
        for identity in &block.identities {
            touched_identities.insert(identity.declaration.genesis.wallet_addr.clone());
        }
        for update in &block.timetoke_updates {
            touched_identities.insert(update.identity.clone());
        }
        let mut expected_reputation = Vec::new();
        for identity in touched_identities {
            if let Some(mut audit) = self.ledger.reputation_audit(&identity)? {
                self.sign_reputation_audit(&mut audit);
                self.audit_exporter.export_reputation(&audit)?;
                expected_reputation.push(ReputationUpdate::from(audit));
            }
        }
        expected_reputation.sort_by(|a, b| a.identity.cmp(&b.identity));
        let expected_bytes =
            bincode::serialize(&expected_reputation).map_err(ChainError::Serialization)?;
        let provided_bytes =
            bincode::serialize(&block.reputation_updates).map_err(ChainError::Serialization)?;
        if expected_bytes != provided_bytes {
            return Err(ChainError::Config(
                "external block reputation updates mismatch ledger state".into(),
            ));
        }

        let state_proof_artifact = block.stark.state_proof.clone();
        self.ledger.sync_epoch_for_height(height.saturating_add(1));
        let receipt = self.persist_accounts(height)?;
        let encoded_new_root = hex::encode(receipt.new_root);
        if encoded_new_root != block.header.state_root {
            return Err(ChainError::Config(
                "firewood state root does not match block header".into(),
            ));
        }

        let lifecycle = StateLifecycle::new(&self.storage);
        lifecycle.verify_transition(
            &state_proof_artifact,
            &receipt.previous_root,
            &receipt.new_root,
        )?;

        let mut metadata = BlockMetadata::from(&block);
        metadata.previous_state_root = hex::encode(receipt.previous_root);
        metadata.new_state_root = encoded_new_root;
        if let Some(firewood_proof) = receipt.pruning_proof.as_ref() {
            let pruning = PruningProof::from_envelope(firewood_proof.clone());
            metadata.pruning = Some(pruning.envelope_metadata());
        }
        let pruning_metadata = metadata
            .pruning
            .clone()
            .or_else(|| Some(block.pruning_proof.envelope_metadata()));
        self.storage.store_block(&block, &metadata)?;
        if self.config.rollout.feature_gates.pruning && block.header.height > 0 {
            let _ = self.storage.prune_block_payload(block.header.height - 1)?;
        }

        let mut tip = self.chain_tip.write();
        tip.height = block.header.height;
        tip.last_hash = block.block_hash();
        tip.pruning = pruning_metadata;
        info!(
            height = tip.height,
            proposer = %block.header.proposer,
            "sealed external block"
        );
        drop(tip);

        self.evidence_pool
            .write()
            .prune_below(block.header.height.saturating_add(1));
        self.prune_consensus_rounds_below(block.header.height.saturating_add(1));

        self.update_runtime_metrics();

        let block_hash = block.hash.clone();
        let event_round = block.consensus.round;
        match Self::commitments_from_header(&block.header) {
            Ok(commitments) => {
                self.publish_pipeline_event(PipelineObservation::BftFinalised {
                    height,
                    round: event_round,
                    block_hash: block_hash.clone(),
                    commitments,
                    certificate: block.consensus.clone(),
                });
            }
            Err(err) => {
                warn!(
                    ?err,
                    height,
                    round = event_round,
                    "failed to decode commitments for pipeline event"
                );
            }
        }
        let previous_root_hex = hex::encode(receipt.previous_root);
        let pruning_proof = receipt.pruning_proof.clone();
        self.publish_pipeline_event(PipelineObservation::FirewoodCommitment {
            height,
            round: event_round,
            block_hash,
            previous_root: previous_root_hex,
            new_root: encoded_new_root.clone(),
            pruning_proof,
        });

        self.emit_state_sync_artifacts();

        Ok(FinalizationOutcome::Sealed {
            tip_height: block.header.height,
            block,
        })
    }

    fn persist_accounts(&self, block_height: u64) -> ChainResult<StateTransitionReceipt> {
        let accounts = self.ledger.accounts_snapshot();
        let lifecycle = StateLifecycle::new(&self.storage);
        lifecycle.apply_block(block_height, &accounts)
    }

    fn bootstrap(&self) -> ChainResult<()> {
        if let Some(metadata) = self.storage.tip()? {
            let block = self
                .storage
                .read_block(metadata.height)?
                .ok_or_else(|| ChainError::Config("tip metadata missing block".into()))?;
            let proposer_key = self.ledger.validator_public_key(&block.header.proposer)?;
            block.verify(None, &proposer_key)?;
            let mut tip = self.chain_tip.write();
            tip.height = block.header.height;
            tip.last_hash = block.block_hash();
            tip.pruning = metadata.pruning.clone();
            if self.config.rollout.feature_gates.pruning {
                for height in 0..block.header.height {
                    let _ = self.storage.prune_block_payload(height)?;
                }
            }
        } else {
            let mut tip = self.chain_tip.write();
            tip.height = 0;
            tip.last_hash = [0u8; 32];
            tip.pruning = None;
        }
        Ok(())
    }

    fn network_identity_profile(&self) -> ChainResult<NetworkIdentityProfile> {
        let account = self
            .ledger
            .get_account(&self.address)
            .ok_or_else(|| ChainError::Config("node account missing in ledger".into()))?;
        let tier_level = tier_to_level(&account.reputation.tier);
        let zsi_id = account.reputation.zsi.public_key_commitment.clone();
        let vrf_public_key = self.vrf_keypair.public.to_bytes().to_vec();
        let template = HandshakePayload::new(
            zsi_id.clone(),
            Some(vrf_public_key.clone()),
            None,
            tier_level,
        );
        let sr_keypair = self.vrf_keypair.secret.expand_to_keypair();
        let signature = sr_keypair.sign_simple(VRF_HANDSHAKE_CONTEXT, &template.vrf_message());
        let vrf_proof = signature.to_bytes().to_vec();
        Ok(NetworkIdentityProfile {
            zsi_id,
            tier: tier_level,
            vrf_public_key,
            vrf_proof,
            feature_gates: self.config.rollout.feature_gates.clone(),
        })
    }
}

fn is_double_spend(err: &ChainError) -> bool {
    matches!(
        err,
        ChainError::Transaction(message)
            if matches!(
                message.as_str(),
                "transaction input already spent" | "transaction input not found"
            )
    )
}

fn tier_to_level(tier: &Tier) -> TierLevel {
    match tier {
        Tier::Tl0 => TierLevel::Tl0,
        Tier::Tl1 => TierLevel::Tl1,
        Tier::Tl2 => TierLevel::Tl2,
        Tier::Tl3 => TierLevel::Tl3,
        Tier::Tl4 => TierLevel::Tl4,
        Tier::Tl5 => TierLevel::Tl5,
    }
}

#[cfg(test)]
mod telemetry_metrics_tests {
    use super::{ConsensusTelemetry, RuntimeMetrics};
    use crate::types::Address;
    use opentelemetry_sdk::metrics::{
        InMemoryMetricExporter, MetricError, PeriodicReader, SdkMeterProvider,
    };
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[test]
    fn consensus_telemetry_records_metrics() -> std::result::Result<(), MetricError> {
        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let meter = provider.meter("telemetry-test");
        let metrics = Arc::new(RuntimeMetrics::from_meter(&meter));
        let telemetry = ConsensusTelemetry::new(metrics.clone());

        let leader: Address = "leader".into();
        telemetry.record_round_start(10, 2, &leader);
        {
            let mut state = telemetry.state.lock();
            state.last_round_started = Some(Instant::now() - Duration::from_millis(25));
        }
        telemetry.record_quorum(10, 2);
        telemetry.record_round_end(10, 2);
        telemetry.record_witness_event("blocks");
        telemetry.record_slashing("invalid_vote");
        telemetry.record_failed_vote("timeout");

        provider.force_flush()?;
        let exported = exporter.get_finished_metrics()?;

        let mut seen = HashSet::new();
        for resource in exported {
            for scope in resource.scope_metrics {
                for metric in scope.metrics {
                    seen.insert(metric.name.clone());
                }
            }
        }

        assert!(seen.contains("rpp.runtime.consensus.round.duration"));
        assert!(seen.contains("rpp.runtime.consensus.round.quorum_latency"));
        assert!(seen.contains("rpp.runtime.consensus.round.leader_changes"));
        assert!(seen.contains("rpp.runtime.consensus.witness.events"));
        assert!(seen.contains("rpp.runtime.consensus.slashing.events"));
        assert!(seen.contains("rpp.runtime.consensus.failed_votes"));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::Path;

    use tempfile::tempdir;

    use crate::crypto::{address_from_public_key, generate_keypair, sign_message};
    use crate::types::{
        Account, ChainProof, ExecutionTrace, ProofKind, ProofPayload, ReputationWeights,
        RppStarkProof, SignedTransaction, Stake, StarkProof, Tier, Transaction,
        TransactionProofBundle, TransactionWitness,
    };

    fn sample_node_config(base: &Path) -> NodeConfig {
        let data_dir = base.join("data");
        let keys_dir = base.join("keys");
        fs::create_dir_all(&data_dir).expect("node data dir");
        fs::create_dir_all(&keys_dir).expect("node key dir");

        let mut config = NodeConfig::default();
        config.data_dir = data_dir.clone();
        config.snapshot_dir = data_dir.join("snapshots");
        config.proof_cache_dir = data_dir.join("proofs");
        config.p2p.peerstore_path = data_dir.join("p2p/peerstore.json");
        config.p2p.gossip_path = Some(data_dir.join("p2p/gossip.json"));
        config.key_path = keys_dir.join("node.toml");
        config.p2p_key_path = keys_dir.join("p2p.toml");
        config.vrf_key_path = keys_dir.join("vrf.toml");
        config.block_time_ms = 200;
        config.mempool_limit = 8;
        config.rollout.feature_gates.pruning = false;
        config.rollout.feature_gates.recursive_proofs = false;
        config.rollout.feature_gates.reconstruction = false;
        config.rollout.feature_gates.consensus_enforcement = false;
        config
    }

    fn sample_transaction_bundle(to: &str, nonce: u64) -> TransactionProofBundle {
        let keypair = generate_keypair();
        let from = address_from_public_key(&keypair.public);
        let tx = Transaction::new(from.clone(), to.to_string(), 42, nonce, 1, None);
        let signature = sign_message(&keypair, &tx.canonical_bytes());
        let signed_tx = SignedTransaction::new(tx, signature, &keypair.public);

        let mut sender = Account::new(from.clone(), 1_000_000, Stake::from_u128(1_000));
        sender.nonce = nonce;

        let receiver = Account::new(to.to_string(), 0, Stake::default());

        let witness = TransactionWitness {
            signed_tx: signed_tx.clone(),
            sender_account: sender,
            receiver_account: Some(receiver),
            required_tier: Tier::Tl0,
            reputation_weights: ReputationWeights::default(),
        };

        let payload = ProofPayload::Transaction(witness.clone());
        let proof = StarkProof {
            kind: ProofKind::Transaction,
            commitment: String::new(),
            public_inputs: Vec::new(),
            payload: payload.clone(),
            trace: ExecutionTrace {
                segments: Vec::new(),
            },
            commitment_proof: Default::default(),
            fri_proof: Default::default(),
        };

        TransactionProofBundle::new(
            signed_tx,
            ChainProof::Stwo(proof),
            Some(witness),
            Some(payload),
        )
    }

    #[test]
    #[cfg(feature = "prover-stwo")]
    fn proof_artifact_serializes_stwo_commitment() {
        let mut bundle = sample_transaction_bundle("receiver", 0);
        if let ChainProof::Stwo(ref mut stark) = bundle.proof {
            stark.commitment = "ab".repeat(32);
        }
        let artifact = NodeInner::proof_artifact(ProofModule::Utxo, &bundle.proof, 16_384)
            .expect("artifact generation")
            .expect("artifact emitted");
        assert_eq!(artifact.commitment, [0xAB; 32]);
        let decoded: ChainProof = serde_json::from_slice(&artifact.proof).expect("decode");
        assert!(matches!(decoded, ChainProof::Stwo(_)));
    }

    #[test]
    #[cfg(feature = "backend-rpp-stark")]
    fn proof_artifact_serializes_rpp_stark_commitment() {
        let proof = ChainProof::RppStark(RppStarkProof::new(
            vec![0xAA, 0xBB],
            vec![0xCC, 0xDD, 0xEE],
            vec![0x01, 0x02],
        ));
        let expected_commitment = match &proof {
            ChainProof::RppStark(stark) => compute_public_digest(stark.public_inputs()).into_bytes(),
            _ => unreachable!(),
        };
        let artifact = NodeInner::proof_artifact(ProofModule::Utxo, &proof, 16_384)
            .expect("artifact generation")
            .expect("artifact emitted");
        assert_eq!(artifact.commitment, expected_commitment);
        let decoded: RppStarkProof = serde_json::from_slice(&artifact.proof).expect("decode rpp");
        assert_eq!(decoded.public_inputs(), &[0xCC, 0xDD, 0xEE]);
        assert_eq!(decoded.proof(), &[0x01, 0x02]);
    }

    #[test]
    fn mempool_status_exposes_witness_metadata_with_and_without_cache() {
        let tempdir = tempdir().expect("tempdir");
        let config = sample_node_config(tempdir.path());
        let node = Node::new(config, RuntimeMetrics::noop()).expect("node init");
        let handle = node.handle();
        let recipient = handle.address().to_string();

        let bundle = sample_transaction_bundle(&recipient, 0);
        let hash = handle
            .submit_transaction(bundle.clone())
            .expect("transaction accepted");

        let status = handle.mempool_status().expect("mempool status");
        let summary = status
            .transactions
            .iter()
            .find(|tx| tx.hash == hash)
            .expect("summary present");
        assert!(summary.witness.is_some(), "witness missing from snapshot");
        assert!(summary.proof.is_some(), "proof missing from snapshot");
        assert!(
            summary.proof_payload.is_some(),
            "proof payload missing from snapshot"
        );

        node.inner
            .pending_transaction_metadata
            .write()
            .remove(&hash);

        let status_after = handle.mempool_status().expect("mempool status fallback");
        let summary_after = status_after
            .transactions
            .iter()
            .find(|tx| tx.hash == hash)
            .expect("summary present after purge");
        assert!(summary_after.witness.is_some(), "fallback witness missing");
        assert!(summary_after.proof.is_some(), "fallback proof missing");
        assert!(
            summary_after.proof_payload.is_some(),
            "fallback proof payload missing"
        );

        drop(handle);
        drop(node);
    }
}

fn build_genesis_accounts(entries: Vec<GenesisAccount>) -> ChainResult<Vec<Account>> {
    entries
        .into_iter()
        .map(|entry| {
            let stake = entry.stake_value()?;
            Ok(Account::new(entry.address, entry.balance, stake))
        })
        .collect()
}
