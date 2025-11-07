//! RPP P2P stack - libp2p-backed networking primitives.

mod admission;
mod behaviour;
mod gossip;
mod handshake;
mod identity;
mod metrics;
mod peerstore;
mod persistence;
mod pipeline;
mod policy_log;
mod roadmap;
mod security;
mod simulator;
mod swarm;
mod tier;
mod topics;

pub mod vendor;

pub use admission::{
    AdmissionControl, AdmissionError, ReputationBroadcast, ReputationEvent, ReputationHeuristics,
    ReputationOutcome,
};
pub use behaviour::snapshots::{
    NullSnapshotProvider, SnapshotItemKind, SnapshotProvider, SnapshotResumeState,
    SnapshotSessionId, SnapshotsRequest, SnapshotsResponse,
};
#[cfg(feature = "request-response")]
pub use behaviour::snapshots::{SnapshotProtocolError, SnapshotsBehaviour, SnapshotsEvent};
pub use behaviour::witness::{
    WitnessChannelConfig, WitnessGossipPipelines, WitnessMessage, WitnessPipelineConfig,
    WitnessPipelineError,
};
pub use handshake::{HandshakePayload, VRF_HANDSHAKE_CONTEXT};
pub use identity::{IdentityError, IdentityMetadata, NodeIdentity, TopicPermission};
pub use peerstore::{
    AdmissionApproval, AdmissionAuditTrail, AdmissionPolicies, AllowlistedPeer, IdentityVerifier,
    PeerRecord, Peerstore, PeerstoreConfig, PeerstoreError,
};
pub use persistence::{GossipStateError, GossipStateStore};
pub use pipeline::{
    decode_gossip_payload, decode_meta_payload, sanitize_block_payload, sanitize_meta_payload,
    sanitize_vote_payload, validate_block_payload, validate_vote_payload,
    BasicRecursiveProofVerifier, BlockProposal, ConsensusPipeline, GossipBlockValidator,
    GossipPayloadError, GossipVoteValidator, JsonProofValidator, LightClientHead, LightClientSync,
    MetaTelemetry, NetworkBlockMetadata, NetworkFeatureAnnouncement, NetworkLightClientUpdate,
    NetworkMetaTelemetryReport, NetworkPayloadExpectations, NetworkPeerTelemetry,
    NetworkPruningCommitment, NetworkPruningEnvelope, NetworkPruningSegment,
    NetworkPruningSnapshot, NetworkReconstructionRequest, NetworkSnapshotSummary,
    NetworkStateSyncChunk, NetworkStateSyncPlan, NetworkTaggedDigestHex, PersistentProofStorage,
    PipelineError, ProofMempool, ProofRecord, ProofStorage, RuntimeProofValidator, SnapshotChunk,
    SnapshotChunkStream, SnapshotStore, TelemetryEvent, TransactionProofVerifier, VoteOutcome,
};
pub use policy_log::{
    AdmissionPolicyChange, AdmissionPolicyLogEntry, AdmissionPolicyLogError, PolicyAllowlistState,
};
pub use roadmap::{libp2p_backbone_plan, Deliverable, Milestone, Phase, Plan, WorkItem};
pub use rpp_p2p_macros::NetworkBehaviour;
pub use security::{RateLimiter, ReplayProtector};
pub use simulator::{NetworkSimulation, SimulationReport};
pub use swarm::{
    Network, NetworkError, NetworkEvent, NetworkMetricsSnapshot, SnapshotProviderHandle,
};
pub use tier::TierLevel;
pub use topics::GossipTopic;
