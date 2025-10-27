//! RPP P2P stack - libp2p-backed networking primitives.

mod admission;
mod handshake;
mod identity;
mod peerstore;
mod persistence;
mod pipeline;
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
pub use handshake::{HandshakePayload, VRF_HANDSHAKE_CONTEXT};
pub use identity::{IdentityError, IdentityMetadata, NodeIdentity, TopicPermission};
pub use peerstore::{
    AllowlistedPeer, IdentityVerifier, PeerRecord, Peerstore, PeerstoreConfig, PeerstoreError,
};
pub use persistence::{GossipStateError, GossipStateStore};
pub use pipeline::{
    decode_gossip_payload, decode_meta_payload, sanitize_block_payload, sanitize_meta_payload,
    sanitize_vote_payload, validate_block_payload, validate_vote_payload,
    BasicRecursiveProofVerifier, BlockProposal, ConsensusPipeline, GossipBlockValidator,
    GossipPayloadError, GossipVoteValidator, JsonProofValidator, LightClientHead, LightClientSync,
    MetaTelemetry, NetworkBlockMetadata, NetworkFeatureAnnouncement, NetworkLightClientUpdate,
    NetworkMetaTelemetryReport, NetworkPayloadExpectations, NetworkPeerTelemetry,
    NetworkPruningCommitment, NetworkPruningEnvelope, NetworkPruningSegment, NetworkPruningSnapshot,
    NetworkReconstructionRequest,
    NetworkSnapshotSummary, NetworkStateSyncChunk, NetworkStateSyncPlan, NetworkTaggedDigestHex,
    PersistentProofStorage, PipelineError, ProofMempool, ProofRecord, ProofStorage,
    RuntimeProofValidator, SnapshotChunk, SnapshotChunkStream, SnapshotStore, TelemetryEvent,
    TransactionProofVerifier, VoteOutcome,
};
pub use roadmap::{libp2p_backbone_plan, Deliverable, Milestone, Phase, Plan, WorkItem};
pub use rpp_p2p_macros::NetworkBehaviour;
pub use security::{RateLimiter, ReplayProtector};
pub use simulator::{NetworkSimulation, SimulationReport};
pub use swarm::{Network, NetworkError, NetworkEvent, NetworkMetricsSnapshot};
pub use tier::TierLevel;
pub use topics::GossipTopic;
