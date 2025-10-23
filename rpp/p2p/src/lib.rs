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
    AdmissionControl, AdmissionError, ReputationBroadcast, ReputationEvent, ReputationOutcome,
};
pub use handshake::{HandshakePayload, VRF_HANDSHAKE_CONTEXT};
pub use identity::{IdentityError, IdentityMetadata, NodeIdentity, TopicPermission};
pub use peerstore::{IdentityVerifier, PeerRecord, Peerstore, PeerstoreConfig, PeerstoreError};
pub use persistence::{GossipStateError, GossipStateStore};
pub use pipeline::{
    BasicRecursiveProofVerifier, BlockProposal, ConsensusPipeline, JsonProofValidator,
    LightClientSync, MetaTelemetry, NetworkBlockMetadata, NetworkLightClientUpdate,
    NetworkMetaTelemetryReport, NetworkPayloadExpectations, NetworkPeerTelemetry,
    NetworkReconstructionRequest, NetworkSnapshotSummary, NetworkStateSyncChunk,
    NetworkStateSyncPlan, PersistentProofStorage, PipelineError, ProofMempool, ProofRecord,
    ProofStorage, RuntimeProofValidator, SnapshotChunk, SnapshotStore, TelemetryEvent,
    TransactionProofVerifier, VoteOutcome,
};
pub use roadmap::{libp2p_backbone_plan, Deliverable, Milestone, Phase, Plan, WorkItem};
pub use rpp_p2p_macros::NetworkBehaviour;
pub use security::{RateLimiter, ReplayProtector};
pub use simulator::{NetworkSimulation, SimulationReport};
pub use swarm::{Network, NetworkError, NetworkEvent};
pub use tier::TierLevel;
pub use topics::GossipTopic;
