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

pub use admission::{AdmissionControl, AdmissionError, ReputationEvent, ReputationOutcome};
pub use handshake::{HandshakePayload, VRF_HANDSHAKE_CONTEXT};
pub use identity::{IdentityError, IdentityMetadata, NodeIdentity, TopicPermission};
pub use peerstore::{IdentityVerifier, PeerRecord, Peerstore, PeerstoreConfig, PeerstoreError};
pub use persistence::{GossipStateError, GossipStateStore};
pub use pipeline::{
    BasicRecursiveProofVerifier, BlockProposal, ConsensusPipeline, JsonProofValidator,
    LightClientSync, MetaTelemetry, PersistentProofStorage, PipelineError, ProofMempool,
    ProofRecord, ProofStorage, SnapshotChunk, SnapshotStore, TelemetryEvent, VoteOutcome,
};
pub use roadmap::{libp2p_backbone_plan, Deliverable, Milestone, Phase, Plan, WorkItem};
pub use security::{RateLimiter, ReplayProtector};
pub use simulator::{NetworkSimulation, SimulationReport};
pub use swarm::{Network, NetworkError, NetworkEvent};
pub use tier::TierLevel;
pub use topics::GossipTopic;
