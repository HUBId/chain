//! RPP P2P stack - libp2p-backed networking primitives.

mod admission;
mod handshake;
mod identity;
mod persistence;
mod peerstore;
mod pipeline;
mod roadmap;
mod simulator;
mod security;
mod swarm;
mod tier;
mod topics;

pub use admission::{AdmissionControl, AdmissionError, ReputationEvent, ReputationOutcome};
pub use handshake::HandshakePayload;
pub use identity::{IdentityError, NodeIdentity};
pub use peerstore::{PeerRecord, Peerstore, PeerstoreConfig, PeerstoreError};
pub use pipeline::{
    BlockProposal, ConsensusPipeline, LightClientSync, MetaTelemetry, PersistentProofStorage,
    PipelineError, ProofMempool, ProofRecord, ProofStorage, SnapshotChunk, SnapshotStore,
    TelemetryEvent, VoteOutcome,
};
pub use persistence::{GossipStateError, GossipStateStore};
pub use roadmap::{libp2p_backbone_plan, Deliverable, Milestone, Phase, Plan, WorkItem};
pub use simulator::{NetworkSimulation, SimulationReport};
pub use security::{RateLimiter, ReplayProtector};
pub use swarm::{Network, NetworkEvent, NetworkError};
pub use tier::TierLevel;
pub use topics::GossipTopic;
