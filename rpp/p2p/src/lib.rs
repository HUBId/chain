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
mod policy_signing;
mod roadmap;
mod security;
mod simulator;
mod swarm;
mod tier;
mod topics;
mod worm_export;

pub mod vendor;

/// [`libp2p_swarm::ConnectionHandler`] that does not support any protocols or events.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmptyConnectionHandler;

impl libp2p_swarm::ConnectionHandler for EmptyConnectionHandler {
    type FromBehaviour = core::convert::Infallible;
    type ToBehaviour = core::convert::Infallible;
    type InboundProtocol = libp2p_core::upgrade::DeniedUpgrade;
    type OutboundProtocol = libp2p_core::upgrade::DeniedUpgrade;
    type InboundOpenInfo = ();
    type OutboundOpenInfo = ();

    fn listen_protocol(
        &self,
    ) -> libp2p_swarm::SubstreamProtocol<Self::InboundProtocol, Self::InboundOpenInfo> {
        libp2p_swarm::SubstreamProtocol::new(libp2p_core::upgrade::DeniedUpgrade, ())
    }

    fn on_behaviour_event(&mut self, event: Self::FromBehaviour) {
        match event {}
    }

    fn poll(
        &mut self,
        _: &mut core::task::Context<'_>,
    ) -> core::task::Poll<
        libp2p_swarm::ConnectionHandlerEvent<
            Self::OutboundProtocol,
            Self::OutboundOpenInfo,
            Self::ToBehaviour,
        >,
    > {
        core::task::Poll::Pending
    }

    fn on_connection_event(
        &mut self,
        event: libp2p_swarm::handler::ConnectionEvent<
            Self::InboundProtocol,
            Self::OutboundProtocol,
            Self::InboundOpenInfo,
            Self::OutboundOpenInfo,
        >,
    ) {
        use libp2p_swarm::handler::{
            ConnectionEvent, DialUpgradeError, FullyNegotiatedInbound, FullyNegotiatedOutbound,
            ListenUpgradeError,
        };
        use libp2p_swarm::StreamUpgradeError;

        match event {
            ConnectionEvent::FullyNegotiatedInbound(FullyNegotiatedInbound {
                protocol, ..
            }) => match protocol {},
            ConnectionEvent::FullyNegotiatedOutbound(FullyNegotiatedOutbound {
                protocol, ..
            }) => match protocol {},
            ConnectionEvent::DialUpgradeError(DialUpgradeError { error, .. }) => match error {
                StreamUpgradeError::Timeout | StreamUpgradeError::NegotiationFailed => {}
                StreamUpgradeError::Apply(error) => match error {},
                StreamUpgradeError::Io(_) => {
                    unreachable!("Denied upgrade does not support any protocols")
                }
            },
            ConnectionEvent::ListenUpgradeError(ListenUpgradeError { error, .. }) => match error {},
            ConnectionEvent::AddressChange(_)
            | ConnectionEvent::LocalProtocolsChange(_)
            | ConnectionEvent::RemoteProtocolsChange(_) => {}
        }
    }
}

/// Re-exports required by the `#[derive(NetworkBehaviour)]` macro.
pub mod derive_prelude {
    pub use crate::EmptyConnectionHandler;
    pub use libp2p_swarm::derive_prelude::*;
}

pub use admission::{
    AdmissionControl, AdmissionError, DualControlApprovalService, DualControlError,
    PendingPolicyChange, ReputationBroadcast, ReputationEvent, ReputationHeuristics,
    ReputationOutcome,
};
pub use behaviour::snapshots::{
    NullSnapshotProvider, SnapshotBreakerStatus, SnapshotItemKind, SnapshotProvider,
    SnapshotResumeState, SnapshotSessionId, SnapshotsRequest, SnapshotsResponse,
};
#[cfg(feature = "request-response")]
pub use behaviour::snapshots::{
    SnapshotProtocolError, SnapshotsBehaviour, SnapshotsBehaviourConfig, SnapshotsEvent,
};
pub use behaviour::witness::{
    WitnessChannelConfig, WitnessGossipPipelines, WitnessMessage, WitnessPipelineConfig,
    WitnessPipelineError,
};
pub use handshake::{HandshakePayload, VRF_HANDSHAKE_CONTEXT};
pub use identity::{IdentityError, IdentityMetadata, NodeIdentity, TopicPermission};
pub use peerstore::{
    AdmissionApproval, AdmissionAuditTrail, AdmissionPolicies, AdmissionPolicyBackup,
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
    NetworkPruningCommitment, NetworkPruningEnvelope, NetworkPruningSegment,
    NetworkPruningSnapshot, NetworkReconstructionRequest, NetworkSnapshotSummary,
    NetworkStateSyncChunk, NetworkStateSyncPlan, NetworkTaggedDigestHex, PersistentProofStorage,
    PipelineError, ProofCacheMetrics, ProofCacheMetricsSnapshot, ProofMempool, ProofRecord,
    ProofStorage, ResumeBoundKind, RuntimeProofValidator, SnapshotChunk, SnapshotChunkStream,
    SnapshotStore, TelemetryEvent, TransactionProofVerifier, VoteOutcome,
};
pub use policy_log::{
    AdmissionPolicyChange, AdmissionPolicyLogEntry, AdmissionPolicyLogError,
    AdmissionPolicyLogOptions, PolicyAllowlistState,
};
pub use policy_signing::{
    PolicySignature, PolicySignatureVerifier, PolicySigner, PolicySigningError, PolicyTrustStore,
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
pub use worm_export::{
    CommandWormExporter, S3WormExporter, WormExportError, WormExportSettings, WormExporter,
    WormRetention, WormRetentionMode,
};
