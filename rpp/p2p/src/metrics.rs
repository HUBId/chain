use crate::handshake::HandshakeOutcome;
use crate::peerstore::{PeerstoreError, ReputationSnapshot};
use crate::tier::TierLevel;
use crate::topics::GossipTopic;
use crate::vendor::PeerId;

#[cfg(feature = "metrics")]
use prometheus_client::metrics::counter::Counter;
#[cfg(feature = "metrics")]
use prometheus_client::metrics::family::Family;
#[cfg(feature = "metrics")]
use prometheus_client::registry::Registry;
#[cfg(feature = "metrics")]
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum GossipDecision {
    Accepted { tier: TierLevel },
    Rejected { reason: String },
}

impl GossipDecision {
    pub fn label(&self) -> &'static str {
        match self {
            GossipDecision::Accepted { .. } => "accepted",
            GossipDecision::Rejected { .. } => "rejected",
        }
    }
}

#[cfg(feature = "metrics")]
struct AdmissionMetricsInner {
    handshake: Family<Vec<(String, String)>, Counter>,
    gossip: Family<Vec<(String, String)>, Counter>,
}

#[cfg(feature = "metrics")]
impl AdmissionMetricsInner {
    fn new(registry: &mut Registry) -> Self {
        let handshake = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "rpp_handshake_decisions",
            "Handshake validation outcomes grouped by decision and tier",
            handshake.clone(),
        );

        let gossip = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "rpp_gossip_decisions",
            "Gossip admission decisions grouped by topic and outcome",
            gossip.clone(),
        );

        Self { handshake, gossip }
    }
}

#[cfg(feature = "metrics")]
#[derive(Clone)]
pub struct AdmissionMetrics {
    inner: Arc<AdmissionMetricsInner>,
}

#[cfg(not(feature = "metrics"))]
#[derive(Clone, Default)]
pub struct AdmissionMetrics;

impl AdmissionMetrics {
    #[cfg(feature = "metrics")]
    pub fn register(registry: &mut Registry) -> Self {
        let inner = AdmissionMetricsInner::new(registry);
        Self {
            inner: Arc::new(inner),
        }
    }

    #[cfg(not(feature = "metrics"))]
    pub fn register(_: &mut Registry) -> Self {
        Self
    }

    pub fn record_handshake(&self, _peer: &PeerId, outcome: &HandshakeOutcome) {
        #[cfg(feature = "metrics")]
        self.record_handshake_inner(outcome);
        let _ = (_peer, outcome);
    }

    pub fn record_handshake_error(&self, _peer: &PeerId, error: &PeerstoreError) {
        #[cfg(feature = "metrics")]
        if let Some(outcome) = handshake_outcome_from_error(error) {
            self.record_handshake_inner(&outcome);
        }
        let _ = (_peer, error);
    }

    pub fn record_gossip(&self, _peer: &PeerId, topic: GossipTopic, decision: &GossipDecision) {
        #[cfg(feature = "metrics")]
        self.record_gossip_inner(topic, decision);
        let _ = (_peer, topic, decision);
    }

    #[cfg(feature = "metrics")]
    fn record_handshake_inner(&self, outcome: &HandshakeOutcome) {
        let mut labels = vec![("decision".to_string(), outcome.label().to_string())];
        match outcome {
            HandshakeOutcome::Accepted { tier, allowlisted } => {
                labels.push(("tier".to_string(), format!("{:?}", tier)));
                labels.push(("allowlisted".to_string(), allowlisted.to_string()));
            }
            HandshakeOutcome::AllowlistTierMismatch { required, actual } => {
                labels.push(("required".to_string(), format!("{:?}", required)));
                labels.push(("actual".to_string(), format!("{:?}", actual)));
            }
            HandshakeOutcome::InvalidVrf { reason } => {
                labels.push(("reason".to_string(), reason.clone()));
            }
            _ => {}
        }
        self.inner.handshake.get_or_create(&labels).inc();
    }

    #[cfg(feature = "metrics")]
    fn record_gossip_inner(&self, topic: GossipTopic, decision: &GossipDecision) {
        let mut labels = vec![
            ("topic".to_string(), topic.as_str().to_string()),
            ("decision".to_string(), decision.label().to_string()),
        ];
        match decision {
            GossipDecision::Accepted { tier } => {
                labels.push(("tier".to_string(), format!("{:?}", tier)));
            }
            GossipDecision::Rejected { reason } => {
                labels.push(("reason".to_string(), reason.clone()));
            }
        }
        self.inner.gossip.get_or_create(&labels).inc();
    }
}

#[cfg(feature = "metrics")]
fn handshake_outcome_from_error(error: &PeerstoreError) -> Option<HandshakeOutcome> {
    match error {
        PeerstoreError::Blocklisted { .. } => Some(HandshakeOutcome::Blocklisted),
        PeerstoreError::MissingPublicKey { .. } => Some(HandshakeOutcome::MissingPublicKey),
        PeerstoreError::MissingSignature => Some(HandshakeOutcome::MissingSignature),
        PeerstoreError::InvalidSignature { .. } => Some(HandshakeOutcome::InvalidSignature),
        PeerstoreError::InvalidVrf { reason, .. } => Some(HandshakeOutcome::InvalidVrf {
            reason: reason.clone(),
        }),
        PeerstoreError::TierBelowAllowlist {
            required, actual, ..
        } => Some(HandshakeOutcome::AllowlistTierMismatch {
            required: *required,
            actual: *actual,
        }),
        _ => None,
    }
}

pub fn gossip_decision_for_snapshot(snapshot: &ReputationSnapshot) -> GossipDecision {
    GossipDecision::Accepted {
        tier: snapshot.tier,
    }
}

pub fn gossip_rejection(reason: String) -> GossipDecision {
    GossipDecision::Rejected { reason }
}
