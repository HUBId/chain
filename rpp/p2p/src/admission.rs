use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::vendor::PeerId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::IdentityMetadata;
use crate::peerstore::{Peerstore, PeerstoreError, ReputationSnapshot};
use crate::tier::TierLevel;
use crate::topics::GossipTopic;

const DEFAULT_GOSSIP_REWARD: f64 = 0.2;
const DEFAULT_UPTIME_REWARD: f64 = 0.3;
const DEFAULT_VOTE_REWARD: f64 = 0.6;
const DEFAULT_SLASH_PENALTY: f64 = 2.5;
const DEFAULT_PENALTY_THRESHOLD: f64 = 0.1;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    #[error("unknown peer")]
    UnknownPeer,
    #[error("peer banned until {until:?}")]
    Banned { until: SystemTime },
    #[error("tier {actual:?} below required {required:?}")]
    TierInsufficient {
        required: TierLevel,
        actual: TierLevel,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReputationEvent {
    GossipSuccess {
        topic: GossipTopic,
    },
    UptimeProof,
    VoteIncluded,
    VoteTimeout {
        height: u64,
        round: u64,
    },
    ProofRelayMissed {
        #[serde(skip_serializing_if = "Option::is_none")]
        height: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<Cow<'static, str>>,
    },
    GossipBackpressure {
        topic: GossipTopic,
        queue_depth: usize,
    },
    Slash {
        severity: f64,
        reason: Cow<'static, str>,
    },
    ManualPenalty {
        amount: f64,
        reason: Cow<'static, str>,
    },
}

impl ReputationEvent {
    pub fn label(&self) -> &str {
        match self {
            ReputationEvent::GossipSuccess { .. } => "gossip_success",
            ReputationEvent::UptimeProof => "uptime_proof",
            ReputationEvent::VoteIncluded => "vote_included",
            ReputationEvent::VoteTimeout { .. } => "vote_timeout",
            ReputationEvent::ProofRelayMissed { .. } => "proof_relay_missed",
            ReputationEvent::GossipBackpressure { .. } => "gossip_backpressure",
            ReputationEvent::Slash { reason, .. } => reason.as_ref(),
            ReputationEvent::ManualPenalty { reason, .. } => reason.as_ref(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ReputationHeuristics {
    pub vote_timeout_penalty: f64,
    pub proof_relay_penalty: f64,
    pub gossip_backpressure_penalty: f64,
    pub gossip_backpressure_threshold: usize,
}

impl Default for ReputationHeuristics {
    fn default() -> Self {
        Self {
            vote_timeout_penalty: 0.4,
            proof_relay_penalty: 0.6,
            gossip_backpressure_penalty: 0.25,
            gossip_backpressure_threshold: 4,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReputationOutcome {
    pub snapshot: ReputationSnapshot,
    pub label: String,
    pub event: ReputationEvent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationBroadcast {
    pub peer: String,
    pub event: ReputationEvent,
    pub reputation: f64,
    pub tier: TierLevel,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub banned_until: Option<u64>,
    pub label: String,
}

impl ReputationBroadcast {
    pub fn new(outcome: &ReputationOutcome) -> Self {
        let banned_until = outcome
            .snapshot
            .banned_until
            .and_then(|until| until.duration_since(UNIX_EPOCH).ok())
            .map(|duration| duration.as_millis() as u64);
        Self {
            peer: outcome.snapshot.peer_id.to_base58(),
            event: outcome.event.clone(),
            reputation: outcome.snapshot.reputation,
            tier: outcome.snapshot.tier,
            banned_until,
            label: outcome.label.clone(),
        }
    }

    pub fn peer_id(&self) -> Result<PeerId, String> {
        self.peer
            .parse()
            .map_err(|err| format!("invalid peer id: {err}"))
    }

    pub fn banned_until_time(&self) -> Option<SystemTime> {
        self.banned_until
            .map(|millis| UNIX_EPOCH + Duration::from_millis(millis))
    }
}

#[derive(Debug)]
pub struct AdmissionControl {
    peerstore: Arc<Peerstore>,
    metadata: IdentityMetadata,
    gossip_reward: f64,
    uptime_reward: f64,
    vote_reward: f64,
    slash_penalty: f64,
    ban_window: Duration,
    heuristics: ReputationHeuristics,
}

impl AdmissionControl {
    pub fn new(peerstore: Arc<Peerstore>, metadata: IdentityMetadata) -> Self {
        Self::with_heuristics(peerstore, metadata, ReputationHeuristics::default())
    }

    pub fn with_heuristics(
        peerstore: Arc<Peerstore>,
        metadata: IdentityMetadata,
        heuristics: ReputationHeuristics,
    ) -> Self {
        Self {
            peerstore,
            metadata,
            gossip_reward: DEFAULT_GOSSIP_REWARD,
            uptime_reward: DEFAULT_UPTIME_REWARD,
            vote_reward: DEFAULT_VOTE_REWARD,
            slash_penalty: DEFAULT_SLASH_PENALTY,
            ban_window: Duration::from_secs(180),
            heuristics,
        }
    }

    fn topic_policy(&self, topic: GossipTopic) -> (TierLevel, TierLevel) {
        let policy = self.metadata.policy_for(topic);
        (policy.subscribe, policy.publish)
    }

    fn ensure_tier(required: TierLevel, actual: TierLevel) -> Result<(), AdmissionError> {
        if actual >= required {
            Ok(())
        } else {
            Err(AdmissionError::TierInsufficient { required, actual })
        }
    }

    pub fn can_subscribe_local(
        &self,
        tier: TierLevel,
        topic: GossipTopic,
    ) -> Result<(), AdmissionError> {
        let (required, _) = self.topic_policy(topic);
        Self::ensure_tier(required, tier)
    }

    pub fn can_publish_local(
        &self,
        tier: TierLevel,
        topic: GossipTopic,
    ) -> Result<(), AdmissionError> {
        let (_, required) = self.topic_policy(topic);
        Self::ensure_tier(required, tier)
    }

    pub fn can_remote_subscribe(
        &self,
        peer: &PeerId,
        topic: GossipTopic,
    ) -> Result<ReputationSnapshot, AdmissionError> {
        if self.peerstore.is_blocklisted(peer) {
            let until = self
                .peerstore
                .is_banned(peer)
                .unwrap_or_else(|| SystemTime::now() + self.ban_window);
            return Err(AdmissionError::Banned { until });
        }
        let snapshot = self
            .peerstore
            .reputation_snapshot(peer)
            .ok_or(AdmissionError::UnknownPeer)?;
        if let Some(until) = snapshot.banned_until {
            return Err(AdmissionError::Banned { until });
        }
        let (required, _) = self.topic_policy(topic);
        Self::ensure_tier(required, snapshot.tier)?;
        Ok(snapshot)
    }

    pub fn can_remote_publish(
        &self,
        peer: &PeerId,
        topic: GossipTopic,
    ) -> Result<ReputationSnapshot, AdmissionError> {
        if self.peerstore.is_blocklisted(peer) {
            let until = self
                .peerstore
                .is_banned(peer)
                .unwrap_or_else(|| SystemTime::now() + self.ban_window);
            return Err(AdmissionError::Banned { until });
        }
        let snapshot = self
            .peerstore
            .reputation_snapshot(peer)
            .ok_or(AdmissionError::UnknownPeer)?;
        if let Some(until) = snapshot.banned_until {
            return Err(AdmissionError::Banned { until });
        }
        let (_, required) = self.topic_policy(topic);
        Self::ensure_tier(required, snapshot.tier)?;
        Ok(snapshot)
    }

    pub fn evaluate_publish(
        &self,
        peer: &PeerId,
        topic: GossipTopic,
    ) -> Result<ReputationSnapshot, AdmissionError> {
        self.can_remote_publish(peer, topic)
    }

    pub fn sanitize_evaluate_publish(
        &self,
        peer: &PeerId,
        topic: GossipTopic,
    ) -> Result<(), AdmissionError> {
        self.evaluate_publish(peer, topic).map(|_| ())
    }

    pub fn record_event(
        &self,
        peer: PeerId,
        event: ReputationEvent,
    ) -> Result<ReputationOutcome, PeerstoreError> {
        let snapshot = match &event {
            ReputationEvent::GossipSuccess { topic } => {
                let reward = match topic {
                    GossipTopic::Blocks | GossipTopic::Votes => self.gossip_reward * 2.0,
                    GossipTopic::Proofs => self.gossip_reward,
                    GossipTopic::VrfProofs => self.gossip_reward * 1.1,
                    GossipTopic::Snapshots => self.gossip_reward * 1.5,
                    GossipTopic::Meta => self.gossip_reward * 0.5,
                    GossipTopic::VrfMeta => self.gossip_reward * 0.6,
                    GossipTopic::WitnessProofs => self.gossip_reward * 1.2,
                    GossipTopic::WitnessMeta => self.gossip_reward * 0.75,
                };
                self.peerstore.update_reputation(peer.clone(), reward)?
            }
            ReputationEvent::UptimeProof => self
                .peerstore
                .update_reputation(peer.clone(), self.uptime_reward)?,
            ReputationEvent::VoteIncluded => self
                .peerstore
                .update_reputation(peer.clone(), self.vote_reward)?,
            ReputationEvent::VoteTimeout { .. } => self
                .peerstore
                .update_reputation(peer.clone(), -self.heuristics.vote_timeout_penalty)?,
            ReputationEvent::ProofRelayMissed { .. } => self
                .peerstore
                .update_reputation(peer.clone(), -self.heuristics.proof_relay_penalty)?,
            ReputationEvent::GossipBackpressure { queue_depth, .. } => {
                if *queue_depth < self.heuristics.gossip_backpressure_threshold {
                    match self.peerstore.reputation_snapshot(&peer) {
                        Some(snapshot) => snapshot,
                        None => self.peerstore.update_reputation(peer.clone(), 0.0)?,
                    }
                } else {
                    self.peerstore.update_reputation(
                        peer.clone(),
                        -self.heuristics.gossip_backpressure_penalty,
                    )?
                }
            }
            ReputationEvent::Slash { severity, .. } => {
                let penalty = -(self.slash_penalty * severity.max(1.0));
                let snapshot = self.peerstore.update_reputation(peer.clone(), penalty)?;
                if severity >= 1.0 || snapshot.reputation < DEFAULT_PENALTY_THRESHOLD {
                    let until = SystemTime::now() + self.ban_window;
                    self.peerstore.ban_peer_until(peer.clone(), until)?
                } else {
                    snapshot
                }
            }
            ReputationEvent::ManualPenalty { amount, .. } => {
                let snapshot = self
                    .peerstore
                    .update_reputation(peer.clone(), -amount.abs())?;
                if snapshot.reputation < DEFAULT_PENALTY_THRESHOLD {
                    let until = SystemTime::now() + self.ban_window;
                    self.peerstore.ban_peer_until(peer.clone(), until)?
                } else {
                    snapshot
                }
            }
        };

        let final_snapshot = self
            .peerstore
            .reputation_snapshot(&peer)
            .unwrap_or(snapshot);

        Ok(ReputationOutcome {
            snapshot: final_snapshot,
            label: event.label().to_string(),
            event,
        })
    }

    pub fn peerstore(&self) -> &Arc<Peerstore> {
        &self.peerstore
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::{HandshakePayload, VRF_HANDSHAKE_CONTEXT};
    use crate::peerstore::{IdentityVerifier, PeerstoreConfig};
    use crate::vendor::identity;
    use proptest::prelude::*;
    use rand::rngs::OsRng;
    use schnorrkel::keys::{ExpansionMode, MiniSecretKey};
    use std::collections::HashMap;
    use std::sync::Arc;

    #[derive(Default)]
    struct StaticVerifier {
        expected: HashMap<String, Vec<u8>>,
    }

    impl StaticVerifier {
        fn new(entries: impl IntoIterator<Item = (String, Vec<u8>)>) -> Self {
            Self {
                expected: entries.into_iter().collect(),
            }
        }
    }

    impl IdentityVerifier for StaticVerifier {
        fn expected_vrf_public_key(&self, zsi_id: &str) -> Option<Vec<u8>> {
            self.expected.get(zsi_id).cloned()
        }
    }

    fn sign_vrf_message(secret: &MiniSecretKey, payload: &HandshakePayload) -> Vec<u8> {
        let keypair = secret.expand_to_keypair(ExpansionMode::Uniform);
        keypair
            .sign_simple(VRF_HANDSHAKE_CONTEXT, &payload.vrf_message())
            .to_bytes()
            .to_vec()
    }

    fn signed_handshake(
        keypair: &identity::Keypair,
        tier: TierLevel,
        vrf_secret: Option<&MiniSecretKey>,
    ) -> HandshakePayload {
        let (vrf_public_key, vrf_proof) = if let Some(secret) = vrf_secret {
            let public = secret
                .expand_to_keypair(ExpansionMode::Uniform)
                .public
                .to_bytes()
                .to_vec();
            let template = HandshakePayload::new("peer", Some(public.clone()), None, tier);
            let proof = sign_vrf_message(secret, &template);
            (Some(public), Some(proof))
        } else {
            (None, None)
        };
        let template = HandshakePayload::new("peer", vrf_public_key, vrf_proof, tier);
        template.signed(keypair).expect("handshake")
    }

    #[test]
    fn enforces_tier_requirements() {
        let mut rng = OsRng;
        let secret = MiniSecretKey::generate_with(&mut rng);
        let public = secret
            .expand_to_keypair(ExpansionMode::Uniform)
            .public
            .to_bytes()
            .to_vec();
        let verifier = Arc::new(StaticVerifier::new(vec![("peer".to_string(), public)]));
        let store = Arc::new(
            Peerstore::open(PeerstoreConfig::memory().with_identity_verifier(verifier))
                .expect("open"),
        );
        let control = AdmissionControl::new(store.clone(), IdentityMetadata::default());
        let keypair = identity::Keypair::generate_ed25519();
        let peer = PeerId::from(keypair.public());

        store
            .record_handshake(
                peer,
                &signed_handshake(&keypair, TierLevel::Tl2, Some(&secret)),
            )
            .expect("handshake");

        assert!(control
            .can_remote_publish(&peer, GossipTopic::WitnessProofs)
            .is_ok());
        assert!(matches!(
            control.can_remote_publish(&peer, GossipTopic::Votes),
            Err(AdmissionError::TierInsufficient { .. })
        ));
    }

    proptest! {
        #[test]
        fn tier_gating_matches_threshold(score in 0.0f64..10.0) {
            let mut rng = OsRng;
            let secret = MiniSecretKey::generate_with(&mut rng);
        let public = secret
            .expand_to_keypair(ExpansionMode::Uniform)
            .public
            .to_bytes()
            .to_vec();
            let verifier = Arc::new(StaticVerifier::new(vec![("peer".to_string(), public)]));
            let store = Arc::new(
                Peerstore::open(PeerstoreConfig::memory().with_identity_verifier(verifier))
                    .expect("open"),
            );
            let control = AdmissionControl::new(store.clone(), IdentityMetadata::default());
            let keypair = identity::Keypair::generate_ed25519();
            let peer = PeerId::from(keypair.public());
            let tier = TierLevel::from_reputation(score);

            store
                .record_handshake(peer, &signed_handshake(&keypair, tier, Some(&secret)))
                .expect("handshake");
            store
                .set_reputation(peer, score)
                .expect("reputation");

            let proofs_allowed = control.can_remote_publish(&peer, GossipTopic::WitnessProofs).is_ok();
            let votes_allowed = control.can_remote_publish(&peer, GossipTopic::Votes).is_ok();
            prop_assert_eq!(proofs_allowed, tier >= TierLevel::Tl2);
            prop_assert_eq!(votes_allowed, tier >= TierLevel::Tl3);
        }
    }
}
