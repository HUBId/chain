use std::sync::Arc;
use std::time::{Duration, SystemTime};

use libp2p::PeerId;
use thiserror::Error;

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

#[derive(Debug, Clone)]
pub enum ReputationEvent {
    GossipSuccess { topic: GossipTopic },
    UptimeProof,
    VoteIncluded,
    Slash { severity: f64, reason: &'static str },
    ManualPenalty { amount: f64, reason: &'static str },
}

impl ReputationEvent {
    pub fn label(&self) -> &'static str {
        match self {
            ReputationEvent::GossipSuccess { .. } => "gossip_success",
            ReputationEvent::UptimeProof => "uptime_proof",
            ReputationEvent::VoteIncluded => "vote_included",
            ReputationEvent::Slash { reason, .. } => reason,
            ReputationEvent::ManualPenalty { reason, .. } => reason,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReputationOutcome {
    pub snapshot: ReputationSnapshot,
    pub label: &'static str,
}

#[derive(Debug)]
pub struct AdmissionControl {
    peerstore: Arc<Peerstore>,
    gossip_reward: f64,
    uptime_reward: f64,
    vote_reward: f64,
    slash_penalty: f64,
    ban_window: Duration,
}

impl AdmissionControl {
    pub fn new(peerstore: Arc<Peerstore>) -> Self {
        Self {
            peerstore,
            gossip_reward: DEFAULT_GOSSIP_REWARD,
            uptime_reward: DEFAULT_UPTIME_REWARD,
            vote_reward: DEFAULT_VOTE_REWARD,
            slash_penalty: DEFAULT_SLASH_PENALTY,
            ban_window: Duration::from_secs(180),
        }
    }

    fn topic_policy(topic: GossipTopic) -> (TierLevel, TierLevel) {
        match topic {
            GossipTopic::Blocks | GossipTopic::Votes => (TierLevel::Tl0, TierLevel::Tl3),
            GossipTopic::Proofs => (TierLevel::Tl0, TierLevel::Tl1),
            GossipTopic::Snapshots => (TierLevel::Tl0, TierLevel::Tl1),
            GossipTopic::Meta => (TierLevel::Tl0, TierLevel::Tl0),
        }
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
        let (required, _) = Self::topic_policy(topic);
        Self::ensure_tier(required, tier)
    }

    pub fn can_publish_local(
        &self,
        tier: TierLevel,
        topic: GossipTopic,
    ) -> Result<(), AdmissionError> {
        let (_, required) = Self::topic_policy(topic);
        Self::ensure_tier(required, tier)
    }

    pub fn can_remote_subscribe(
        &self,
        peer: &PeerId,
        topic: GossipTopic,
    ) -> Result<ReputationSnapshot, AdmissionError> {
        let snapshot = self
            .peerstore
            .reputation_snapshot(peer)
            .ok_or(AdmissionError::UnknownPeer)?;
        if let Some(until) = snapshot.banned_until {
            return Err(AdmissionError::Banned { until });
        }
        let (required, _) = Self::topic_policy(topic);
        Self::ensure_tier(required, snapshot.tier)?;
        Ok(snapshot)
    }

    pub fn can_remote_publish(
        &self,
        peer: &PeerId,
        topic: GossipTopic,
    ) -> Result<ReputationSnapshot, AdmissionError> {
        let snapshot = self
            .peerstore
            .reputation_snapshot(peer)
            .ok_or(AdmissionError::UnknownPeer)?;
        if let Some(until) = snapshot.banned_until {
            return Err(AdmissionError::Banned { until });
        }
        let (_, required) = Self::topic_policy(topic);
        Self::ensure_tier(required, snapshot.tier)?;
        Ok(snapshot)
    }

    pub fn record_event(
        &self,
        peer: PeerId,
        event: ReputationEvent,
    ) -> Result<ReputationOutcome, PeerstoreError> {
        let snapshot = match event {
            ReputationEvent::GossipSuccess { topic } => {
                let reward = match topic {
                    GossipTopic::Blocks | GossipTopic::Votes => self.gossip_reward * 2.0,
                    GossipTopic::Proofs => self.gossip_reward,
                    GossipTopic::Snapshots => self.gossip_reward * 1.5,
                    GossipTopic::Meta => self.gossip_reward * 0.5,
                };
                self.peerstore.update_reputation(peer, reward)?
            }
            ReputationEvent::UptimeProof => {
                self.peerstore.update_reputation(peer, self.uptime_reward)?
            }
            ReputationEvent::VoteIncluded => {
                self.peerstore.update_reputation(peer, self.vote_reward)?
            }
            ReputationEvent::Slash { severity, .. } => {
                let penalty = -(self.slash_penalty * severity.max(1.0));
                let snapshot = self.peerstore.update_reputation(peer, penalty)?;
                if severity >= 1.0 || snapshot.reputation < DEFAULT_PENALTY_THRESHOLD {
                    let until = SystemTime::now() + self.ban_window;
                    self.peerstore.ban_peer_until(peer, until)?
                } else {
                    snapshot
                }
            }
            ReputationEvent::ManualPenalty { amount, .. } => {
                let snapshot = self.peerstore.update_reputation(peer, -amount.abs())?;
                if snapshot.reputation < DEFAULT_PENALTY_THRESHOLD {
                    let until = SystemTime::now() + self.ban_window;
                    self.peerstore.ban_peer_until(peer, until)?
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
            label: event.label(),
        })
    }

    pub fn peerstore(&self) -> &Arc<Peerstore> {
        &self.peerstore
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake::HandshakePayload;
    use crate::peerstore::PeerstoreConfig;
    use proptest::prelude::*;
    use libp2p::identity;

    fn signed_handshake(
        keypair: &identity::Keypair,
        tier: TierLevel,
    ) -> HandshakePayload {
        HandshakePayload::new("peer", None, tier)
            .signed(keypair)
            .expect("handshake")
    }

    #[test]
    fn enforces_tier_requirements() {
        let store = Arc::new(Peerstore::open(PeerstoreConfig::memory()).expect("open"));
        let control = AdmissionControl::new(store.clone());
        let keypair = identity::Keypair::generate_ed25519();
        let peer = PeerId::from(keypair.public());

        store
            .record_handshake(
                peer,
                &signed_handshake(&keypair, TierLevel::Tl1),
            )
            .expect("handshake");

        assert!(
            control
                .can_remote_publish(&peer, GossipTopic::Proofs)
                .is_ok()
        );
        assert!(matches!(
            control.can_remote_publish(&peer, GossipTopic::Votes),
            Err(AdmissionError::TierInsufficient { .. })
        ));
    }

    proptest! {
        #[test]
        fn tier_gating_matches_threshold(score in 0.0f64..10.0) {
            let store = Arc::new(Peerstore::open(PeerstoreConfig::memory()).expect("open"));
            let control = AdmissionControl::new(store.clone());
            let keypair = identity::Keypair::generate_ed25519();
            let peer = PeerId::from(keypair.public());
            let tier = TierLevel::from_reputation(score);

            store
                .record_handshake(peer, &signed_handshake(&keypair, tier))
                .expect("handshake");
            store
                .set_reputation(peer, score)
                .expect("reputation");

            let proofs_allowed = control.can_remote_publish(&peer, GossipTopic::Proofs).is_ok();
            let votes_allowed = control.can_remote_publish(&peer, GossipTopic::Votes).is_ok();
            prop_assert_eq!(proofs_allowed, tier >= TierLevel::Tl1);
            prop_assert_eq!(votes_allowed, tier >= TierLevel::Tl3);
        }
    }
}
