use serde::{Deserialize, Serialize};

#[cfg(feature = "gossipsub")]
use crate::vendor::gossipsub::{IdentTopic, TopicHash};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum TopicPriority {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopicQoS {
    Realtime,
    Throughput,
    Background,
    Telemetry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicMetadata {
    pub priority: TopicPriority,
    pub qos: TopicQoS,
}

impl TopicMetadata {
    pub const fn new(priority: TopicPriority, qos: TopicQoS) -> Self {
        Self { priority, qos }
    }
}

/// Canonical GossipSub topics used by the RPP network backbone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GossipTopic {
    Blocks,
    Votes,
    Proofs,
    VrfProofs,
    Snapshots,
    Meta,
    VrfMeta,
    WitnessProofs,
    WitnessMeta,
}

impl GossipTopic {
    pub const fn as_str(&self) -> &'static str {
        match self {
            GossipTopic::Blocks => "/rpp/gossip/blocks/1.0.0",
            GossipTopic::Votes => "/rpp/gossip/votes/1.0.0",
            GossipTopic::Proofs => "/rpp/gossip/proofs/1.0.0",
            GossipTopic::VrfProofs => "/rpp/gossip/vrf/proofs/1.0.0",
            GossipTopic::Snapshots => "/rpp/gossip/snapshots/1.0.0",
            GossipTopic::Meta => "/rpp/gossip/meta/1.0.0",
            GossipTopic::VrfMeta => "/rpp/gossip/vrf/meta/1.0.0",
            GossipTopic::WitnessProofs => "/rpp/gossip/witness/proofs/1.0.0",
            GossipTopic::WitnessMeta => "/rpp/gossip/witness/meta/1.0.0",
        }
    }

    #[cfg(feature = "gossipsub")]
    pub fn ident(self) -> IdentTopic {
        IdentTopic::new(self.as_str())
    }

    #[cfg(feature = "gossipsub")]
    pub fn from_hash(hash: &TopicHash) -> Option<Self> {
        match hash.as_str() {
            "/rpp/gossip/blocks/1.0.0" => Some(GossipTopic::Blocks),
            "/rpp/gossip/votes/1.0.0" => Some(GossipTopic::Votes),
            "/rpp/gossip/proofs/1.0.0" => Some(GossipTopic::Proofs),
            "/rpp/gossip/vrf/proofs/1.0.0" => Some(GossipTopic::VrfProofs),
            "/rpp/gossip/snapshots/1.0.0" => Some(GossipTopic::Snapshots),
            "/rpp/gossip/meta/1.0.0" => Some(GossipTopic::Meta),
            "/rpp/gossip/vrf/meta/1.0.0" => Some(GossipTopic::VrfMeta),
            "/rpp/gossip/witness/proofs/1.0.0" => Some(GossipTopic::WitnessProofs),
            "/rpp/gossip/witness/meta/1.0.0" => Some(GossipTopic::WitnessMeta),
            _ => None,
        }
    }

    pub const fn all() -> [GossipTopic; 9] {
        [
            GossipTopic::Blocks,
            GossipTopic::Votes,
            GossipTopic::Proofs,
            GossipTopic::VrfProofs,
            GossipTopic::Snapshots,
            GossipTopic::Meta,
            GossipTopic::VrfMeta,
            GossipTopic::WitnessProofs,
            GossipTopic::WitnessMeta,
        ]
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "/rpp/gossip/blocks/1.0.0" => Some(GossipTopic::Blocks),
            "/rpp/gossip/votes/1.0.0" => Some(GossipTopic::Votes),
            "/rpp/gossip/proofs/1.0.0" => Some(GossipTopic::Proofs),
            "/rpp/gossip/vrf/proofs/1.0.0" => Some(GossipTopic::VrfProofs),
            "/rpp/gossip/snapshots/1.0.0" => Some(GossipTopic::Snapshots),
            "/rpp/gossip/meta/1.0.0" => Some(GossipTopic::Meta),
            "/rpp/gossip/vrf/meta/1.0.0" => Some(GossipTopic::VrfMeta),
            "/rpp/gossip/witness/proofs/1.0.0" => Some(GossipTopic::WitnessProofs),
            "/rpp/gossip/witness/meta/1.0.0" => Some(GossipTopic::WitnessMeta),
            _ => None,
        }
    }

    pub const fn metadata(&self) -> TopicMetadata {
        match self {
            GossipTopic::Blocks => TopicMetadata::new(TopicPriority::Critical, TopicQoS::Realtime),
            GossipTopic::Votes => TopicMetadata::new(TopicPriority::Critical, TopicQoS::Realtime),
            GossipTopic::Proofs => TopicMetadata::new(TopicPriority::High, TopicQoS::Throughput),
            GossipTopic::VrfProofs => TopicMetadata::new(TopicPriority::High, TopicQoS::Throughput),
            GossipTopic::Snapshots => {
                TopicMetadata::new(TopicPriority::Medium, TopicQoS::Background)
            }
            GossipTopic::Meta => TopicMetadata::new(TopicPriority::Low, TopicQoS::Telemetry),
            GossipTopic::VrfMeta => TopicMetadata::new(TopicPriority::Low, TopicQoS::Telemetry),
            GossipTopic::WitnessProofs => {
                TopicMetadata::new(TopicPriority::Critical, TopicQoS::Throughput)
            }
            GossipTopic::WitnessMeta => {
                TopicMetadata::new(TopicPriority::High, TopicQoS::Telemetry)
            }
        }
    }

    pub const fn priority(&self) -> TopicPriority {
        self.metadata().priority
    }

    pub const fn qos(&self) -> TopicQoS {
        self.metadata().qos
    }
}

impl std::fmt::Display for GossipTopic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
