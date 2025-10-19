use crate::vendor::gossipsub::{IdentTopic, TopicHash};

/// Canonical GossipSub topics used by the RPP network backbone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GossipTopic {
    Blocks,
    Votes,
    Proofs,
    Snapshots,
    Meta,
}

impl GossipTopic {
    pub const fn as_str(&self) -> &'static str {
        match self {
            GossipTopic::Blocks => "/rpp/gossip/blocks/1.0.0",
            GossipTopic::Votes => "/rpp/gossip/votes/1.0.0",
            GossipTopic::Proofs => "/rpp/gossip/proofs/1.0.0",
            GossipTopic::Snapshots => "/rpp/gossip/snapshots/1.0.0",
            GossipTopic::Meta => "/rpp/gossip/meta/1.0.0",
        }
    }

    pub fn ident(self) -> IdentTopic {
        IdentTopic::new(self.as_str())
    }

    pub fn from_hash(hash: &TopicHash) -> Option<Self> {
        match hash.as_str() {
            "/rpp/gossip/blocks/1.0.0" => Some(GossipTopic::Blocks),
            "/rpp/gossip/votes/1.0.0" => Some(GossipTopic::Votes),
            "/rpp/gossip/proofs/1.0.0" => Some(GossipTopic::Proofs),
            "/rpp/gossip/snapshots/1.0.0" => Some(GossipTopic::Snapshots),
            "/rpp/gossip/meta/1.0.0" => Some(GossipTopic::Meta),
            _ => None,
        }
    }

    pub const fn all() -> [GossipTopic; 5] {
        [
            GossipTopic::Blocks,
            GossipTopic::Votes,
            GossipTopic::Proofs,
            GossipTopic::Snapshots,
            GossipTopic::Meta,
        ]
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value {
            "/rpp/gossip/blocks/1.0.0" => Some(GossipTopic::Blocks),
            "/rpp/gossip/votes/1.0.0" => Some(GossipTopic::Votes),
            "/rpp/gossip/proofs/1.0.0" => Some(GossipTopic::Proofs),
            "/rpp/gossip/snapshots/1.0.0" => Some(GossipTopic::Snapshots),
            "/rpp/gossip/meta/1.0.0" => Some(GossipTopic::Meta),
            _ => None,
        }
    }
}

impl std::fmt::Display for GossipTopic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
