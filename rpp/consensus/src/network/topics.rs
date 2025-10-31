use rpp_p2p::GossipTopic;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsensusStream {
    Proposals,
    Votes,
    Commits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicRoute {
    primary: GossipTopic,
    fanout: Vec<GossipTopic>,
}

impl TopicRoute {
    pub fn new(primary: GossipTopic, fanout: Vec<GossipTopic>) -> Self {
        Self { primary, fanout }
    }

    pub const fn primary(&self) -> GossipTopic {
        self.primary
    }

    pub fn fanout(&self) -> &[GossipTopic] {
        &self.fanout
    }

    pub fn contains(&self, topic: GossipTopic) -> bool {
        self.primary == topic || self.fanout.contains(&topic)
    }

    pub fn all_topics(&self) -> Vec<GossipTopic> {
        let mut topics = Vec::with_capacity(1 + self.fanout.len());
        topics.push(self.primary);
        topics.extend(self.fanout.iter().copied());
        topics
    }
}

#[derive(Debug, Clone)]
pub struct TopicRouter {
    witness_enabled: bool,
}

impl TopicRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_witness_enabled(mut self, enabled: bool) -> Self {
        self.witness_enabled = enabled;
        self
    }

    pub fn route(&self, stream: ConsensusStream) -> TopicRoute {
        match stream {
            ConsensusStream::Proposals => {
                TopicRoute::new(GossipTopic::Blocks, vec![GossipTopic::Meta])
            }
            ConsensusStream::Votes => TopicRoute::new(GossipTopic::Votes, vec![GossipTopic::Meta]),
            ConsensusStream::Commits => {
                let mut fanout = vec![GossipTopic::Meta];
                if self.witness_enabled {
                    fanout.push(GossipTopic::WitnessProofs);
                    fanout.push(GossipTopic::WitnessMeta);
                }
                TopicRoute::new(GossipTopic::Proofs, fanout)
            }
        }
    }

    pub const fn witness_enabled(&self) -> bool {
        self.witness_enabled
    }
}

impl Default for TopicRouter {
    fn default() -> Self {
        Self {
            witness_enabled: true,
        }
    }
}
