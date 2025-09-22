use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use crate::admission::AdmissionControl;
use crate::protocol::Message;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GossipTopic {
    Blocks,
    Votes,
    Proofs,
    Snapshots,
    Meta,
}

impl GossipTopic {
    pub fn as_str(&self) -> &'static str {
        match self {
            GossipTopic::Blocks => "blocks",
            GossipTopic::Votes => "votes",
            GossipTopic::Proofs => "proofs",
            GossipTopic::Snapshots => "snapshots",
            GossipTopic::Meta => "meta",
        }
    }

    pub fn parse(topic: &str) -> Option<GossipTopic> {
        match topic {
            "blocks" => Some(GossipTopic::Blocks),
            "votes" => Some(GossipTopic::Votes),
            "proofs" => Some(GossipTopic::Proofs),
            "snapshots" => Some(GossipTopic::Snapshots),
            "meta" => Some(GossipTopic::Meta),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MessageEnvelope {
    pub topic: GossipTopic,
    pub message: Message,
    pub from: String,
    pub timestamp: SystemTime,
}

#[derive(Debug)]
pub enum GossipError {
    UnknownTopic,
    AdmissionDenied,
    DeliveryFailed,
}

pub type Subscription = Receiver<MessageEnvelope>;

#[derive(Debug)]
pub struct GossipEngine {
    local_peer: String,
    admission: Arc<AdmissionControl>,
    topics: Mutex<HashMap<GossipTopic, Vec<Sender<MessageEnvelope>>>>,
}

impl GossipEngine {
    pub fn new(local_peer: impl Into<String>, admission: Arc<AdmissionControl>) -> Self {
        Self {
            local_peer: local_peer.into(),
            admission,
            topics: Mutex::new(HashMap::new()),
        }
    }

    pub fn subscribe(&self, topic: &str) -> Result<Subscription, GossipError> {
        let topic = GossipTopic::parse(topic).ok_or(GossipError::UnknownTopic)?;
        let (tx, rx) = mpsc::channel();
        let mut guard = self.topics.lock().expect("topics mutex poisoned");
        guard.entry(topic).or_default().push(tx);
        Ok(rx)
    }

    pub fn publish(&self, topic: &str, message: Message) -> Result<(), GossipError> {
        let topic = GossipTopic::parse(topic).ok_or(GossipError::UnknownTopic)?;
        if !self.admission.check_publish(&self.local_peer, topic) {
            return Err(GossipError::AdmissionDenied);
        }

        let envelope = MessageEnvelope {
            topic,
            message,
            from: self.local_peer.clone(),
            timestamp: SystemTime::now(),
        };

        let guard = self.topics.lock().expect("topics mutex poisoned");
        if let Some(subscribers) = guard.get(&topic) {
            for subscriber in subscribers.iter() {
                if subscriber.send(envelope.clone()).is_err() {
                    return Err(GossipError::DeliveryFailed);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admission::PeerReputation;
    use std::time::Duration;

    #[test]
    fn publishes_to_subscribers() {
        let admission = Arc::new(AdmissionControl::new());
        admission.register_peer(PeerReputation::new("node-a", 3.0, Duration::from_secs(10)));
        let gossip = GossipEngine::new("node-a", admission);

        let rx = gossip.subscribe("blocks").expect("subscribe blocks");
        let message = Message::block_proposal(1, b"proposal");
        gossip.publish("blocks", message.clone()).expect("publish");

        let received = rx.recv().expect("gossip message");
        assert_eq!(received.message, message);
        assert_eq!(received.topic, GossipTopic::Blocks);
    }

    #[test]
    fn denies_publication_without_tier() {
        let admission = Arc::new(AdmissionControl::new());
        admission.register_peer(PeerReputation::new("node-b", 0.2, Duration::from_secs(1)));
        let gossip = GossipEngine::new("node-b", admission);
        assert!(matches!(
            gossip.publish("blocks", Message::meta("hello")),
            Err(GossipError::AdmissionDenied)
        ));
    }
}
