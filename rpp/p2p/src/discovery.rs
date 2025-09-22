use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use crate::admission::TierLevel;
use crate::transport::Multiaddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    pub peer_id: String,
    pub address: Multiaddr,
    pub tier: TierLevel,
    pub last_seen: Instant,
}

impl PeerRecord {
    pub fn new(peer_id: impl Into<String>, address: Multiaddr, tier: TierLevel) -> Self {
        Self {
            peer_id: peer_id.into(),
            address,
            tier,
            last_seen: Instant::now(),
        }
    }
}

#[derive(Debug)]
pub struct Discovery {
    local_peer: String,
    peers: Mutex<HashMap<String, PeerRecord>>,
    bootstrap: Vec<PeerRecord>,
}

impl Discovery {
    pub fn new(local_peer: impl Into<String>) -> Self {
        Self {
            local_peer: local_peer.into(),
            peers: Mutex::new(HashMap::new()),
            bootstrap: Vec::new(),
        }
    }

    pub fn add_bootstrap_peer(&mut self, peer: PeerRecord) {
        self.bootstrap.push(peer);
    }

    pub fn integrate_bootstrap(&self) {
        let mut guard = self.peers.lock().expect("peers mutex poisoned");
        for peer in &self.bootstrap {
            guard.entry(peer.peer_id.clone()).or_insert_with(|| peer.clone());
        }
    }

    pub fn register_peer(&self, peer: PeerRecord) {
        self.peers
            .lock()
            .expect("peers mutex poisoned")
            .insert(peer.peer_id.clone(), peer);
    }

    pub fn find_peer(&self, peer_id: &str) -> Option<PeerRecord> {
        self.peers
            .lock()
            .expect("peers mutex poisoned")
            .get(peer_id)
            .cloned()
    }

    pub fn known_peers(&self) -> Vec<PeerRecord> {
        self.peers
            .lock()
            .expect("peers mutex poisoned")
            .values()
            .cloned()
            .collect()
    }

    pub fn local_peer(&self) -> &str {
        &self.local_peer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrates_bootstrap_peers() {
        let mut discovery = Discovery::new("node-a");
        discovery.add_bootstrap_peer(PeerRecord::new(
            "node-b",
            Multiaddr::from("/ip4/127.0.0.1/tcp/9000"),
            TierLevel::Tier2,
        ));
        discovery.integrate_bootstrap();
        let known = discovery.known_peers();
        assert_eq!(known.len(), 1);
        assert_eq!(known[0].peer_id, "node-b");
    }
}
