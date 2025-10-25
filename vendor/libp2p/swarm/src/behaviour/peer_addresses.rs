use std::num::NonZeroUsize;

use hashlink::LruCache;
use libp2p_core::Multiaddr;
use libp2p_identity::PeerId;

use crate::{behaviour::FromSwarm, DialError, DialFailure, NewExternalAddrOfPeer};

/// Struct for tracking peers' external addresses of the [`Swarm`](crate::Swarm).
#[derive(Debug)]
pub struct PeerAddresses(LruCache<PeerId, LruCache<Multiaddr, ()>>);

impl PeerAddresses {
    /// Creates a [`PeerAddresses`] cache with capacity for the given number of peers.
    ///
    /// For each peer, we will at most store 10 addresses.
    pub fn new(number_of_peers: NonZeroUsize) -> Self {
        Self(LruCache::new(number_of_peers.get()))
    }

    /// Feed a [`FromSwarm`] event to this struct.
    ///
    /// Returns whether the event changed peer's known external addresses.
    pub fn on_swarm_event(&mut self, event: &FromSwarm) -> bool {
        match event {
            FromSwarm::NewExternalAddrOfPeer(NewExternalAddrOfPeer { peer_id, addr }) => {
                self.add(*peer_id, (*addr).clone())
            }
            FromSwarm::DialFailure(DialFailure {
                peer_id: Some(peer_id),
                error: DialError::Transport(errors),
                ..
            }) => {
                for (addr, _error) in errors {
                    self.remove(peer_id, addr);
                }
                true
            }
            _ => false,
        }
    }

    /// Adds address to cache.
    /// Appends address to the existing set if peer addresses already exist.
    /// Creates a new cache entry for peer_id if no addresses are present.
    /// Returns true if the newly added address was not previously in the cache.
    pub fn add(&mut self, peer: PeerId, address: Multiaddr) -> bool {
        match prepare_addr(&peer, &address) {
            Ok(address) => {
                if let Some(cached) = self.0.get_mut(&peer) {
                    cached.insert(address, ()).is_none()
                } else {
                    let mut set = LruCache::new(10);
                    set.insert(address, ());
                    self.0.insert(peer, set);

                    true
                }
            }
            Err(_) => false,
        }
    }

    /// Returns peer's external addresses.
    pub fn get(&mut self, peer: &PeerId) -> impl Iterator<Item = Multiaddr> + '_ {
        self.0
            .get(peer)
            .into_iter()
            .flat_map(|c| c.iter().map(|(m, ())| m))
            .cloned()
    }

    /// Removes address from peer addresses cache.
    /// Returns true if the address was removed.
    pub fn remove(&mut self, peer: &PeerId, address: &Multiaddr) -> bool {
        match self.0.get_mut(peer) {
            Some(addrs) => match prepare_addr(peer, address) {
                Ok(address) => addrs.remove(&address).is_some(),
                Err(_) => false,
            },
            None => false,
        }
    }
}

fn prepare_addr(peer: &PeerId, addr: &Multiaddr) -> Result<Multiaddr, Multiaddr> {
    addr.clone().with_p2p(*peer)
}

impl Default for PeerAddresses {
    fn default() -> Self {
        Self(LruCache::new(100))
    }
}
