use std::collections::HashSet;

use libp2p_core::Multiaddr;

use crate::behaviour::{ExpiredListenAddr, FromSwarm, NewListenAddr};

/// Utility struct for tracking the addresses a [`Swarm`](crate::Swarm) is listening on.
#[derive(Debug, Default, Clone)]
pub struct ListenAddresses {
    addresses: HashSet<Multiaddr>,
}

impl ListenAddresses {
    /// Returns an [`Iterator`] over all listen addresses.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Multiaddr> {
        self.addresses.iter()
    }

    /// Feed a [`FromSwarm`] event to this struct.
    ///
    /// Returns whether the event changed our set of listen addresses.
    pub fn on_swarm_event(&mut self, event: &FromSwarm) -> bool {
        match event {
            FromSwarm::NewListenAddr(NewListenAddr { addr, .. }) => {
                self.addresses.insert((*addr).clone())
            }
            FromSwarm::ExpiredListenAddr(ExpiredListenAddr { addr, .. }) => {
                self.addresses.remove(addr)
            }
            _ => false,
        }
    }
}
