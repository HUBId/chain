use libp2p_core::Multiaddr;

use crate::behaviour::{ExternalAddrConfirmed, ExternalAddrExpired, FromSwarm};

/// The maximum number of local external addresses. When reached any
/// further externally reported addresses are ignored. The behaviour always
/// tracks all its listen addresses.
const MAX_LOCAL_EXTERNAL_ADDRS: usize = 20;

/// Utility struct for tracking the external addresses of a [`Swarm`](crate::Swarm).
#[derive(Debug, Clone, Default)]
pub struct ExternalAddresses {
    addresses: Vec<Multiaddr>,
}

impl ExternalAddresses {
    /// Returns an [`Iterator`] over all external addresses.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &Multiaddr> {
        self.addresses.iter()
    }

    pub fn as_slice(&self) -> &[Multiaddr] {
        self.addresses.as_slice()
    }

    /// Feed a [`FromSwarm`] event to this struct.
    ///
    /// Returns whether the event changed our set of external addresses.
    pub fn on_swarm_event(&mut self, event: &FromSwarm) -> bool {
        match event {
            FromSwarm::ExternalAddrConfirmed(ExternalAddrConfirmed { addr }) => {
                if let Some(pos) = self
                    .addresses
                    .iter()
                    .position(|candidate| candidate == *addr)
                {
                    // Refresh the existing confirmed address.
                    self.addresses.remove(pos);
                    self.push_front(addr);

                    tracing::debug!(address=%addr, "Refreshed external address");

                    return false; // No changes to our external addresses.
                }

                self.push_front(addr);

                if self.addresses.len() > MAX_LOCAL_EXTERNAL_ADDRS {
                    let expired = self.addresses.pop().expect("list to be not empty");

                    tracing::debug!(
                        external_address=%expired,
                        address_limit=%MAX_LOCAL_EXTERNAL_ADDRS,
                        "Removing previously confirmed external address because we reached the address limit"
                    );
                }

                return true;
            }
            FromSwarm::ExternalAddrExpired(ExternalAddrExpired {
                addr: expired_addr, ..
            }) => {
                let Some(pos) = self
                    .addresses
                    .iter()
                    .position(|candidate| candidate == *expired_addr)
                else {
                    return false;
                };

                self.addresses.remove(pos);
                return true;
            }
            _ => {}
        }

        false
    }

    fn push_front(&mut self, addr: &Multiaddr) {
        // We have at most `MAX_LOCAL_EXTERNAL_ADDRS` so
        // this isn't very expensive.
        self.addresses.insert(0, addr.clone());
    }
}
