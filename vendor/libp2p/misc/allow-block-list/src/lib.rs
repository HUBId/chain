// Copyright 2023 Protocol Labs.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

//! A libp2p module for managing allow and blocks lists to peers.
//!
//! # Allow list example
//!
//! ```rust
//! # use libp2p_swarm::Swarm;
//! # use libp2p_swarm_derive::NetworkBehaviour;
//! # use libp2p_allow_block_list as allow_block_list;
//! # use libp2p_allow_block_list::AllowedPeers;
//! #
//! #[derive(NetworkBehaviour)]
//! # #[behaviour(prelude = "libp2p_swarm::derive_prelude")]
//! struct MyBehaviour {
//!     allowed_peers: allow_block_list::Behaviour<AllowedPeers>,
//! }
//!
//! # fn main() {
//! let behaviour = MyBehaviour {
//!     allowed_peers: allow_block_list::Behaviour::default(),
//! };
//! # }
//! ```
//! # Block list example
//!
//! ```rust
//! # use libp2p_swarm::Swarm;
//! # use libp2p_swarm_derive::NetworkBehaviour;
//! # use libp2p_allow_block_list as allow_block_list;
//! # use libp2p_allow_block_list::BlockedPeers;
//! #
//! #[derive(NetworkBehaviour)]
//! # #[behaviour(prelude = "libp2p_swarm::derive_prelude")]
//! struct MyBehaviour {
//!     blocked_peers: allow_block_list::Behaviour<BlockedPeers>,
//! }
//!
//! # fn main() {
//! let behaviour = MyBehaviour {
//!     blocked_peers: allow_block_list::Behaviour::default(),
//! };
//! # }
//! ```

use std::{
    collections::{HashSet, VecDeque},
    convert::Infallible,
    fmt,
    task::{Context, Poll, Waker},
};

use libp2p_core::{transport::PortUse, Endpoint, Multiaddr};
use libp2p_identity::PeerId;
use libp2p_swarm::{
    dummy, CloseConnection, ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler,
    THandlerInEvent, THandlerOutEvent, ToSwarm,
};

/// A [`NetworkBehaviour`] that can act as an allow or block list.
#[derive(Default, Debug)]
pub struct Behaviour<S> {
    state: S,
    close_connections: VecDeque<PeerId>,
    waker: Option<Waker>,
}

/// The list of explicitly allowed peers.
#[derive(Default)]
pub struct AllowedPeers {
    peers: HashSet<PeerId>,
}

/// The list of explicitly blocked peers.
#[derive(Default)]
pub struct BlockedPeers {
    peers: HashSet<PeerId>,
}

impl Behaviour<AllowedPeers> {
    /// Peers that are currently allowed.
    pub fn allowed_peers(&self) -> &HashSet<PeerId> {
        &self.state.peers
    }

    /// Allow connections to the given peer.
    ///
    /// Returns whether the peer was newly inserted. Does nothing if the peer
    /// was already present in the set.
    pub fn allow_peer(&mut self, peer: PeerId) -> bool {
        let inserted = self.state.peers.insert(peer);
        if inserted {
            if let Some(waker) = self.waker.take() {
                waker.wake()
            }
        }
        inserted
    }

    /// Disallow connections to the given peer.
    ///
    /// All active connections to this peer will be closed immediately.
    ///
    /// Returns whether the peer was present in the set. Does nothing if the peer
    /// was not present in the set.
    pub fn disallow_peer(&mut self, peer: PeerId) -> bool {
        let removed = self.state.peers.remove(&peer);
        if removed {
            self.close_connections.push_back(peer);
            if let Some(waker) = self.waker.take() {
                waker.wake()
            }
        }
        removed
    }
}

impl Behaviour<BlockedPeers> {
    /// Peers that are currently blocked.
    pub fn blocked_peers(&self) -> &HashSet<PeerId> {
        &self.state.peers
    }

    /// Block connections to a given peer.
    ///
    /// All active connections to this peer will be closed immediately.
    ///
    /// Returns whether the peer was newly inserted. Does nothing if the peer was already present in
    /// the set.
    pub fn block_peer(&mut self, peer: PeerId) -> bool {
        let inserted = self.state.peers.insert(peer);
        if inserted {
            self.close_connections.push_back(peer);
            if let Some(waker) = self.waker.take() {
                waker.wake()
            }
        }
        inserted
    }

    /// Unblock connections to a given peer.
    ///
    /// Returns whether the peer was present in the set. Does nothing if the peer
    /// was not present in the set.
    pub fn unblock_peer(&mut self, peer: PeerId) -> bool {
        let removed = self.state.peers.remove(&peer);
        if removed {
            if let Some(waker) = self.waker.take() {
                waker.wake()
            }
        }
        removed
    }
}

/// A connection to this peer is not explicitly allowed and was thus [`denied`](ConnectionDenied).
#[derive(Debug)]
pub struct NotAllowed {
    peer: PeerId,
}

impl fmt::Display for NotAllowed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peer {} is not in the allow list", self.peer)
    }
}

impl std::error::Error for NotAllowed {}

/// A connection to this peer was explicitly blocked and was thus [`denied`](ConnectionDenied).
#[derive(Debug)]
pub struct Blocked {
    peer: PeerId,
}

impl fmt::Display for Blocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "peer {} is in the block list", self.peer)
    }
}

impl std::error::Error for Blocked {}

trait Enforce: 'static {
    fn enforce(&self, peer: &PeerId) -> Result<(), ConnectionDenied>;
}

impl Enforce for AllowedPeers {
    fn enforce(&self, peer: &PeerId) -> Result<(), ConnectionDenied> {
        if !self.peers.contains(peer) {
            return Err(ConnectionDenied::new(NotAllowed { peer: *peer }));
        }

        Ok(())
    }
}

impl Enforce for BlockedPeers {
    fn enforce(&self, peer: &PeerId) -> Result<(), ConnectionDenied> {
        if self.peers.contains(peer) {
            return Err(ConnectionDenied::new(Blocked { peer: *peer }));
        }

        Ok(())
    }
}

impl<S> NetworkBehaviour for Behaviour<S>
where
    S: Enforce,
{
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = Infallible;

    fn handle_established_inbound_connection(
        &mut self,
        _: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.state.enforce(&peer)?;

        Ok(dummy::ConnectionHandler)
    }

    fn handle_pending_outbound_connection(
        &mut self,
        _: ConnectionId,
        peer: Option<PeerId>,
        _: &[Multiaddr],
        _: Endpoint,
    ) -> Result<Vec<Multiaddr>, ConnectionDenied> {
        if let Some(peer) = peer {
            self.state.enforce(&peer)?;
        }

        Ok(vec![])
    }

    fn handle_established_outbound_connection(
        &mut self,
        _: ConnectionId,
        peer: PeerId,
        _: &Multiaddr,
        _: Endpoint,
        _: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        self.state.enforce(&peer)?;

        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, _event: FromSwarm) {}

    fn on_connection_handler_event(
        &mut self,
        _id: PeerId,
        _: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        libp2p_core::util::unreachable(event)
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        if let Some(peer) = self.close_connections.pop_front() {
            return Poll::Ready(ToSwarm::CloseConnection {
                peer_id: peer,
                connection: CloseConnection::All,
            });
        }

        self.waker = Some(cx.waker().clone());
        Poll::Pending
    }
}
