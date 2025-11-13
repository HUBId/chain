// Copyright 2019 Parity Technologies (UK) Ltd.
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

//! High-level network manager.
//!
//! A [`Swarm`] contains the state of the network as a whole. The entire
//! behaviour of a libp2p network can be controlled through the `Swarm`.
//! The `Swarm` struct contains all active and pending connections to
//! remotes and manages the state of all the substreams that have been
//! opened, and all the upgrades that were built upon these substreams.
//!
//! # Initializing a Swarm
//!
//! Creating a `Swarm` requires three things:
//!
//!  1. A network identity of the local node in form of a [`PeerId`].
//!  2. An implementation of the [`Transport`] trait. This is the type that will be used in order to
//!     reach nodes on the network based on their address. See the `transport` module for more
//!     information.
//!  3. An implementation of the [`NetworkBehaviour`] trait. This is a state machine that defines
//!     how the swarm should behave once it is connected to a node.
//!
//! # Network Behaviour
//!
//! The [`NetworkBehaviour`] trait is implemented on types that indicate to
//! the swarm how it should behave. This includes which protocols are supported
//! and which nodes to try to connect to. It is the `NetworkBehaviour` that
//! controls what happens on the network. Multiple types that implement
//! `NetworkBehaviour` can be composed into a single behaviour.
//!
//! # Protocols Handler
//!
//! The [`ConnectionHandler`] trait defines how each active connection to a
//! remote should behave: how to handle incoming substreams, which protocols
//! are supported, when to open a new outbound substream, etc.

#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod connection;
mod executor;
mod stream;
mod stream_protocol;
mod upgrade;

pub mod builder;
pub mod behaviour;
pub mod dial_opts;
pub mod dummy;
pub mod handler;
mod listen_opts;
mod translation;

/// [`ConnectionHandler`] that does not support any protocols or events.
pub use dummy::ConnectionHandler as EmptyConnectionHandler;

/// Bundles all symbols required for the [`libp2p_swarm_derive::NetworkBehaviour`] macro.
#[doc(hidden)]
pub mod derive_prelude {
    pub use either::Either;
    pub use futures::prelude as futures;
    pub use libp2p_core::{
        transport::{ListenerId, PortUse},
        ConnectedPoint, Endpoint, Multiaddr,
    };
    pub use libp2p_identity::PeerId;

    pub use crate::{
        behaviour::{
            AddressChange, ConnectionClosed, ConnectionEstablished, DialFailure, ExpiredListenAddr,
            ExternalAddrConfirmed, ExternalAddrExpired, FromSwarm, ListenFailure, ListenerClosed,
            ListenerError, NewExternalAddrCandidate, NewExternalAddrOfPeer, NewListenAddr,
            NewListener,
        },
        connection::ConnectionId,
        ConnectionDenied, ConnectionHandler, ConnectionHandlerSelect, DialError,
        EmptyConnectionHandler, NetworkBehaviour,
        THandler, THandlerInEvent, THandlerOutEvent, ToSwarm,
    };
}

use std::{
    collections::{HashMap, HashSet, VecDeque},
    error, fmt, io,
    num::{NonZeroU32, NonZeroU8, NonZeroUsize},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

pub use behaviour::{
    AddressChange, CloseConnection, ConnectionClosed, DialFailure, ExpiredListenAddr,
    ExternalAddrExpired, ExternalAddresses, FromSwarm, ListenAddresses, ListenFailure,
    ListenerClosed, ListenerError, NetworkBehaviour, NewExternalAddrCandidate,
    NewExternalAddrOfPeer, NewListenAddr, NotifyHandler, PeerAddresses, ToSwarm,
};
pub use builder::SwarmBuilder;
pub use connection::{pool::ConnectionCounters, ConnectionError, ConnectionId, SupportedProtocols};
use connection::{
    pool::{EstablishedConnection, Pool, PoolConfig, PoolEvent},
    IncomingInfo, PendingInboundConnectionError, PendingOutboundConnectionError,
};
use dial_opts::{DialOpts, PeerCondition};
pub use executor::Executor;
use futures::{prelude::*, stream::FusedStream};
#[cfg(all(feature = "macros", feature = "tokio"))]
use futures::channel::mpsc;
pub use handler::{
    ConnectionHandler, ConnectionHandlerEvent, ConnectionHandlerSelect, OneShotHandler,
    OneShotHandlerConfig, StreamUpgradeError, SubstreamProtocol,
};
use libp2p_core::{
    connection::ConnectedPoint,
    muxing::StreamMuxerBox,
    transport::{self, ListenerId, TransportError, TransportEvent},
    Multiaddr, Transport,
};
use libp2p_identity::PeerId;
#[cfg(feature = "macros")]
pub use libp2p_swarm_derive::NetworkBehaviour;
pub use listen_opts::ListenOpts;
use smallvec::SmallVec;
pub use stream::Stream;
pub use stream_protocol::{InvalidProtocol, StreamProtocol};
use tracing::Instrument;
#[doc(hidden)]
pub use translation::_address_translation;

use crate::{behaviour::ExternalAddrConfirmed, handler::UpgradeInfoSend};

/// Event generated by the [`NetworkBehaviour`] that the swarm will report back.
type TBehaviourOutEvent<TBehaviour> = <TBehaviour as NetworkBehaviour>::ToSwarm;

/// [`ConnectionHandler`] of the [`NetworkBehaviour`] for all the protocols the [`NetworkBehaviour`]
/// supports.
pub type THandler<TBehaviour> = <TBehaviour as NetworkBehaviour>::ConnectionHandler;

/// Custom event that can be received by the [`ConnectionHandler`] of the
/// [`NetworkBehaviour`].
pub type THandlerInEvent<TBehaviour> = <THandler<TBehaviour> as ConnectionHandler>::FromBehaviour;

/// Custom event that can be produced by the [`ConnectionHandler`] of the [`NetworkBehaviour`].
pub type THandlerOutEvent<TBehaviour> = <THandler<TBehaviour> as ConnectionHandler>::ToBehaviour;

/// Event generated by the `Swarm`.
#[derive(Debug)]
#[non_exhaustive]
pub enum SwarmEvent<TBehaviourOutEvent> {
    /// Event generated by the `NetworkBehaviour`.
    Behaviour(TBehaviourOutEvent),
    /// A connection to the given peer has been opened.
    ConnectionEstablished {
        /// Identity of the peer that we have connected to.
        peer_id: PeerId,
        /// Identifier of the connection.
        connection_id: ConnectionId,
        /// Endpoint of the connection that has been opened.
        endpoint: ConnectedPoint,
        /// Number of established connections to this peer, including the one that has just been
        /// opened.
        num_established: NonZeroU32,
        /// [`Some`] when the new connection is an outgoing connection.
        /// Addresses are dialed concurrently. Contains the addresses and errors
        /// of dial attempts that failed before the one successful dial.
        concurrent_dial_errors: Option<Vec<(Multiaddr, TransportError<io::Error>)>>,
        /// How long it took to establish this connection
        established_in: std::time::Duration,
    },
    /// A connection with the given peer has been closed,
    /// possibly as a result of an error.
    ConnectionClosed {
        /// Identity of the peer that we have connected to.
        peer_id: PeerId,
        /// Identifier of the connection.
        connection_id: ConnectionId,
        /// Endpoint of the connection that has been closed.
        endpoint: ConnectedPoint,
        /// Number of other remaining connections to this same peer.
        num_established: u32,
        /// Reason for the disconnection, if it was not a successful
        /// active close.
        cause: Option<ConnectionError>,
    },
    /// A new connection arrived on a listener and is in the process of protocol negotiation.
    ///
    /// A corresponding [`ConnectionEstablished`](SwarmEvent::ConnectionEstablished) or
    /// [`IncomingConnectionError`](SwarmEvent::IncomingConnectionError) event will later be
    /// generated for this connection.
    IncomingConnection {
        /// Identifier of the connection.
        connection_id: ConnectionId,
        /// Local connection address.
        /// This address has been earlier reported with a
        /// [`NewListenAddr`](SwarmEvent::NewListenAddr) event.
        local_addr: Multiaddr,
        /// Address used to send back data to the remote.
        send_back_addr: Multiaddr,
    },
    /// An error happened on an inbound connection during its initial handshake.
    ///
    /// This can include, for example, an error during the handshake of the encryption layer, or
    /// the connection unexpectedly closed.
    IncomingConnectionError {
        /// Identifier of the connection.
        connection_id: ConnectionId,
        /// Local connection address.
        /// This address has been earlier reported with a
        /// [`NewListenAddr`](SwarmEvent::NewListenAddr) event.
        local_addr: Multiaddr,
        /// Address used to send back data to the remote.
        send_back_addr: Multiaddr,
        /// The error that happened.
        error: ListenError,
        /// If known, [`PeerId`] of the peer that tried to connect to us.
        peer_id: Option<PeerId>,
    },
    /// An error happened on an outbound connection.
    OutgoingConnectionError {
        /// Identifier of the connection.
        connection_id: ConnectionId,
        /// If known, [`PeerId`] of the peer we tried to reach.
        peer_id: Option<PeerId>,
        /// Error that has been encountered.
        error: DialError,
    },
    /// One of our listeners has reported a new local listening address.
    NewListenAddr {
        /// The listener that is listening on the new address.
        listener_id: ListenerId,
        /// The new address that is being listened on.
        address: Multiaddr,
    },
    /// One of our listeners has reported the expiration of a listening address.
    ExpiredListenAddr {
        /// The listener that is no longer listening on the address.
        listener_id: ListenerId,
        /// The expired address.
        address: Multiaddr,
    },
    /// One of the listeners gracefully closed.
    ListenerClosed {
        /// The listener that closed.
        listener_id: ListenerId,
        /// The addresses that the listener was listening on. These addresses are now considered
        /// expired, similar to if a [`ExpiredListenAddr`](SwarmEvent::ExpiredListenAddr) event
        /// has been generated for each of them.
        addresses: Vec<Multiaddr>,
        /// Reason for the closure. Contains `Ok(())` if the stream produced `None`, or `Err`
        /// if the stream produced an error.
        reason: Result<(), io::Error>,
    },
    /// One of the listeners reported a non-fatal error.
    ListenerError {
        /// The listener that errored.
        listener_id: ListenerId,
        /// The listener error.
        error: io::Error,
    },
    /// A new dialing attempt has been initiated by the [`NetworkBehaviour`]
    /// implementation.
    ///
    /// A [`ConnectionEstablished`](SwarmEvent::ConnectionEstablished) event is
    /// reported if the dialing attempt succeeds, otherwise a
    /// [`OutgoingConnectionError`](SwarmEvent::OutgoingConnectionError) event
    /// is reported.
    Dialing {
        /// Identity of the peer that we are connecting to.
        peer_id: Option<PeerId>,

        /// Identifier of the connection.
        connection_id: ConnectionId,
    },
    /// We have discovered a new candidate for an external address for us.
    NewExternalAddrCandidate { address: Multiaddr },
    /// An external address of the local node was confirmed.
    ExternalAddrConfirmed { address: Multiaddr },
    /// An external address of the local node expired, i.e. is no-longer confirmed.
    ExternalAddrExpired { address: Multiaddr },
    /// We have discovered a new address of a peer.
    NewExternalAddrOfPeer { peer_id: PeerId, address: Multiaddr },
}

#[cfg(all(feature = "macros", feature = "tokio"))]
/// Handle used to inject external events into a [`Swarm`].
///
/// Handles can be cloned and used from arbitrary tasks in order to enqueue events without
/// holding a mutable reference to the [`Swarm`].
#[derive(Clone)]
pub struct ExternalEventHandle<TBehaviourOutEvent> {
    sender: mpsc::UnboundedSender<TBehaviourOutEvent>,
}

#[cfg(all(feature = "macros", feature = "tokio"))]
impl<TBehaviourOutEvent> ExternalEventHandle<TBehaviourOutEvent> {
    /// Pushes a behaviour event into the [`Swarm`] from outside its poll loop.
    pub fn push(&self, event: TBehaviourOutEvent) -> Result<(), mpsc::SendError<TBehaviourOutEvent>> {
        self.sender.unbounded_send(event)
    }
}

impl<TBehaviourOutEvent> SwarmEvent<TBehaviourOutEvent> {
    /// Extract the `TBehaviourOutEvent` from this [`SwarmEvent`] in case it is the `Behaviour`
    /// variant, otherwise fail.
    #[allow(clippy::result_large_err)]
    pub fn try_into_behaviour_event(self) -> Result<TBehaviourOutEvent, Self> {
        match self {
            SwarmEvent::Behaviour(inner) => Ok(inner),
            other => Err(other),
        }
    }
}

/// Contains the state of the network, plus the way it should behave.
///
/// Note: Needs to be polled via `<Swarm as Stream>` in order to make
/// progress.
pub struct Swarm<TBehaviour>
where
    TBehaviour: NetworkBehaviour,
{
    /// [`Transport`] for dialing remote peers and listening for incoming connection.
    transport: transport::Boxed<(PeerId, StreamMuxerBox)>,

    /// The nodes currently active.
    pool: Pool<THandler<TBehaviour>>,

    /// The local peer ID.
    local_peer_id: PeerId,

    /// Handles which nodes to connect to and how to handle the events sent back by the protocol
    /// handlers.
    behaviour: TBehaviour,

    /// List of protocols that the behaviour says it supports.
    supported_protocols: SmallVec<[Vec<u8>; 16]>,

    confirmed_external_addr: HashSet<Multiaddr>,

    /// Multiaddresses that our listeners are listening on,
    listened_addrs: HashMap<ListenerId, SmallVec<[Multiaddr; 1]>>,

    /// Pending event to be delivered to connection handlers
    /// (or dropped if the peer disconnected) before the `behaviour`
    /// can be polled again.
    pending_handler_event: Option<(PeerId, PendingNotifyHandler, THandlerInEvent<TBehaviour>)>,

    pending_swarm_events: VecDeque<SwarmEvent<TBehaviour::ToSwarm>>,
    #[cfg(all(feature = "macros", feature = "tokio"))]
    external_event_receiver: Option<mpsc::UnboundedReceiver<TBehaviour::ToSwarm>>,
}

impl<TBehaviour> Unpin for Swarm<TBehaviour> where TBehaviour: NetworkBehaviour {}

impl<TBehaviour> Swarm<TBehaviour>
where
    TBehaviour: NetworkBehaviour,
{
    /// Creates a new [`Swarm`] from the given [`Transport`], [`NetworkBehaviour`], [`PeerId`] and
    /// [`Config`].
    pub fn new(
        transport: transport::Boxed<(PeerId, StreamMuxerBox)>,
        behaviour: TBehaviour,
        local_peer_id: PeerId,
        config: Config,
    ) -> Self {
        tracing::info!(%local_peer_id);

        Swarm {
            local_peer_id,
            transport,
            pool: Pool::new(local_peer_id, config.pool_config),
            behaviour,
            supported_protocols: Default::default(),
            confirmed_external_addr: Default::default(),
            listened_addrs: HashMap::new(),
            pending_handler_event: None,
            pending_swarm_events: VecDeque::default(),
            #[cfg(all(feature = "macros", feature = "tokio"))]
            external_event_receiver: None,
        }
    }

    #[cfg(all(feature = "macros", feature = "tokio"))]
    /// Creates a new [`Swarm`] and returns an [`ExternalEventHandle`] that can be used to
    /// inject custom [`NetworkBehaviour::ToSwarm`] events from outside the [`Swarm`].
    pub fn new_with_external_event_channel(
        transport: transport::Boxed<(PeerId, StreamMuxerBox)>,
        behaviour: TBehaviour,
        local_peer_id: PeerId,
        config: Config,
    ) -> (Self, ExternalEventHandle<TBehaviour::ToSwarm>) {
        let (sender, receiver) = mpsc::unbounded();
        let mut swarm = Self::new(transport, behaviour, local_peer_id, config);
        swarm.external_event_receiver = Some(receiver);
        (swarm, ExternalEventHandle { sender })
    }

    /// Returns information about the connections underlying the [`Swarm`].
    pub fn network_info(&self) -> NetworkInfo {
        let num_peers = self.pool.num_peers();
        let connection_counters = self.pool.counters().clone();
        NetworkInfo {
            num_peers,
            connection_counters,
        }
    }

    /// Starts listening on the given address.
    /// Returns an error if the address is not supported.
    ///
    /// Listeners report their new listening addresses as [`SwarmEvent::NewListenAddr`].
    /// Depending on the underlying transport, one listener may have multiple listening addresses.
    pub fn listen_on(&mut self, addr: Multiaddr) -> Result<ListenerId, TransportError<io::Error>> {
        let opts = ListenOpts::new(addr);
        let id = opts.listener_id();
        self.add_listener(opts)?;
        Ok(id)
    }

    /// Remove some listener.
    ///
    /// Returns `true` if there was a listener with this ID, `false`
    /// otherwise.
    pub fn remove_listener(&mut self, listener_id: ListenerId) -> bool {
        self.transport.remove_listener(listener_id)
    }

    /// Dial a known or unknown peer.
    ///
    /// See also [`DialOpts`].
    ///
    /// ```
    /// # use libp2p_swarm::Swarm;
    /// # use libp2p_swarm::dial_opts::{DialOpts, PeerCondition};
    /// # use libp2p_core::{Multiaddr, Transport};
    /// # use libp2p_core::transport::dummy::DummyTransport;
    /// # use libp2p_swarm::dummy;
    /// # use libp2p_identity::PeerId;
    /// #
    /// # #[tokio::main]
    /// # async fn main() {
    /// let mut swarm = build_swarm();
    ///
    /// // Dial a known peer.
    /// swarm.dial(PeerId::random());
    ///
    /// // Dial an unknown peer.
    /// swarm.dial("/ip6/::1/tcp/12345".parse::<Multiaddr>().unwrap());
    /// # }
    ///
    /// # fn build_swarm() -> Swarm<dummy::Behaviour> {
    /// #     Swarm::new(DummyTransport::new().boxed(), dummy::Behaviour, PeerId::random(), libp2p_swarm::Config::with_tokio_executor())
    /// # }
    /// ```
    pub fn dial(&mut self, opts: impl Into<DialOpts>) -> Result<(), DialError> {
        let dial_opts = opts.into();

        let peer_id = dial_opts.get_peer_id();
        let condition = dial_opts.peer_condition();
        let connection_id = dial_opts.connection_id();

        let should_dial = match (condition, peer_id) {
            (_, None) => true,
            (PeerCondition::Always, _) => true,
            (PeerCondition::Disconnected, Some(peer_id)) => !self.pool.is_connected(peer_id),
            (PeerCondition::NotDialing, Some(peer_id)) => !self.pool.is_dialing(peer_id),
            (PeerCondition::DisconnectedAndNotDialing, Some(peer_id)) => {
                !self.pool.is_dialing(peer_id) && !self.pool.is_connected(peer_id)
            }
        };

        if !should_dial {
            let e = DialError::DialPeerConditionFalse(condition);

            self.behaviour
                .on_swarm_event(FromSwarm::DialFailure(DialFailure {
                    peer_id,
                    error: &e,
                    connection_id,
                }));

            return Err(e);
        }

        let addresses = {
            let mut addresses_from_opts = dial_opts.get_addresses();

            match self.behaviour.handle_pending_outbound_connection(
                connection_id,
                peer_id,
                addresses_from_opts.as_slice(),
                dial_opts.role_override(),
            ) {
                Ok(addresses) => {
                    if dial_opts.extend_addresses_through_behaviour() {
                        addresses_from_opts.extend(addresses)
                    } else {
                        let num_addresses = addresses.len();

                        if num_addresses > 0 {
                            tracing::debug!(
                                connection=%connection_id,
                                discarded_addresses_count=%num_addresses,
                                "discarding addresses from `NetworkBehaviour` because `DialOpts::extend_addresses_through_behaviour is `false` for connection"
                            )
                        }
                    }
                }
                Err(cause) => {
                    let error = DialError::Denied { cause };

                    self.behaviour
                        .on_swarm_event(FromSwarm::DialFailure(DialFailure {
                            peer_id,
                            error: &error,
                            connection_id,
                        }));

                    return Err(error);
                }
            }

            let mut unique_addresses = HashSet::new();
            addresses_from_opts.retain(|addr| {
                !self.listened_addrs.values().flatten().any(|a| a == addr)
                    && unique_addresses.insert(addr.clone())
            });

            if addresses_from_opts.is_empty() {
                let error = DialError::NoAddresses;
                self.behaviour
                    .on_swarm_event(FromSwarm::DialFailure(DialFailure {
                        peer_id,
                        error: &error,
                        connection_id,
                    }));
                return Err(error);
            };

            addresses_from_opts
        };

        let dials = addresses
            .into_iter()
            .map(|a| match peer_id.map_or(Ok(a.clone()), |p| a.with_p2p(p)) {
                Ok(address) => {
                    let dial = self.transport.dial(
                        address.clone(),
                        transport::DialOpts {
                            role: dial_opts.role_override(),
                            port_use: dial_opts.port_use(),
                        },
                    );
                    let span = tracing::debug_span!(parent: tracing::Span::none(), "Transport::dial", %address);
                    span.follows_from(tracing::Span::current());
                    match dial {
                        Ok(fut) => fut
                            .map(|r| (address, r.map_err(TransportError::Other)))
                            .instrument(span)
                            .boxed(),
                        Err(err) => futures::future::ready((address, Err(err))).boxed(),
                    }
                }
                Err(address) => futures::future::ready((
                    address.clone(),
                    Err(TransportError::MultiaddrNotSupported(address)),
                ))
                .boxed(),
            })
            .collect();

        self.pool.add_outgoing(
            dials,
            peer_id,
            dial_opts.role_override(),
            dial_opts.port_use(),
            dial_opts.dial_concurrency_override(),
            connection_id,
        );

        Ok(())
    }

    #[cfg(all(feature = "macros", feature = "tokio"))]
    /// Pushes an event originating outside of the [`Swarm`] onto the internal queue of
    /// pending swarm events.
    ///
    /// This is primarily useful together with [`ExternalEventHandle`] to inject events without
    /// holding a mutable reference to the [`Swarm`].
    pub fn push_external_event(&mut self, event: TBehaviour::ToSwarm) {
        self.pending_swarm_events
            .push_back(SwarmEvent::Behaviour(event));
    }

    /// Returns an iterator that produces the list of addresses we're listening on.
    pub fn listeners(&self) -> impl Iterator<Item = &Multiaddr> {
        self.listened_addrs.values().flatten()
    }

    /// Returns the peer ID of the swarm passed as parameter.
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    /// List all **confirmed** external address for the local node.
    pub fn external_addresses(&self) -> impl Iterator<Item = &Multiaddr> {
        self.confirmed_external_addr.iter()
    }

    fn add_listener(&mut self, opts: ListenOpts) -> Result<(), TransportError<io::Error>> {
        let addr = opts.address();
        let listener_id = opts.listener_id();

        if let Err(e) = self.transport.listen_on(listener_id, addr.clone()) {
            self.behaviour
                .on_swarm_event(FromSwarm::ListenerError(behaviour::ListenerError {
                    listener_id,
                    err: &e,
                }));

            return Err(e);
        }

        self.behaviour
            .on_swarm_event(FromSwarm::NewListener(behaviour::NewListener {
                listener_id,
            }));

        Ok(())
    }

    /// Add a **confirmed** external address for the local node.
    ///
    /// This function should only be called with addresses that are guaranteed to be reachable.
    /// The address is broadcast to all [`NetworkBehaviour`]s via
    /// [`FromSwarm::ExternalAddrConfirmed`].
    pub fn add_external_address(&mut self, a: Multiaddr) {
        self.behaviour
            .on_swarm_event(FromSwarm::ExternalAddrConfirmed(ExternalAddrConfirmed {
                addr: &a,
            }));
        self.confirmed_external_addr.insert(a);
    }

    /// Remove an external address for the local node.
    ///
    /// The address is broadcast to all [`NetworkBehaviour`]s via
    /// [`FromSwarm::ExternalAddrExpired`].
    pub fn remove_external_address(&mut self, addr: &Multiaddr) {
        self.behaviour
            .on_swarm_event(FromSwarm::ExternalAddrExpired(ExternalAddrExpired { addr }));
        self.confirmed_external_addr.remove(addr);
    }

    /// Add a new external address of a remote peer.
    ///
    /// The address is broadcast to all [`NetworkBehaviour`]s via
    /// [`FromSwarm::NewExternalAddrOfPeer`].
    pub fn add_peer_address(&mut self, peer_id: PeerId, addr: Multiaddr) {
        self.behaviour
            .on_swarm_event(FromSwarm::NewExternalAddrOfPeer(NewExternalAddrOfPeer {
                peer_id,
                addr: &addr,
            }))
    }

    /// Disconnects a peer by its peer ID, closing all connections to said peer.
    ///
    /// Returns `Ok(())` if there was one or more established connections to the peer.
    ///
    /// Closing a connection via [`Swarm::disconnect_peer_id`] will poll
    /// [`ConnectionHandler::poll_close`] to completion. Use this function if you want to close
    /// a connection _despite_ it still being in use by one or more handlers.
    #[allow(clippy::result_unit_err)]
    pub fn disconnect_peer_id(&mut self, peer_id: PeerId) -> Result<(), ()> {
        let was_connected = self.pool.is_connected(peer_id);
        self.pool.disconnect(peer_id);

        if was_connected {
            Ok(())
        } else {
            Err(())
        }
    }

    /// Attempt to gracefully close a connection.
    ///
    /// Closing a connection is asynchronous but this function will return immediately.
    /// A [`SwarmEvent::ConnectionClosed`] event will be emitted
    /// once the connection is actually closed.
    ///
    /// # Returns
    ///
    /// - `true` if the connection was established and is now being closed.
    /// - `false` if the connection was not found or is no longer established.
    pub fn close_connection(&mut self, connection_id: ConnectionId) -> bool {
        if let Some(established) = self.pool.get_established(connection_id) {
            established.start_close();
            return true;
        }

        false
    }

    /// Checks whether there is an established connection to a peer.
    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.pool.is_connected(*peer_id)
    }

    /// Returns the currently connected peers.
    pub fn connected_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.pool.iter_connected()
    }

    /// Returns a reference to the provided [`NetworkBehaviour`].
    pub fn behaviour(&self) -> &TBehaviour {
        &self.behaviour
    }

    /// Returns a mutable reference to the provided [`NetworkBehaviour`].
    pub fn behaviour_mut(&mut self) -> &mut TBehaviour {
        &mut self.behaviour
    }

    fn handle_pool_event(&mut self, event: PoolEvent<THandlerOutEvent<TBehaviour>>) {
        match event {
            PoolEvent::ConnectionEstablished {
                peer_id,
                id,
                endpoint,
                connection,
                concurrent_dial_errors,
                established_in,
            } => {
                let handler = match endpoint.clone() {
                    ConnectedPoint::Dialer {
                        address,
                        role_override,
                        port_use,
                    } => {
                        match self.behaviour.handle_established_outbound_connection(
                            id,
                            peer_id,
                            &address,
                            role_override,
                            port_use,
                        ) {
                            Ok(handler) => handler,
                            Err(cause) => {
                                let dial_error = DialError::Denied { cause };
                                self.behaviour.on_swarm_event(FromSwarm::DialFailure(
                                    DialFailure {
                                        connection_id: id,
                                        error: &dial_error,
                                        peer_id: Some(peer_id),
                                    },
                                ));

                                self.pending_swarm_events.push_back(
                                    SwarmEvent::OutgoingConnectionError {
                                        peer_id: Some(peer_id),
                                        connection_id: id,
                                        error: dial_error,
                                    },
                                );
                                return;
                            }
                        }
                    }
                    ConnectedPoint::Listener {
                        local_addr,
                        send_back_addr,
                    } => {
                        match self.behaviour.handle_established_inbound_connection(
                            id,
                            peer_id,
                            &local_addr,
                            &send_back_addr,
                        ) {
                            Ok(handler) => handler,
                            Err(cause) => {
                                let listen_error = ListenError::Denied { cause };
                                self.behaviour.on_swarm_event(FromSwarm::ListenFailure(
                                    ListenFailure {
                                        local_addr: &local_addr,
                                        send_back_addr: &send_back_addr,
                                        error: &listen_error,
                                        connection_id: id,
                                        peer_id: Some(peer_id),
                                    },
                                ));

                                self.pending_swarm_events.push_back(
                                    SwarmEvent::IncomingConnectionError {
                                        connection_id: id,
                                        send_back_addr,
                                        local_addr,
                                        error: listen_error,
                                        peer_id: Some(peer_id),
                                    },
                                );
                                return;
                            }
                        }
                    }
                };

                let supported_protocols = handler
                    .listen_protocol()
                    .upgrade()
                    .protocol_info()
                    .map(|p| p.as_ref().as_bytes().to_vec())
                    .collect();
                let other_established_connection_ids = self
                    .pool
                    .iter_established_connections_of_peer(&peer_id)
                    .collect::<Vec<_>>();
                let num_established = NonZeroU32::new(
                    u32::try_from(other_established_connection_ids.len() + 1).unwrap(),
                )
                .expect("n + 1 is always non-zero; qed");

                self.pool
                    .spawn_connection(id, peer_id, &endpoint, connection, handler);

                tracing::debug!(
                    peer=%peer_id,
                    ?endpoint,
                    total_peers=%num_established,
                    "Connection established"
                );
                let failed_addresses = concurrent_dial_errors
                    .as_ref()
                    .map(|es| {
                        es.iter()
                            .map(|(a, _)| a)
                            .cloned()
                            .collect::<Vec<Multiaddr>>()
                    })
                    .unwrap_or_default();
                self.behaviour
                    .on_swarm_event(FromSwarm::ConnectionEstablished(
                        behaviour::ConnectionEstablished {
                            peer_id,
                            connection_id: id,
                            endpoint: &endpoint,
                            failed_addresses: &failed_addresses,
                            other_established: other_established_connection_ids.len(),
                        },
                    ));
                self.supported_protocols = supported_protocols;
                self.pending_swarm_events
                    .push_back(SwarmEvent::ConnectionEstablished {
                        peer_id,
                        connection_id: id,
                        num_established,
                        endpoint,
                        concurrent_dial_errors,
                        established_in,
                    });
            }
            PoolEvent::PendingOutboundConnectionError {
                id: connection_id,
                error,
                peer,
            } => {
                let error = error.into();

                self.behaviour
                    .on_swarm_event(FromSwarm::DialFailure(DialFailure {
                        peer_id: peer,
                        error: &error,
                        connection_id,
                    }));

                if let Some(peer) = peer {
                    tracing::debug!(%peer, "Connection attempt to peer failed with {:?}.", error,);
                } else {
                    tracing::debug!("Connection attempt to unknown peer failed with {:?}", error);
                }

                self.pending_swarm_events
                    .push_back(SwarmEvent::OutgoingConnectionError {
                        peer_id: peer,
                        connection_id,
                        error,
                    });
            }
            PoolEvent::PendingInboundConnectionError {
                id,
                send_back_addr,
                local_addr,
                error,
            } => {
                let error = error.into();

                tracing::debug!("Incoming connection failed: {:?}", error);
                self.behaviour
                    .on_swarm_event(FromSwarm::ListenFailure(ListenFailure {
                        local_addr: &local_addr,
                        send_back_addr: &send_back_addr,
                        error: &error,
                        connection_id: id,
                        peer_id: None,
                    }));
                self.pending_swarm_events
                    .push_back(SwarmEvent::IncomingConnectionError {
                        connection_id: id,
                        local_addr,
                        send_back_addr,
                        error,
                        peer_id: None,
                    });
            }
            PoolEvent::ConnectionClosed {
                id,
                connected,
                error,
                remaining_established_connection_ids,
                ..
            } => {
                let Connected { endpoint, peer_id } = connected;
                let remote_addr = endpoint.get_remote_address().clone();

                if let Some(error) = error.as_ref() {
                    tracing::debug!(
                        total_peers=%remaining_established_connection_ids.len(),
                        %peer_id,
                        remote_addr=%remote_addr,
                        "Connection closed with error: {error}",
                    );
                } else {
                    tracing::debug!(
                        total_peers=%remaining_established_connection_ids.len(),
                        %peer_id,
                        remote_addr=%remote_addr,
                        "Connection closed",
                    );
                }

                let num_established =
                    u32::try_from(remaining_established_connection_ids.len()).unwrap();

                self.behaviour
                    .on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
                        peer_id,
                        connection_id: id,
                        endpoint: &endpoint,
                        cause: error.as_ref(),
                        remaining_established: num_established as usize,
                    }));
                self.pending_swarm_events
                    .push_back(SwarmEvent::ConnectionClosed {
                        peer_id,
                        connection_id: id,
                        endpoint,
                        cause: error,
                        num_established,
                    });
            }
            PoolEvent::ConnectionEvent { peer_id, id, event } => {
                self.behaviour
                    .on_connection_handler_event(peer_id, id, event);
            }
            PoolEvent::AddressChange {
                peer_id,
                id,
                new_endpoint,
                old_endpoint,
            } => {
                self.behaviour
                    .on_swarm_event(FromSwarm::AddressChange(AddressChange {
                        peer_id,
                        connection_id: id,
                        old: &old_endpoint,
                        new: &new_endpoint,
                    }));
            }
        }
    }

    fn handle_transport_event(
        &mut self,
        event: TransportEvent<
            <transport::Boxed<(PeerId, StreamMuxerBox)> as Transport>::ListenerUpgrade,
            io::Error,
        >,
    ) {
        match event {
            TransportEvent::Incoming {
                listener_id: _,
                upgrade,
                local_addr,
                send_back_addr,
            } => {
                let connection_id = ConnectionId::next();

                match self.behaviour.handle_pending_inbound_connection(
                    connection_id,
                    &local_addr,
                    &send_back_addr,
                ) {
                    Ok(()) => {}
                    Err(cause) => {
                        let listen_error = ListenError::Denied { cause };

                        self.behaviour
                            .on_swarm_event(FromSwarm::ListenFailure(ListenFailure {
                                local_addr: &local_addr,
                                send_back_addr: &send_back_addr,
                                error: &listen_error,
                                connection_id,
                                peer_id: None,
                            }));

                        self.pending_swarm_events
                            .push_back(SwarmEvent::IncomingConnectionError {
                                connection_id,
                                local_addr,
                                send_back_addr,
                                error: listen_error,
                                peer_id: None,
                            });
                        return;
                    }
                }

                self.pool.add_incoming(
                    upgrade,
                    IncomingInfo {
                        local_addr: &local_addr,
                        send_back_addr: &send_back_addr,
                    },
                    connection_id,
                );

                self.pending_swarm_events
                    .push_back(SwarmEvent::IncomingConnection {
                        connection_id,
                        local_addr,
                        send_back_addr,
                    })
            }
            TransportEvent::NewAddress {
                listener_id,
                listen_addr,
            } => {
                tracing::debug!(
                    listener=?listener_id,
                    address=%listen_addr,
                    "New listener address"
                );
                let addrs = self.listened_addrs.entry(listener_id).or_default();
                if !addrs.contains(&listen_addr) {
                    addrs.push(listen_addr.clone())
                }
                self.behaviour
                    .on_swarm_event(FromSwarm::NewListenAddr(NewListenAddr {
                        listener_id,
                        addr: &listen_addr,
                    }));
                self.pending_swarm_events
                    .push_back(SwarmEvent::NewListenAddr {
                        listener_id,
                        address: listen_addr,
                    })
            }
            TransportEvent::AddressExpired {
                listener_id,
                listen_addr,
            } => {
                tracing::debug!(
                    listener=?listener_id,
                    address=%listen_addr,
                    "Expired listener address"
                );
                if let Some(addrs) = self.listened_addrs.get_mut(&listener_id) {
                    addrs.retain(|a| a != &listen_addr);
                }
                self.behaviour
                    .on_swarm_event(FromSwarm::ExpiredListenAddr(ExpiredListenAddr {
                        listener_id,
                        addr: &listen_addr,
                    }));
                self.pending_swarm_events
                    .push_back(SwarmEvent::ExpiredListenAddr {
                        listener_id,
                        address: listen_addr,
                    })
            }
            TransportEvent::ListenerClosed {
                listener_id,
                reason,
            } => {
                tracing::debug!(
                    listener=?listener_id,
                    ?reason,
                    "Listener closed"
                );
                let addrs = self.listened_addrs.remove(&listener_id).unwrap_or_default();
                for addr in addrs.iter() {
                    self.behaviour.on_swarm_event(FromSwarm::ExpiredListenAddr(
                        ExpiredListenAddr { listener_id, addr },
                    ));
                }
                self.behaviour
                    .on_swarm_event(FromSwarm::ListenerClosed(ListenerClosed {
                        listener_id,
                        reason: reason.as_ref().copied(),
                    }));
                self.pending_swarm_events
                    .push_back(SwarmEvent::ListenerClosed {
                        listener_id,
                        addresses: addrs.to_vec(),
                        reason,
                    })
            }
            TransportEvent::ListenerError { listener_id, error } => {
                self.behaviour
                    .on_swarm_event(FromSwarm::ListenerError(ListenerError {
                        listener_id,
                        err: &error,
                    }));
                self.pending_swarm_events
                    .push_back(SwarmEvent::ListenerError { listener_id, error })
            }
        }
    }

    fn handle_behaviour_event(
        &mut self,
        event: ToSwarm<TBehaviour::ToSwarm, THandlerInEvent<TBehaviour>>,
    ) {
        match event {
            ToSwarm::GenerateEvent(event) => {
                self.pending_swarm_events
                    .push_back(SwarmEvent::Behaviour(event));
            }
            ToSwarm::Dial { opts } => {
                let peer_id = opts.get_peer_id();
                let connection_id = opts.connection_id();
                if let Ok(()) = self.dial(opts) {
                    self.pending_swarm_events.push_back(SwarmEvent::Dialing {
                        peer_id,
                        connection_id,
                    });
                }
            }
            ToSwarm::ListenOn { opts } => {
                // Error is dispatched internally, safe to ignore.
                let _ = self.add_listener(opts);
            }
            ToSwarm::RemoveListener { id } => {
                self.remove_listener(id);
            }
            ToSwarm::NotifyHandler {
                peer_id,
                handler,
                event,
            } => {
                assert!(self.pending_handler_event.is_none());
                let handler = match handler {
                    NotifyHandler::One(connection) => PendingNotifyHandler::One(connection),
                    NotifyHandler::Any => {
                        let ids = self
                            .pool
                            .iter_established_connections_of_peer(&peer_id)
                            .collect();
                        PendingNotifyHandler::Any(ids)
                    }
                };

                self.pending_handler_event = Some((peer_id, handler, event));
            }
            ToSwarm::NewExternalAddrCandidate(addr) => {
                if !self.confirmed_external_addr.contains(&addr) {
                    self.behaviour
                        .on_swarm_event(FromSwarm::NewExternalAddrCandidate(
                            NewExternalAddrCandidate { addr: &addr },
                        ));
                    self.pending_swarm_events
                        .push_back(SwarmEvent::NewExternalAddrCandidate { address: addr });
                }
            }
            ToSwarm::ExternalAddrConfirmed(addr) => {
                self.add_external_address(addr.clone());
                self.pending_swarm_events
                    .push_back(SwarmEvent::ExternalAddrConfirmed { address: addr });
            }
            ToSwarm::ExternalAddrExpired(addr) => {
                self.remove_external_address(&addr);
                self.pending_swarm_events
                    .push_back(SwarmEvent::ExternalAddrExpired { address: addr });
            }
            ToSwarm::CloseConnection {
                peer_id,
                connection,
            } => match connection {
                CloseConnection::One(connection_id) => {
                    if let Some(conn) = self.pool.get_established(connection_id) {
                        conn.start_close();
                    }
                }
                CloseConnection::All => {
                    self.pool.disconnect(peer_id);
                }
            },
            ToSwarm::NewExternalAddrOfPeer { peer_id, address } => {
                self.behaviour
                    .on_swarm_event(FromSwarm::NewExternalAddrOfPeer(NewExternalAddrOfPeer {
                        peer_id,
                        addr: &address,
                    }));
                self.pending_swarm_events
                    .push_back(SwarmEvent::NewExternalAddrOfPeer { peer_id, address });
            }
        }
    }

    /// Internal function used by everything event-related.
    ///
    /// Polls the `Swarm` for the next event.
    #[tracing::instrument(level = "debug", name = "Swarm::poll", skip(self, cx))]
    fn poll_next_event(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<SwarmEvent<TBehaviour::ToSwarm>> {
        // We use a `this` variable because the compiler can't mutably borrow multiple times
        // across a `Deref`.
        let this = &mut *self;

        // This loop polls the components below in a prioritized order.
        //
        // 1. [`NetworkBehaviour`]
        // 2. Connection [`Pool`]
        // 3. [`ListenersStream`]
        //
        // (1) is polled before (2) to prioritize local work over work coming from a remote.
        //
        // (2) is polled before (3) to prioritize existing connections
        // over upgrading new incoming connections.
        loop {
            #[cfg(all(feature = "macros", feature = "tokio"))]
            if let Some(receiver) = this.external_event_receiver.as_mut() {
                while let Poll::Ready(item) = Pin::new(receiver).poll_next(cx) {
                    match item {
                        Some(event) => {
                            this.pending_swarm_events
                                .push_back(SwarmEvent::Behaviour(event));
                        }
                        None => {
                            this.external_event_receiver = None;
                            break;
                        }
                    }
                }
            }

            if let Some(swarm_event) = this.pending_swarm_events.pop_front() {
                return Poll::Ready(swarm_event);
            }

            match this.pending_handler_event.take() {
                // Try to deliver the pending event emitted by the [`NetworkBehaviour`] in the
                // previous iteration to the connection handler(s).
                Some((peer_id, handler, event)) => match handler {
                    PendingNotifyHandler::One(conn_id) => {
                        match this.pool.get_established(conn_id) {
                            Some(conn) => match notify_one(conn, event, cx) {
                                None => continue,
                                Some(event) => {
                                    this.pending_handler_event = Some((peer_id, handler, event));
                                }
                            },
                            None => continue,
                        }
                    }
                    PendingNotifyHandler::Any(ids) => {
                        match notify_any::<_, TBehaviour>(ids, &mut this.pool, event, cx) {
                            None => continue,
                            Some((event, ids)) => {
                                let handler = PendingNotifyHandler::Any(ids);
                                this.pending_handler_event = Some((peer_id, handler, event));
                            }
                        }
                    }
                },
                // No pending event. Allow the [`NetworkBehaviour`] to make progress.
                None => match this.behaviour.poll(cx) {
                    Poll::Pending => {}
                    Poll::Ready(behaviour_event) => {
                        this.handle_behaviour_event(behaviour_event);

                        continue;
                    }
                },
            }

            // Poll the known peers.
            match this.pool.poll(cx) {
                Poll::Pending => {}
                Poll::Ready(pool_event) => {
                    this.handle_pool_event(pool_event);
                    continue;
                }
            }

            // Poll the listener(s) for new connections.
            match Pin::new(&mut this.transport).poll(cx) {
                Poll::Pending => {}
                Poll::Ready(transport_event) => {
                    this.handle_transport_event(transport_event);
                    continue;
                }
            }

            return Poll::Pending;
        }
    }
}

/// Connection to notify of a pending event.
///
/// The connection IDs out of which to notify one of an event are captured at
/// the time the behaviour emits the event, in order not to forward the event to
/// a new connection which the behaviour may not have been aware of at the time
/// it issued the request for sending it.
enum PendingNotifyHandler {
    One(ConnectionId),
    Any(SmallVec<[ConnectionId; 10]>),
}

/// Notify a single connection of an event.
///
/// Returns `Some` with the given event if the connection is not currently
/// ready to receive another event, in which case the current task is
/// scheduled to be woken up.
///
/// Returns `None` if the connection is closing or the event has been
/// successfully sent, in either case the event is consumed.
fn notify_one<THandlerInEvent>(
    conn: &mut EstablishedConnection<THandlerInEvent>,
    event: THandlerInEvent,
    cx: &mut Context<'_>,
) -> Option<THandlerInEvent> {
    match conn.poll_ready_notify_handler(cx) {
        Poll::Pending => Some(event),
        Poll::Ready(Err(())) => None, // connection is closing
        Poll::Ready(Ok(())) => {
            // Can now only fail if connection is closing.
            let _ = conn.notify_handler(event);
            None
        }
    }
}

/// Notify any one of a given list of connections of a peer of an event.
///
/// Returns `Some` with the given event and a new list of connections if
/// none of the given connections was able to receive the event but at
/// least one of them is not closing, in which case the current task
/// is scheduled to be woken up. The returned connections are those which
/// may still become ready to receive another event.
///
/// Returns `None` if either all connections are closing or the event
/// was successfully sent to a handler, in either case the event is consumed.
fn notify_any<THandler, TBehaviour>(
    ids: SmallVec<[ConnectionId; 10]>,
    pool: &mut Pool<THandler>,
    event: THandlerInEvent<TBehaviour>,
    cx: &mut Context<'_>,
) -> Option<(THandlerInEvent<TBehaviour>, SmallVec<[ConnectionId; 10]>)>
where
    TBehaviour: NetworkBehaviour,
    THandler: ConnectionHandler<
        FromBehaviour = THandlerInEvent<TBehaviour>,
        ToBehaviour = THandlerOutEvent<TBehaviour>,
    >,
{
    let mut pending = SmallVec::new();
    let mut event = Some(event); // (1)
    for id in ids.into_iter() {
        if let Some(conn) = pool.get_established(id) {
            match conn.poll_ready_notify_handler(cx) {
                Poll::Pending => pending.push(id),
                Poll::Ready(Err(())) => {} // connection is closing
                Poll::Ready(Ok(())) => {
                    let e = event.take().expect("by (1),(2)");
                    if let Err(e) = conn.notify_handler(e) {
                        event = Some(e) // (2)
                    } else {
                        break;
                    }
                }
            }
        }
    }

    event.and_then(|e| {
        if !pending.is_empty() {
            Some((e, pending))
        } else {
            None
        }
    })
}

/// Stream of events returned by [`Swarm`].
///
/// Includes events from the [`NetworkBehaviour`] as well as events about
/// connection and listener status. See [`SwarmEvent`] for details.
///
/// Note: This stream is infinite and it is guaranteed that
/// [`futures::Stream::poll_next`] will never return `Poll::Ready(None)`.
impl<TBehaviour> futures::Stream for Swarm<TBehaviour>
where
    TBehaviour: NetworkBehaviour,
{
    type Item = SwarmEvent<TBehaviourOutEvent<TBehaviour>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.as_mut().poll_next_event(cx).map(Some)
    }
}

/// The stream of swarm events never terminates, so we can implement fused for it.
impl<TBehaviour> FusedStream for Swarm<TBehaviour>
where
    TBehaviour: NetworkBehaviour,
{
    fn is_terminated(&self) -> bool {
        false
    }
}

pub struct Config {
    pool_config: PoolConfig,
}

impl Config {
    /// Creates a new [`Config`] from the given executor. The [`Swarm`] is obtained via
    /// [`Swarm::new`].
    pub fn with_executor(executor: impl Executor + Send + 'static) -> Self {
        Self {
            pool_config: PoolConfig::new(Some(Box::new(executor))),
        }
    }

    #[doc(hidden)]
    /// Used on connection benchmarks.
    pub fn without_executor() -> Self {
        Self {
            pool_config: PoolConfig::new(None),
        }
    }

    /// Sets executor to the `wasm` executor.
    /// Background tasks will be executed by the browser on the next micro-tick.
    ///
    /// Spawning a task is similar too:
    /// ```typescript
    /// function spawn(task: () => Promise<void>) {
    ///     task()
    /// }
    /// ```
    #[cfg(feature = "wasm-bindgen")]
    pub fn with_wasm_executor() -> Self {
        Self::with_executor(crate::executor::WasmBindgenExecutor)
    }

    /// Builds a new [`Config`] from the given `tokio` executor.
    #[cfg(all(
        feature = "tokio",
        not(any(target_os = "emscripten", target_os = "wasi", target_os = "unknown"))
    ))]
    pub fn with_tokio_executor() -> Self {
        Self::with_executor(crate::executor::TokioExecutor)
    }

    /// Configures the number of events from the [`NetworkBehaviour`] in
    /// destination to the [`ConnectionHandler`] that can be buffered before
    /// the [`Swarm`] has to wait. An individual buffer with this number of
    /// events exists for each individual connection.
    ///
    /// The ideal value depends on the executor used, the CPU speed, and the
    /// volume of events. If this value is too low, then the [`Swarm`] will
    /// be sleeping more often than necessary. Increasing this value increases
    /// the overall memory usage.
    pub fn with_notify_handler_buffer_size(mut self, n: NonZeroUsize) -> Self {
        self.pool_config = self.pool_config.with_notify_handler_buffer_size(n);
        self
    }

    /// Configures the size of the buffer for events sent by a [`ConnectionHandler`] to the
    /// [`NetworkBehaviour`].
    ///
    /// Each connection has its own buffer.
    ///
    /// The ideal value depends on the executor used, the CPU speed and the volume of events.
    /// If this value is too low, then the [`ConnectionHandler`]s will be sleeping more often
    /// than necessary. Increasing this value increases the overall memory
    /// usage, and more importantly the latency between the moment when an
    /// event is emitted and the moment when it is received by the
    /// [`NetworkBehaviour`].
    pub fn with_per_connection_event_buffer_size(mut self, n: usize) -> Self {
        self.pool_config = self.pool_config.with_per_connection_event_buffer_size(n);
        self
    }

    /// Number of addresses concurrently dialed for a single outbound connection attempt.
    pub fn with_dial_concurrency_factor(mut self, factor: NonZeroU8) -> Self {
        self.pool_config = self.pool_config.with_dial_concurrency_factor(factor);
        self
    }

    /// Configures an override for the substream upgrade protocol to use.
    ///
    /// The subtream upgrade protocol is the multistream-select protocol
    /// used for protocol negotiation on substreams. Since a listener
    /// supports all existing versions, the choice of upgrade protocol
    /// only effects the "dialer", i.e. the peer opening a substream.
    ///
    /// > **Note**: If configured, specific upgrade protocols for
    /// > individual [`SubstreamProtocol`]s emitted by the `NetworkBehaviour`
    /// > are ignored.
    pub fn with_substream_upgrade_protocol_override(
        mut self,
        v: libp2p_core::upgrade::Version,
    ) -> Self {
        self.pool_config = self.pool_config.with_substream_upgrade_protocol_override(v);
        self
    }

    /// The maximum number of inbound streams concurrently negotiating on a
    /// connection. New inbound streams exceeding the limit are dropped and thus
    /// reset.
    ///
    /// Note: This only enforces a limit on the number of concurrently
    /// negotiating inbound streams. The total number of inbound streams on a
    /// connection is the sum of negotiating and negotiated streams. A limit on
    /// the total number of streams can be enforced at the
    /// [`StreamMuxerBox`] level.
    pub fn with_max_negotiating_inbound_streams(mut self, v: usize) -> Self {
        self.pool_config = self.pool_config.with_max_negotiating_inbound_streams(v);
        self
    }

    /// How long to keep a connection alive once it is idling.
    ///
    /// Defaults to 10s.
    ///
    /// Typically, you shouldn't _need_ to modify this default as connections will be kept alive
    /// whilst they are "in use" (see below). Depending on the application's usecase, it may be
    /// desirable to keep connections alive despite them not being in use.
    ///
    /// A connection is considered idle if:
    /// - There are no active inbound streams.
    /// - There are no active outbounds streams.
    /// - There are no pending outbound streams (i.e. all streams requested via
    ///   [`ConnectionHandlerEvent::OutboundSubstreamRequest`] have completed).
    /// - Every [`ConnectionHandler`] returns `false` from
    ///   [`ConnectionHandler::connection_keep_alive`].
    ///
    /// Once all these conditions are true, the idle connection timeout starts ticking.
    pub fn with_idle_connection_timeout(mut self, timeout: Duration) -> Self {
        self.pool_config.idle_connection_timeout = timeout;
        self
    }
}

/// Possible errors when trying to establish or upgrade an outbound connection.
#[derive(Debug)]
pub enum DialError {
    /// The peer identity obtained on the connection matches the local peer.
    LocalPeerId { address: Multiaddr },
    /// No addresses have been provided by [`NetworkBehaviour::handle_pending_outbound_connection`]
    /// and [`DialOpts`].
    NoAddresses,
    /// The provided [`dial_opts::PeerCondition`] evaluated to false and thus
    /// the dial was aborted.
    DialPeerConditionFalse(dial_opts::PeerCondition),
    /// Pending connection attempt has been aborted.
    Aborted,
    /// The peer identity obtained on the connection did not match the one that was expected.
    WrongPeerId {
        obtained: PeerId,
        address: Multiaddr,
    },
    /// One of the [`NetworkBehaviour`]s rejected the outbound connection
    /// via [`NetworkBehaviour::handle_pending_outbound_connection`] or
    /// [`NetworkBehaviour::handle_established_outbound_connection`].
    Denied { cause: ConnectionDenied },
    /// An error occurred while negotiating the transport protocol(s) on a connection.
    Transport(Vec<(Multiaddr, TransportError<io::Error>)>),
}

impl From<PendingOutboundConnectionError> for DialError {
    fn from(error: PendingOutboundConnectionError) -> Self {
        match error {
            PendingOutboundConnectionError::Aborted => DialError::Aborted,
            PendingOutboundConnectionError::WrongPeerId { obtained, address } => {
                DialError::WrongPeerId { obtained, address }
            }
            PendingOutboundConnectionError::LocalPeerId { address } => {
                DialError::LocalPeerId { address }
            }
            PendingOutboundConnectionError::Transport(e) => DialError::Transport(e),
        }
    }
}

impl fmt::Display for DialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DialError::NoAddresses => write!(f, "Dial error: no addresses for peer."),
            DialError::LocalPeerId { address } => write!(
                f,
                "Dial error: tried to dial local peer id at {address:?}."
            ),
            DialError::DialPeerConditionFalse(PeerCondition::Disconnected) => write!(f, "Dial error: dial condition was configured to only happen when disconnected (`PeerCondition::Disconnected`), but node is already connected, thus cancelling new dial."),
            DialError::DialPeerConditionFalse(PeerCondition::NotDialing) => write!(f, "Dial error: dial condition was configured to only happen if there is currently no ongoing dialing attempt (`PeerCondition::NotDialing`), but a dial is in progress, thus cancelling new dial."),
            DialError::DialPeerConditionFalse(PeerCondition::DisconnectedAndNotDialing) => write!(f, "Dial error: dial condition was configured to only happen when both disconnected (`PeerCondition::Disconnected`) and there is currently no ongoing dialing attempt (`PeerCondition::NotDialing`), but node is already connected or dial is in progress, thus cancelling new dial."),
            DialError::DialPeerConditionFalse(PeerCondition::Always) => unreachable!("Dial peer condition is by definition true."),
            DialError::Aborted => write!(
                f,
                "Dial error: Pending connection attempt has been aborted."
            ),
            DialError::WrongPeerId { obtained, address } => write!(
                f,
                "Dial error: Unexpected peer ID {obtained} at {address:?}."
            ),
            DialError::Transport(errors) => {
                write!(f, "Failed to negotiate transport protocol(s): [")?;

                for (addr, error) in errors {
                    write!(f, "({addr}")?;
                    print_error_chain(f, error)?;
                    write!(f, ")")?;
                }
                write!(f, "]")?;

                Ok(())
            }
            DialError::Denied { .. } => {
                write!(f, "Dial error")
            }
        }
    }
}

fn print_error_chain(f: &mut fmt::Formatter<'_>, e: &dyn error::Error) -> fmt::Result {
    write!(f, ": {e}")?;

    if let Some(source) = e.source() {
        print_error_chain(f, source)?;
    }

    Ok(())
}

impl error::Error for DialError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            DialError::LocalPeerId { .. } => None,
            DialError::NoAddresses => None,
            DialError::DialPeerConditionFalse(_) => None,
            DialError::Aborted => None,
            DialError::WrongPeerId { .. } => None,
            DialError::Transport(_) => None,
            DialError::Denied { cause } => Some(cause),
        }
    }
}

/// Possible errors when upgrading an inbound connection.
#[derive(Debug)]
pub enum ListenError {
    /// Pending connection attempt has been aborted.
    Aborted,
    /// The peer identity obtained on the connection did not match the one that was expected.
    WrongPeerId {
        obtained: PeerId,
        endpoint: ConnectedPoint,
    },
    /// The connection was dropped because it resolved to our own [`PeerId`].
    LocalPeerId {
        address: Multiaddr,
    },
    Denied {
        cause: ConnectionDenied,
    },
    /// An error occurred while negotiating the transport protocol(s) on a connection.
    Transport(TransportError<io::Error>),
}

impl From<PendingInboundConnectionError> for ListenError {
    fn from(error: PendingInboundConnectionError) -> Self {
        match error {
            PendingInboundConnectionError::Transport(inner) => ListenError::Transport(inner),
            PendingInboundConnectionError::Aborted => ListenError::Aborted,
            PendingInboundConnectionError::LocalPeerId { address } => {
                ListenError::LocalPeerId { address }
            }
        }
    }
}

impl fmt::Display for ListenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ListenError::Aborted => write!(
                f,
                "Listen error: Pending connection attempt has been aborted."
            ),
            ListenError::WrongPeerId { obtained, endpoint } => write!(
                f,
                "Listen error: Unexpected peer ID {obtained} at {endpoint:?}."
            ),
            ListenError::Transport(_) => {
                write!(f, "Listen error: Failed to negotiate transport protocol(s)")
            }
            ListenError::Denied { cause } => {
                write!(f, "Listen error: Denied: {cause}")
            }
            ListenError::LocalPeerId { address } => {
                write!(f, "Listen error: Local peer ID at {address:?}.")
            }
        }
    }
}

impl error::Error for ListenError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ListenError::WrongPeerId { .. } => None,
            ListenError::Transport(err) => Some(err),
            ListenError::Aborted => None,
            ListenError::Denied { cause } => Some(cause),
            ListenError::LocalPeerId { .. } => None,
        }
    }
}

/// A connection was denied.
///
/// To figure out which [`NetworkBehaviour`] denied the connection, use
/// [`ConnectionDenied::downcast`].
#[derive(Debug)]
pub struct ConnectionDenied {
    inner: Box<dyn error::Error + Send + Sync + 'static>,
}

impl ConnectionDenied {
    pub fn new(cause: impl Into<Box<dyn error::Error + Send + Sync + 'static>>) -> Self {
        Self {
            inner: cause.into(),
        }
    }

    /// Attempt to downcast to a particular reason for why the connection was denied.
    pub fn downcast<E>(self) -> Result<E, Self>
    where
        E: error::Error + Send + Sync + 'static,
    {
        let inner = self
            .inner
            .downcast::<E>()
            .map_err(|inner| ConnectionDenied { inner })?;

        Ok(*inner)
    }

    /// Attempt to downcast to a particular reason for why the connection was denied.
    pub fn downcast_ref<E>(&self) -> Option<&E>
    where
        E: error::Error + Send + Sync + 'static,
    {
        self.inner.downcast_ref::<E>()
    }
}

impl fmt::Display for ConnectionDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "connection denied")
    }
}

impl error::Error for ConnectionDenied {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        Some(self.inner.as_ref())
    }
}

/// Information about the connections obtained by [`Swarm::network_info()`].
#[derive(Clone, Debug)]
pub struct NetworkInfo {
    /// The total number of connected peers.
    num_peers: usize,
    /// Counters of ongoing network connections.
    connection_counters: ConnectionCounters,
}

impl NetworkInfo {
    /// The number of connected peers, i.e. peers with whom at least
    /// one established connection exists.
    pub fn num_peers(&self) -> usize {
        self.num_peers
    }

    /// Gets counters for ongoing network connections.
    pub fn connection_counters(&self) -> &ConnectionCounters {
        &self.connection_counters
    }
}

