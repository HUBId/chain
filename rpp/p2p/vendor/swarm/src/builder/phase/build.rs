use std::time::Duration;

use libp2p_core::{transport::timeout::TransportTimeout, Transport};

#[allow(unused_imports)]
use super::*;
use crate::{builder::SwarmBuilder, Config, NetworkBehaviour, Swarm};

pub struct BuildPhase<T, B> {
    pub(crate) behaviour: B,
    pub(crate) transport: T,
    pub(crate) swarm_config: Config,
    pub(crate) connection_timeout: Duration,
}

impl<Provider, T: AuthenticatedMultiplexedTransport, B: NetworkBehaviour>
    SwarmBuilder<Provider, BuildPhase<T, B>>
{
    /// Timeout of the [`TransportTimeout`] wrapping the transport.
    pub fn with_connection_timeout(mut self, connection_timeout: Duration) -> Self {
        self.phase.connection_timeout = connection_timeout;
        self
    }

    pub fn build(self) -> Swarm<B> {
        Swarm::new(
            TransportTimeout::new(self.phase.transport, self.phase.connection_timeout).boxed(),
            self.phase.behaviour,
            self.keypair.public().to_peer_id(),
            self.phase.swarm_config,
        )
    }

    #[cfg(all(feature = "macros", feature = "tokio"))]
    /// Builds a [`Swarm`] alongside an [`ExternalEventHandle`](crate::ExternalEventHandle) for
    /// injecting external behaviour events.
    pub fn build_with_external_event_handle(
        self,
    ) -> (Swarm<B>, crate::ExternalEventHandle<B::ToSwarm>) {
        Swarm::new_with_external_event_channel(
            TransportTimeout::new(self.phase.transport, self.phase.connection_timeout).boxed(),
            self.phase.behaviour,
            self.keypair.public().to_peer_id(),
            self.phase.swarm_config,
        )
    }
}
