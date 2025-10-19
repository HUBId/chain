use std::marker::PhantomData;

use libp2p_core::muxing::{StreamMuxer, StreamMuxerBox};
use libp2p_core::Transport;
use libp2p_core::{
    upgrade::InboundConnectionUpgrade, upgrade::OutboundConnectionUpgrade, Negotiated, UpgradeInfo,
};

use super::*;
use crate::builder::SwarmBuilder;

pub struct TcpPhase;

impl SwarmBuilder<super::provider::Tokio, TcpPhase> {
    /// Adds a TCP based transport.
    ///
    /// Note that both `security_upgrade` and `multiplexer_upgrade` take function pointers,
    /// i.e. they take the function themselves (without the invocation via `()`), not the
    /// result of the function invocation. See example below.
    pub fn with_tcp<SecUpgrade, SecStream, SecError, MuxUpgrade, MuxStream, MuxError>(
        self,
        tcp_config: libp2p_tcp::Config,
        security_upgrade: SecUpgrade,
        multiplexer_upgrade: MuxUpgrade,
    ) -> Result<
        SwarmBuilder<super::provider::Tokio, BehaviourPhase<impl AuthenticatedMultiplexedTransport>>,
        SecUpgrade::Error,
    >
    where
        SecStream: futures::AsyncRead + futures::AsyncWrite + Unpin + Send + 'static,
        SecError: std::error::Error + Send + Sync + 'static,
        SecUpgrade: IntoSecurityUpgrade<libp2p_tcp::tokio::TcpStream>,
        SecUpgrade::Upgrade: InboundConnectionUpgrade<
                Negotiated<libp2p_tcp::tokio::TcpStream>,
                Output = (libp2p_identity::PeerId, SecStream),
                Error = SecError,
            > + OutboundConnectionUpgrade<
                Negotiated<libp2p_tcp::tokio::TcpStream>,
                Output = (libp2p_identity::PeerId, SecStream),
                Error = SecError,
            > + Clone
            + Send
            + 'static,
        <SecUpgrade::Upgrade as InboundConnectionUpgrade<Negotiated<libp2p_tcp::tokio::TcpStream>>>::Future: Send,
        <SecUpgrade::Upgrade as OutboundConnectionUpgrade<Negotiated<libp2p_tcp::tokio::TcpStream>>>::Future: Send,
        <<<SecUpgrade as IntoSecurityUpgrade<libp2p_tcp::tokio::TcpStream>>::Upgrade as UpgradeInfo>::InfoIter as IntoIterator>::IntoIter:
            Send,
        <<SecUpgrade as IntoSecurityUpgrade<libp2p_tcp::tokio::TcpStream>>::Upgrade as UpgradeInfo>::Info: Send,

        MuxStream: StreamMuxer + Send + 'static,
        MuxStream::Substream: Send + 'static,
        MuxStream::Error: Send + Sync + 'static,
        MuxUpgrade: IntoMultiplexerUpgrade<SecStream>,
        MuxUpgrade::Upgrade: InboundConnectionUpgrade<
                Negotiated<SecStream>,
                Output = MuxStream,
                Error = MuxError,
            > + OutboundConnectionUpgrade<
                Negotiated<SecStream>,
                Output = MuxStream,
                Error = MuxError,
            > + Clone
            + Send
            + 'static,
        <MuxUpgrade::Upgrade as InboundConnectionUpgrade<Negotiated<SecStream>>>::Future: Send,
        <MuxUpgrade::Upgrade as OutboundConnectionUpgrade<Negotiated<SecStream>>>::Future: Send,
        MuxError: std::error::Error + Send + Sync + 'static,
        <<<MuxUpgrade as IntoMultiplexerUpgrade<SecStream>>::Upgrade as UpgradeInfo>::InfoIter as IntoIterator>::IntoIter:
            Send,
        <<MuxUpgrade as IntoMultiplexerUpgrade<SecStream>>::Upgrade as UpgradeInfo>::Info: Send,
    {
        let transport = libp2p_tcp::tokio::Transport::new(tcp_config)
            .upgrade(libp2p_core::upgrade::Version::V1Lazy)
            .authenticate(security_upgrade.into_security_upgrade(&self.keypair)?)
            .multiplex(multiplexer_upgrade.into_multiplexer_upgrade())
            .map(|(peer_id, muxer), _| (peer_id, StreamMuxerBox::new(muxer)));

        Ok(SwarmBuilder {
            phase: BehaviourPhase { transport },
            keypair: self.keypair,
            phantom: PhantomData,
        })
    }
}
