// Copyright 2018 Parity Technologies (UK) Ltd.
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

use std::{fmt, io, ops::Deref};

use crate::{transport::TransportError, Multiaddr, PeerId};

/// The underlying [`io::Error`] that triggered [`ConnectionError::IO`]
/// augmented with optional context about the affected connection.
#[derive(Debug)]
pub struct ConnectionIoError {
    error: io::Error,
    peer_id: Option<PeerId>,
    remote_address: Option<Multiaddr>,
}

impl ConnectionIoError {
    /// Creates a new [`ConnectionIoError`] from the provided [`io::Error`].
    pub fn new(error: io::Error) -> Self {
        Self {
            error,
            peer_id: None,
            remote_address: None,
        }
    }

    /// Returns the underlying [`io::Error`].
    pub fn into_inner(self) -> io::Error {
        self.error
    }

    /// Returns a reference to the underlying [`io::Error`].
    pub fn as_ref(&self) -> &io::Error {
        &self.error
    }

    /// Adds information about the remote peer associated with the error.
    pub fn with_peer_id(mut self, peer_id: PeerId) -> Self {
        self.peer_id = Some(peer_id);
        self
    }

    /// Adds information about the remote address associated with the error.
    pub fn with_remote_address(mut self, remote_address: Multiaddr) -> Self {
        self.remote_address = Some(remote_address);
        self
    }

    /// Sets the peer id metadata in-place.
    pub fn set_peer_id(&mut self, peer_id: PeerId) {
        self.peer_id = Some(peer_id);
    }

    /// Sets the remote address metadata in-place.
    pub fn set_remote_address(&mut self, remote_address: Multiaddr) {
        self.remote_address = Some(remote_address);
    }

    /// Returns the associated peer id if known.
    pub fn peer_id(&self) -> Option<&PeerId> {
        self.peer_id.as_ref()
    }

    /// Returns the remote address if known.
    pub fn remote_address(&self) -> Option<&Multiaddr> {
        self.remote_address.as_ref()
    }
}

impl Deref for ConnectionIoError {
    type Target = io::Error;

    fn deref(&self) -> &Self::Target {
        &self.error
    }
}

impl fmt::Display for ConnectionIoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)?;

        if let Some(peer_id) = &self.peer_id {
            write!(f, "; peer: {peer_id}")?;
        }

        if let Some(remote_address) = &self.remote_address {
            write!(f, "; remote_addr: {remote_address}")?;
        }

        Ok(())
    }
}

impl std::error::Error for ConnectionIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl From<io::Error> for ConnectionIoError {
    fn from(error: io::Error) -> Self {
        Self::new(error)
    }
}

/// Errors that can occur in the context of an established `Connection`.
#[derive(Debug)]
pub enum ConnectionError {
    /// An I/O error occurred on the connection.
    // TODO: Eventually this should also be a custom error?
    IO(ConnectionIoError),

    /// The connection keep-alive timeout expired.
    KeepAliveTimeout,
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionError::IO(err) => {
                write!(f, "Connection error: I/O error: {err}")
            }
            ConnectionError::KeepAliveTimeout => {
                write!(f, "Connection closed due to expired keep-alive timeout.")
            }
        }
    }
}

impl std::error::Error for ConnectionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConnectionError::IO(err) => Some(err),
            ConnectionError::KeepAliveTimeout => None,
        }
    }
}

impl From<io::Error> for ConnectionError {
    fn from(error: io::Error) -> Self {
        ConnectionError::IO(ConnectionIoError::new(error))
    }
}

impl ConnectionError {
    /// Adds the peer metadata to an [`ConnectionError::IO`] if present.
    pub fn with_peer_id(mut self, peer_id: PeerId) -> Self {
        if let ConnectionError::IO(ref mut error) = self {
            error.set_peer_id(peer_id);
        }
        self
    }

    /// Adds the remote address metadata to an [`ConnectionError::IO`] if present.
    pub fn with_remote_address(mut self, remote_address: Multiaddr) -> Self {
        if let ConnectionError::IO(ref mut error) = self {
            error.set_remote_address(remote_address);
        }
        self
    }
}

/// Errors that can occur in the context of a pending outgoing `Connection`.
///
/// Note: Addresses for an outbound connection are dialed in parallel. Thus, compared to
/// [`PendingInboundConnectionError`], one or more [`TransportError`]s can occur for a single
/// connection.
#[derive(Debug)]
pub(crate) enum PendingOutboundConnectionError {
    /// An error occurred while negotiating the transport protocol(s) on a connection.
    Transport(Vec<(Multiaddr, TransportError<io::Error>)>),

    /// Pending connection attempt has been aborted.
    Aborted,

    /// The peer identity obtained on the connection did not
    /// match the one that was expected.
    WrongPeerId {
        obtained: PeerId,
        address: Multiaddr,
    },

    /// The connection was dropped because it resolved to our own [`PeerId`].
    LocalPeerId { address: Multiaddr },
}

/// Errors that can occur in the context of a pending incoming `Connection`.
#[derive(Debug)]
pub(crate) enum PendingInboundConnectionError {
    /// An error occurred while negotiating the transport protocol(s) on a connection.
    Transport(TransportError<io::Error>),

    /// Pending connection attempt has been aborted.
    Aborted,

    /// The connection was dropped because it resolved to our own [`PeerId`].
    LocalPeerId { address: Multiaddr },
}

#[cfg(test)]
mod tests {
    use super::{ConnectionError, ConnectionIoError};
    use crate::Multiaddr;
    use libp2p_identity::PeerId;
    use std::io;

    #[test]
    fn preserves_deref_to_io_error() {
        let error = ConnectionError::from(io::Error::new(io::ErrorKind::Other, "boom"));

        match error {
            ConnectionError::IO(io_error) => {
                assert_eq!(io_error.kind(), io::ErrorKind::Other);
                assert_eq!(io_error.to_string(), "boom");
            }
            ConnectionError::KeepAliveTimeout => panic!("unexpected variant"),
        }
    }

    #[test]
    fn display_includes_metadata() {
        let peer_id = PeerId::random();
        let peer_id_string = peer_id.to_string();
        let remote_address: Multiaddr =
            "/ip4/127.0.0.1/tcp/30333".parse().expect("valid multiaddr");

        let error = ConnectionError::from(io::Error::new(io::ErrorKind::Other, "reset"))
            .with_peer_id(peer_id.clone())
            .with_remote_address(remote_address.clone());

        let formatted = error.to_string();

        assert!(formatted.contains(&peer_id_string));
        assert!(formatted.contains(remote_address.to_string().as_str()));
        assert!(formatted.contains("reset"));
    }

    #[test]
    fn metadata_accessors_expose_endpoint_details() {
        let peer_id = PeerId::random();
        let remote_address: Multiaddr =
            "/ip4/10.1.1.9/tcp/30333".parse().expect("valid multiaddr");

        let error = ConnectionError::from(io::Error::new(io::ErrorKind::Other, "disconnected"))
            .with_peer_id(peer_id.clone())
            .with_remote_address(remote_address.clone());

        match error {
            ConnectionError::IO(io_error) => {
                assert_eq!(io_error.peer_id(), Some(&peer_id));
                assert_eq!(io_error.remote_address(), Some(&remote_address));
            }
            ConnectionError::KeepAliveTimeout => panic!("unexpected variant"),
        }
    }

    #[test]
    fn connection_io_error_into_inner() {
        let io_error = io::Error::new(io::ErrorKind::ConnectionReset, "oops");
        let wrapped = ConnectionIoError::from(io_error);
        let inner = wrapped.into_inner();
        assert_eq!(inner.kind(), io::ErrorKind::ConnectionReset);
    }
}
