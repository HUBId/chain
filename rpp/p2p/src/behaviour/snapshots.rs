use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::pipeline::{
    NetworkLightClientUpdate, NetworkStateSyncChunk, NetworkStateSyncPlan, PipelineError,
};
use crate::vendor::PeerId;

#[cfg(feature = "request-response")]
use crate::vendor::protocols::request_response::{
    self, Behaviour as RequestResponseBehaviour, Config as RequestResponseConfig,
    Event as RequestResponseEvent, InboundRequestId as RequestResponseInboundId,
    Message as RequestResponseMessage, OutboundFailure as RequestResponseOutboundFailure,
    OutboundRequestId as RequestResponseId, ProtocolSupport,
    ResponseChannel as RequestResponseChannel,
};
#[cfg(feature = "request-response")]
use crate::vendor::swarm::behaviour::ToSwarm;
#[cfg(feature = "request-response")]
use crate::vendor::swarm::{
    ConnectionDenied, ConnectionHandler, ConnectionId, FromSwarm, NetworkBehaviour,
};

#[cfg(feature = "request-response")]
use async_trait::async_trait;
#[cfg(feature = "request-response")]
use futures::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "request-response")]
use crate::vendor::protocols::request_response::MAX_HANDSHAKE_BYTES;

/// Identifier associated with a snapshot session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SnapshotSessionId(u64);

impl SnapshotSessionId {
    /// Creates a new `SnapshotSessionId` from the provided raw value.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Returns the underlying identifier value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SnapshotSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Enumeration of snapshot artefacts exchanged over the snapshots protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SnapshotItemKind {
    Plan,
    Chunk,
    LightClientUpdate,
    Resume,
    Ack,
    Error,
}

/// Resume state reported by providers when a session is resumed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotResumeState {
    pub next_chunk_index: u64,
    pub next_update_index: u64,
}

/// Snapshot protocol request payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SnapshotsRequest {
    Plan {
        session_id: SnapshotSessionId,
    },
    Chunk {
        session_id: SnapshotSessionId,
        chunk_index: u64,
    },
    LightClientUpdate {
        session_id: SnapshotSessionId,
        update_index: u64,
    },
    Resume {
        session_id: SnapshotSessionId,
        chunk_index: u64,
        update_index: u64,
    },
    Ack {
        session_id: SnapshotSessionId,
        kind: SnapshotItemKind,
        index: u64,
    },
    Error {
        session_id: SnapshotSessionId,
        message: String,
    },
}

/// Snapshot protocol response payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SnapshotsResponse {
    Plan {
        session_id: SnapshotSessionId,
        plan: NetworkStateSyncPlan,
    },
    Chunk {
        session_id: SnapshotSessionId,
        chunk_index: u64,
        chunk: NetworkStateSyncChunk,
    },
    LightClientUpdate {
        session_id: SnapshotSessionId,
        update_index: u64,
        update: NetworkLightClientUpdate,
    },
    Resume {
        session_id: SnapshotSessionId,
        chunk_index: u64,
        update_index: u64,
    },
    Ack {
        session_id: SnapshotSessionId,
        kind: SnapshotItemKind,
        index: u64,
    },
    Error {
        session_id: SnapshotSessionId,
        message: String,
    },
}

/// Trait describing a provider that can service snapshot data requests.
pub trait SnapshotProvider: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn fetch_plan(
        &self,
        session_id: SnapshotSessionId,
    ) -> Result<NetworkStateSyncPlan, Self::Error>;

    fn fetch_chunk(
        &self,
        session_id: SnapshotSessionId,
        chunk_index: u64,
    ) -> Result<NetworkStateSyncChunk, Self::Error>;

    fn fetch_update(
        &self,
        session_id: SnapshotSessionId,
        update_index: u64,
    ) -> Result<NetworkLightClientUpdate, Self::Error>;

    fn resume_session(
        &self,
        session_id: SnapshotSessionId,
        chunk_index: u64,
        update_index: u64,
    ) -> Result<SnapshotResumeState, Self::Error>;

    fn acknowledge(
        &self,
        session_id: SnapshotSessionId,
        kind: SnapshotItemKind,
        index: u64,
    ) -> Result<(), Self::Error>;
}

impl<T: SnapshotProvider> SnapshotProvider for Arc<T> {
    type Error = T::Error;

    fn fetch_plan(
        &self,
        session_id: SnapshotSessionId,
    ) -> Result<NetworkStateSyncPlan, Self::Error> {
        (**self).fetch_plan(session_id)
    }

    fn fetch_chunk(
        &self,
        session_id: SnapshotSessionId,
        chunk_index: u64,
    ) -> Result<NetworkStateSyncChunk, Self::Error> {
        (**self).fetch_chunk(session_id, chunk_index)
    }

    fn fetch_update(
        &self,
        session_id: SnapshotSessionId,
        update_index: u64,
    ) -> Result<NetworkLightClientUpdate, Self::Error> {
        (**self).fetch_update(session_id, update_index)
    }

    fn resume_session(
        &self,
        session_id: SnapshotSessionId,
        chunk_index: u64,
        update_index: u64,
    ) -> Result<SnapshotResumeState, Self::Error> {
        (**self).resume_session(session_id, chunk_index, update_index)
    }

    fn acknowledge(
        &self,
        session_id: SnapshotSessionId,
        kind: SnapshotItemKind,
        index: u64,
    ) -> Result<(), Self::Error> {
        (**self).acknowledge(session_id, kind, index)
    }
}

/// Fallback snapshot provider returning `SnapshotNotFound` for every request.
#[derive(Clone, Debug, Default)]
pub struct NullSnapshotProvider;

impl SnapshotProvider for NullSnapshotProvider {
    type Error = PipelineError;

    fn fetch_plan(
        &self,
        _session_id: SnapshotSessionId,
    ) -> Result<NetworkStateSyncPlan, Self::Error> {
        Err(PipelineError::SnapshotNotFound)
    }

    fn fetch_chunk(
        &self,
        _session_id: SnapshotSessionId,
        _chunk_index: u64,
    ) -> Result<NetworkStateSyncChunk, Self::Error> {
        Err(PipelineError::SnapshotNotFound)
    }

    fn fetch_update(
        &self,
        _session_id: SnapshotSessionId,
        _update_index: u64,
    ) -> Result<NetworkLightClientUpdate, Self::Error> {
        Err(PipelineError::SnapshotNotFound)
    }

    fn resume_session(
        &self,
        _session_id: SnapshotSessionId,
        _chunk_index: u64,
        _update_index: u64,
    ) -> Result<SnapshotResumeState, Self::Error> {
        Err(PipelineError::SnapshotNotFound)
    }

    fn acknowledge(
        &self,
        _session_id: SnapshotSessionId,
        _kind: SnapshotItemKind,
        _index: u64,
    ) -> Result<(), Self::Error> {
        Err(PipelineError::SnapshotNotFound)
    }
}

#[cfg(feature = "request-response")]
/// Errors surfaced by the snapshots protocol.
#[derive(Debug, Error)]
pub enum SnapshotProtocolError {
    #[error("outbound {kind:?} request failed: {error}")]
    Outbound {
        kind: SnapshotItemKind,
        #[source]
        error: RequestResponseOutboundFailure,
    },
    #[error("provider error: {0}")]
    Provider(String),
    #[error("remote error: {0}")]
    Remote(String),
}

#[cfg(feature = "request-response")]
/// Events emitted by the snapshots behaviour.
#[derive(Debug)]
pub enum SnapshotsEvent {
    Plan {
        peer: PeerId,
        session_id: SnapshotSessionId,
        plan: NetworkStateSyncPlan,
    },
    Chunk {
        peer: PeerId,
        session_id: SnapshotSessionId,
        chunk_index: u64,
        chunk: NetworkStateSyncChunk,
    },
    LightClientUpdate {
        peer: PeerId,
        session_id: SnapshotSessionId,
        update_index: u64,
        update: NetworkLightClientUpdate,
    },
    Resume {
        peer: PeerId,
        session_id: SnapshotSessionId,
        chunk_index: u64,
        update_index: u64,
    },
    Ack {
        peer: PeerId,
        session_id: SnapshotSessionId,
        kind: SnapshotItemKind,
        index: u64,
    },
    InboundRequest {
        peer: PeerId,
        session_id: SnapshotSessionId,
        request: SnapshotsRequest,
    },
    Error {
        peer: PeerId,
        session_id: SnapshotSessionId,
        error: SnapshotProtocolError,
    },
}

#[cfg(feature = "request-response")]
const MAX_SNAPSHOT_MESSAGE_BYTES: usize = MAX_HANDSHAKE_BYTES * 8;

#[cfg(feature = "request-response")]
const SNAPSHOTS_PROTOCOL_ID: &str = "/rpp/snapshots/1.0.0";

#[cfg(feature = "request-response")]
#[derive(Clone, Default)]
pub struct SnapshotsCodec;

#[cfg(feature = "request-response")]
#[async_trait]
impl request_response::Codec for SnapshotsCodec {
    type Protocol = String;
    type Request = SnapshotsRequest;
    type Response = SnapshotsResponse;

    async fn read_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = request_response::read_limited(io, MAX_SNAPSHOT_MESSAGE_BYTES).await?;
        serde_json::from_slice(&buf)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let buf = request_response::read_limited(io, MAX_SNAPSHOT_MESSAGE_BYTES).await?;
        serde_json::from_slice(&buf)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }

    async fn write_request<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        request: Self::Request,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let payload = serde_json::to_vec(&request)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        request_response::write_payload(io, &payload).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        response: Self::Response,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let payload = serde_json::to_vec(&response)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        request_response::write_payload(io, &payload).await
    }
}

#[cfg(feature = "request-response")]
struct SessionState {
    peer: PeerId,
    next_chunk_index: u64,
    next_update_index: u64,
    in_flight: Option<RequestResponseId>,
}

#[cfg(feature = "request-response")]
impl SessionState {
    fn new(peer: PeerId) -> Self {
        Self {
            peer,
            next_chunk_index: 0,
            next_update_index: 0,
            in_flight: None,
        }
    }
}

/// Behaviour managing snapshot-related networking logic.
#[cfg(feature = "request-response")]
pub struct SnapshotsBehaviour<P: SnapshotProvider> {
    inner: RequestResponseBehaviour<SnapshotsCodec>,
    provider: P,
    pending_events: VecDeque<SnapshotsEvent>,
    requests: HashMap<RequestResponseId, (SnapshotSessionId, SnapshotItemKind)>,
    sessions: HashMap<SnapshotSessionId, SessionState>,
}

#[cfg(feature = "request-response")]
impl<P: SnapshotProvider> SnapshotsBehaviour<P> {
    /// Creates a new `SnapshotsBehaviour` for the given provider.
    pub fn new(provider: P) -> Self {
        let protocols = vec![(SNAPSHOTS_PROTOCOL_ID.to_string(), ProtocolSupport::Full)];
        let config = RequestResponseConfig::default();
        Self {
            inner: RequestResponseBehaviour::new(protocols, config),
            provider,
            pending_events: VecDeque::new(),
            requests: HashMap::new(),
            sessions: HashMap::new(),
        }
    }

    /// Returns a reference to the wrapped provider instance.
    pub fn provider(&self) -> &P {
        &self.provider
    }

    /// Sends a plan request to the remote peer.
    pub fn request_plan(
        &mut self,
        peer: PeerId,
        session_id: SnapshotSessionId,
    ) -> Option<RequestResponseId> {
        let entry = self
            .sessions
            .entry(session_id)
            .or_insert_with(|| SessionState::new(peer.clone()));
        if entry.in_flight.is_some() {
            return None;
        }
        if entry.peer != peer {
            entry.peer = peer.clone();
        }
        let request = SnapshotsRequest::Plan { session_id };
        let request_id = self.inner.send_request(&peer, request);
        entry.in_flight = Some(request_id);
        self.requests
            .insert(request_id, (session_id, SnapshotItemKind::Plan));
        Some(request_id)
    }

    /// Requests a chunk from the remote peer.
    pub fn request_chunk(
        &mut self,
        peer: PeerId,
        session_id: SnapshotSessionId,
        chunk_index: u64,
    ) -> Option<RequestResponseId> {
        let entry = self.sessions.get_mut(&session_id)?;
        if entry.in_flight.is_some() || entry.peer != peer {
            return None;
        }
        let request = SnapshotsRequest::Chunk {
            session_id,
            chunk_index,
        };
        let request_id = self.inner.send_request(&peer, request);
        entry.in_flight = Some(request_id);
        self.requests
            .insert(request_id, (session_id, SnapshotItemKind::Chunk));
        Some(request_id)
    }

    /// Requests a light client update from the remote peer.
    pub fn request_update(
        &mut self,
        peer: PeerId,
        session_id: SnapshotSessionId,
        update_index: u64,
    ) -> Option<RequestResponseId> {
        let entry = self.sessions.get_mut(&session_id)?;
        if entry.in_flight.is_some() || entry.peer != peer {
            return None;
        }
        let request = SnapshotsRequest::LightClientUpdate {
            session_id,
            update_index,
        };
        let request_id = self.inner.send_request(&peer, request);
        entry.in_flight = Some(request_id);
        self.requests.insert(
            request_id,
            (session_id, SnapshotItemKind::LightClientUpdate),
        );
        Some(request_id)
    }

    /// Requests the remote peer to resume a snapshot session from the stored indices.
    pub fn request_resume(
        &mut self,
        peer: PeerId,
        session_id: SnapshotSessionId,
    ) -> Option<RequestResponseId> {
        let entry = self.sessions.get_mut(&session_id)?;
        if entry.in_flight.is_some() || entry.peer != peer {
            return None;
        }
        let request = SnapshotsRequest::Resume {
            session_id,
            chunk_index: entry.next_chunk_index,
            update_index: entry.next_update_index,
        };
        let request_id = self.inner.send_request(&peer, request);
        entry.in_flight = Some(request_id);
        self.requests
            .insert(request_id, (session_id, SnapshotItemKind::Resume));
        Some(request_id)
    }

    /// Cancels a snapshot session by notifying the remote peer.
    pub fn cancel_session(
        &mut self,
        peer: PeerId,
        session_id: SnapshotSessionId,
        reason: impl Into<String>,
    ) -> Option<RequestResponseId> {
        let reason = reason.into();
        if self
            .sessions
            .get(&session_id)
            .map(|state| state.peer != peer)
            .unwrap_or(true)
        {
            return None;
        }
        self.sessions.remove(&session_id)?;
        let request = SnapshotsRequest::Error {
            session_id,
            message: reason,
        };
        let request_id = self.inner.send_request(&peer, request);
        self.requests
            .insert(request_id, (session_id, SnapshotItemKind::Error));
        Some(request_id)
    }

    fn handle_inner_event(
        &mut self,
        event: RequestResponseEvent<SnapshotsRequest, SnapshotsResponse>,
    ) {
        match event {
            RequestResponseEvent::Message { peer, message, .. } => match message {
                RequestResponseMessage::Request {
                    request_id,
                    request,
                    channel,
                } => {
                    let session_id = match &request {
                        SnapshotsRequest::Plan { session_id }
                        | SnapshotsRequest::Chunk { session_id, .. }
                        | SnapshotsRequest::LightClientUpdate { session_id, .. }
                        | SnapshotsRequest::Resume { session_id, .. }
                        | SnapshotsRequest::Ack { session_id, .. }
                        | SnapshotsRequest::Error { session_id, .. } => *session_id,
                    };
                    self.pending_events
                        .push_back(SnapshotsEvent::InboundRequest {
                            peer: peer.clone(),
                            session_id,
                            request: request.clone(),
                        });
                    self.handle_inbound_request(peer, request_id, request, channel);
                }
                RequestResponseMessage::Response {
                    request_id,
                    response,
                } => {
                    if let Some((session_id, kind)) = self.requests.remove(&request_id) {
                        if let Some(state) = self.sessions.get_mut(&session_id) {
                            if state.in_flight == Some(request_id) {
                                state.in_flight = None;
                            }
                        }
                        self.handle_response(peer, session_id, kind, response);
                    }
                }
            },
            RequestResponseEvent::OutboundFailure {
                peer,
                request_id,
                error,
                ..
            } => {
                if let Some((session_id, kind)) = self.requests.remove(&request_id) {
                    if let Some(state) = self.sessions.get_mut(&session_id) {
                        if state.in_flight == Some(request_id) {
                            state.in_flight = None;
                        }
                    }
                    self.pending_events.push_back(SnapshotsEvent::Error {
                        peer,
                        session_id,
                        error: SnapshotProtocolError::Outbound { kind, error },
                    });
                }
            }
            RequestResponseEvent::InboundFailure { .. } => {}
            RequestResponseEvent::ResponseSent { .. } => {}
        }
    }

    fn handle_inbound_request(
        &mut self,
        peer: PeerId,
        _request_id: RequestResponseInboundId,
        request: SnapshotsRequest,
        channel: RequestResponseChannel<SnapshotsResponse>,
    ) {
        match request {
            SnapshotsRequest::Plan { session_id } => match self.provider.fetch_plan(session_id) {
                Ok(plan) => {
                    let _ = self
                        .inner
                        .send_response(channel, SnapshotsResponse::Plan { session_id, plan });
                }
                Err(err) => {
                    let message = err.to_string();
                    let _ = self.inner.send_response(
                        channel,
                        SnapshotsResponse::Error {
                            session_id,
                            message: message.clone(),
                        },
                    );
                    self.pending_events.push_back(SnapshotsEvent::Error {
                        peer,
                        session_id,
                        error: SnapshotProtocolError::Provider(message),
                    });
                }
            },
            SnapshotsRequest::Chunk {
                session_id,
                chunk_index,
            } => match self.provider.fetch_chunk(session_id, chunk_index) {
                Ok(chunk) => {
                    let _ = self.inner.send_response(
                        channel,
                        SnapshotsResponse::Chunk {
                            session_id,
                            chunk_index,
                            chunk,
                        },
                    );
                }
                Err(err) => {
                    let message = err.to_string();
                    let _ = self.inner.send_response(
                        channel,
                        SnapshotsResponse::Error {
                            session_id,
                            message: message.clone(),
                        },
                    );
                    self.pending_events.push_back(SnapshotsEvent::Error {
                        peer,
                        session_id,
                        error: SnapshotProtocolError::Provider(message),
                    });
                }
            },
            SnapshotsRequest::LightClientUpdate {
                session_id,
                update_index,
            } => match self.provider.fetch_update(session_id, update_index) {
                Ok(update) => {
                    let _ = self.inner.send_response(
                        channel,
                        SnapshotsResponse::LightClientUpdate {
                            session_id,
                            update_index,
                            update,
                        },
                    );
                }
                Err(err) => {
                    let message = err.to_string();
                    let _ = self.inner.send_response(
                        channel,
                        SnapshotsResponse::Error {
                            session_id,
                            message: message.clone(),
                        },
                    );
                    self.pending_events.push_back(SnapshotsEvent::Error {
                        peer,
                        session_id,
                        error: SnapshotProtocolError::Provider(message),
                    });
                }
            },
            SnapshotsRequest::Resume {
                session_id,
                chunk_index,
                update_index,
            } => match self
                .provider
                .resume_session(session_id, chunk_index, update_index)
            {
                Ok(resume) => {
                    let _ = self.inner.send_response(
                        channel,
                        SnapshotsResponse::Resume {
                            session_id,
                            chunk_index: resume.next_chunk_index,
                            update_index: resume.next_update_index,
                        },
                    );
                }
                Err(err) => {
                    let message = err.to_string();
                    let _ = self.inner.send_response(
                        channel,
                        SnapshotsResponse::Error {
                            session_id,
                            message: message.clone(),
                        },
                    );
                    self.pending_events.push_back(SnapshotsEvent::Error {
                        peer,
                        session_id,
                        error: SnapshotProtocolError::Provider(message),
                    });
                }
            },
            SnapshotsRequest::Ack {
                session_id,
                kind,
                index,
            } => match self.provider.acknowledge(session_id, kind, index) {
                Ok(()) => {
                    let _ = self.inner.send_response(
                        channel,
                        SnapshotsResponse::Ack {
                            session_id,
                            kind,
                            index,
                        },
                    );
                }
                Err(err) => {
                    let message = err.to_string();
                    let _ = self.inner.send_response(
                        channel,
                        SnapshotsResponse::Error {
                            session_id,
                            message: message.clone(),
                        },
                    );
                    self.pending_events.push_back(SnapshotsEvent::Error {
                        peer,
                        session_id,
                        error: SnapshotProtocolError::Provider(message),
                    });
                }
            },
            SnapshotsRequest::Error {
                session_id,
                message,
            } => {
                self.pending_events.push_back(SnapshotsEvent::Error {
                    peer,
                    session_id,
                    error: SnapshotProtocolError::Remote(message),
                });
                let _ = self.inner.send_response(
                    channel,
                    SnapshotsResponse::Ack {
                        session_id,
                        kind: SnapshotItemKind::Error,
                        index: 0,
                    },
                );
            }
        }
    }

    fn handle_response(
        &mut self,
        peer: PeerId,
        session_id: SnapshotSessionId,
        kind: SnapshotItemKind,
        response: SnapshotsResponse,
    ) {
        match response {
            SnapshotsResponse::Plan { plan, .. } => {
                let state = self
                    .sessions
                    .entry(session_id)
                    .or_insert_with(|| SessionState::new(peer.clone()));
                state.next_chunk_index = 0;
                state.next_update_index = 0;
                self.pending_events.push_back(SnapshotsEvent::Plan {
                    peer,
                    session_id,
                    plan,
                });
            }
            SnapshotsResponse::Chunk {
                chunk_index, chunk, ..
            } => {
                if let Some(state) = self.sessions.get_mut(&session_id) {
                    state.next_chunk_index = chunk_index.saturating_add(1);
                }
                self.pending_events.push_back(SnapshotsEvent::Chunk {
                    peer,
                    session_id,
                    chunk_index,
                    chunk,
                });
            }
            SnapshotsResponse::LightClientUpdate {
                update_index,
                update,
                ..
            } => {
                if let Some(state) = self.sessions.get_mut(&session_id) {
                    state.next_update_index = update_index.saturating_add(1);
                }
                self.pending_events
                    .push_back(SnapshotsEvent::LightClientUpdate {
                        peer,
                        session_id,
                        update_index,
                        update,
                    });
            }
            SnapshotsResponse::Resume {
                chunk_index,
                update_index,
                ..
            } => {
                if let Some(state) = self.sessions.get_mut(&session_id) {
                    state.next_chunk_index = chunk_index;
                    state.next_update_index = update_index;
                }
                self.pending_events.push_back(SnapshotsEvent::Resume {
                    peer,
                    session_id,
                    chunk_index,
                    update_index,
                });
            }
            SnapshotsResponse::Ack { kind, index, .. } => {
                self.pending_events.push_back(SnapshotsEvent::Ack {
                    peer,
                    session_id,
                    kind,
                    index,
                });
            }
            SnapshotsResponse::Error { message, .. } => {
                self.pending_events.push_back(SnapshotsEvent::Error {
                    peer,
                    session_id,
                    error: SnapshotProtocolError::Remote(message),
                });
            }
        }
        if matches!(kind, SnapshotItemKind::Ack | SnapshotItemKind::Error) {
            self.sessions.remove(&session_id);
        }
    }
}

#[cfg(feature = "request-response")]
impl<P: SnapshotProvider> NetworkBehaviour for SnapshotsBehaviour<P> {
    type ConnectionHandler =
        <RequestResponseBehaviour<SnapshotsCodec> as NetworkBehaviour>::ConnectionHandler;
    type ToSwarm = SnapshotsEvent;

    fn handle_pending_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        local_addr: &crate::vendor::Multiaddr,
        remote_addr: &crate::vendor::Multiaddr,
    ) -> Result<(), ConnectionDenied> {
        self.inner
            .handle_pending_inbound_connection(connection_id, local_addr, remote_addr)
    }

    fn handle_established_inbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        local_addr: &crate::vendor::Multiaddr,
        remote_addr: &crate::vendor::Multiaddr,
    ) -> Result<Self::ConnectionHandler, ConnectionDenied> {
        self.inner.handle_established_inbound_connection(
            connection_id,
            peer,
            local_addr,
            remote_addr,
        )
    }

    fn handle_pending_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        maybe_peer: Option<PeerId>,
        addresses: &[crate::vendor::Multiaddr],
        effective_role: crate::vendor::core::Endpoint,
    ) -> Result<Vec<crate::vendor::Multiaddr>, ConnectionDenied> {
        self.inner.handle_pending_outbound_connection(
            connection_id,
            maybe_peer,
            addresses,
            effective_role,
        )
    }

    fn handle_established_outbound_connection(
        &mut self,
        connection_id: ConnectionId,
        peer: PeerId,
        addr: &crate::vendor::Multiaddr,
        role_override: crate::vendor::core::Endpoint,
        port_use: crate::vendor::core::transport::PortUse,
    ) -> Result<Self::ConnectionHandler, ConnectionDenied> {
        self.inner.handle_established_outbound_connection(
            connection_id,
            peer,
            addr,
            role_override,
            port_use,
        )
    }

    fn on_swarm_event(&mut self, event: FromSwarm<'_, Self::ConnectionHandler>) {
        self.inner.on_swarm_event(event);
    }

    fn on_connection_handler_event(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        event: <Self::ConnectionHandler as ConnectionHandler>::OutEvent,
    ) {
        self.inner
            .on_connection_handler_event(peer_id, connection_id, event);
    }

    fn poll(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<
        ToSwarm<Self::ToSwarm, <Self::ConnectionHandler as ConnectionHandler>::InEvent>,
    > {
        if let Some(event) = self.pending_events.pop_front() {
            return std::task::Poll::Ready(ToSwarm::GenerateEvent(event));
        }

        loop {
            match self.inner.poll(cx) {
                std::task::Poll::Pending => {
                    return std::task::Poll::Pending;
                }
                std::task::Poll::Ready(ToSwarm::GenerateEvent(event)) => {
                    self.handle_inner_event(event);
                    if let Some(pending) = self.pending_events.pop_front() {
                        return std::task::Poll::Ready(ToSwarm::GenerateEvent(pending));
                    }
                }
                std::task::Poll::Ready(ToSwarm::Dial { opts }) => {
                    return std::task::Poll::Ready(ToSwarm::Dial { opts });
                }
                std::task::Poll::Ready(ToSwarm::ListenOn { opts }) => {
                    return std::task::Poll::Ready(ToSwarm::ListenOn { opts });
                }
                std::task::Poll::Ready(ToSwarm::RemoveListener { id }) => {
                    return std::task::Poll::Ready(ToSwarm::RemoveListener { id });
                }
                std::task::Poll::Ready(ToSwarm::NotifyHandler {
                    peer_id,
                    handler,
                    event,
                }) => {
                    return std::task::Poll::Ready(ToSwarm::NotifyHandler {
                        peer_id,
                        handler,
                        event,
                    });
                }
                std::task::Poll::Ready(ToSwarm::CloseConnection {
                    peer_id,
                    connection,
                }) => {
                    return std::task::Poll::Ready(ToSwarm::CloseConnection {
                        peer_id,
                        connection,
                    });
                }
                std::task::Poll::Ready(ToSwarm::NewExternalAddrCandidate(addr)) => {
                    return std::task::Poll::Ready(ToSwarm::NewExternalAddrCandidate(addr));
                }
                std::task::Poll::Ready(ToSwarm::ExternalAddrConfirmed(addr)) => {
                    return std::task::Poll::Ready(ToSwarm::ExternalAddrConfirmed(addr));
                }
                std::task::Poll::Ready(ToSwarm::ExternalAddrExpired(addr)) => {
                    return std::task::Poll::Ready(ToSwarm::ExternalAddrExpired(addr));
                }
                std::task::Poll::Ready(ToSwarm::NewExternalAddrOfPeer { peer_id, address }) => {
                    return std::task::Poll::Ready(ToSwarm::NewExternalAddrOfPeer {
                        peer_id,
                        address,
                    });
                }
            }
        }
    }
}
