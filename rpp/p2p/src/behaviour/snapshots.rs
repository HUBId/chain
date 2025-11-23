use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::debug;

use crate::pipeline::{
    chunk_sizing::ChunkSizingStrategy, NetworkLightClientUpdate, NetworkStateSyncPlan,
    PipelineError, SnapshotChunk,
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
use crate::vendor::swarm::behaviour::{FromSwarm, ToSwarm};
#[cfg(feature = "request-response")]
use crate::vendor::swarm::{ConnectionDenied, ConnectionHandler, ConnectionId, NetworkBehaviour};

#[cfg(all(feature = "metrics", feature = "request-response"))]
use prometheus_client::metrics::counter::Counter;
#[cfg(all(feature = "metrics", feature = "request-response"))]
use prometheus_client::metrics::family::Family;
#[cfg(all(feature = "metrics", feature = "request-response"))]
use prometheus_client::metrics::gauge::Gauge;
#[cfg(all(feature = "metrics", feature = "request-response"))]
use prometheus_client::metrics::histogram::{exponential_buckets, Histogram};
#[cfg(all(feature = "metrics", feature = "request-response"))]
use prometheus_client::registry::{Registry, Unit};
#[cfg(all(feature = "metrics", feature = "request-response"))]
use std::sync::atomic::AtomicU64;

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SnapshotChunkCapabilities {
    pub chunk_size: Option<u64>,
    pub min_chunk_size: Option<u64>,
    pub max_chunk_size: Option<u64>,
    pub max_concurrent_requests: Option<u64>,
}

/// Snapshot protocol request payload.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SnapshotsRequest {
    Plan {
        session_id: SnapshotSessionId,
        /// Optional chunk size requested by the consumer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chunk_size: Option<u64>,
        /// Optional lower capability bound for negotiated chunk sizes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min_chunk_size: Option<u64>,
        /// Optional upper capability bound for negotiated chunk sizes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_chunk_size: Option<u64>,
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
        plan_id: String,
        chunk_index: u64,
        update_index: u64,
        /// Optional chunk size requested by the consumer when resuming.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chunk_size: Option<u64>,
        /// Optional lower capability bound for negotiated chunk sizes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min_chunk_size: Option<u64>,
        /// Optional upper capability bound for negotiated chunk sizes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_chunk_size: Option<u64>,
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
        plan: Vec<u8>,
        /// Optional chunk size offered by the provider for this plan.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chunk_size: Option<u64>,
        /// Optional lower capability bound for negotiated chunk sizes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min_chunk_size: Option<u64>,
        /// Optional upper capability bound for negotiated chunk sizes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_chunk_size: Option<u64>,
        /// Optional maximum concurrent requests supported by the provider for this plan.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_concurrent_requests: Option<u64>,
    },
    Chunk {
        session_id: SnapshotSessionId,
        chunk_index: u64,
        chunk: Vec<u8>,
    },
    LightClientUpdate {
        session_id: SnapshotSessionId,
        update_index: u64,
        update: Vec<u8>,
    },
    Resume {
        session_id: SnapshotSessionId,
        chunk_index: u64,
        update_index: u64,
        /// Optional chunk size offered by the provider for this session.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chunk_size: Option<u64>,
        /// Optional lower capability bound for negotiated chunk sizes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min_chunk_size: Option<u64>,
        /// Optional upper capability bound for negotiated chunk sizes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_chunk_size: Option<u64>,
        /// Optional maximum concurrent requests supported by the provider for this session.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_concurrent_requests: Option<u64>,
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

/// Status snapshot for the snapshot serving circuit breaker.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotBreakerStatus {
    pub open: bool,
    pub consecutive_failures: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Trait describing a provider that can service snapshot data requests.
pub trait SnapshotProvider: Send + Sync + 'static {
    type Error: std::error::Error + Send + Sync + 'static;

    fn open_session(
        &self,
        _session_id: SnapshotSessionId,
        _peer: &PeerId,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn start_session(
        &self,
        _session_id: SnapshotSessionId,
        _peer: &PeerId,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn finish_session(&self, _session_id: SnapshotSessionId) -> Result<(), Self::Error> {
        Ok(())
    }

    fn active_sessions(&self) -> Option<usize> {
        None
    }

    fn fetch_plan(
        &self,
        session_id: SnapshotSessionId,
    ) -> Result<NetworkStateSyncPlan, Self::Error>;

    fn fetch_chunk(
        &self,
        session_id: SnapshotSessionId,
        chunk_index: u64,
    ) -> Result<SnapshotChunk, Self::Error>;

    fn fetch_update(
        &self,
        session_id: SnapshotSessionId,
        update_index: u64,
    ) -> Result<NetworkLightClientUpdate, Self::Error>;

    fn resume_session(
        &self,
        session_id: SnapshotSessionId,
        plan_id: &str,
        chunk_index: u64,
        update_index: u64,
        chunk_size: Option<u64>,
        min_chunk_size: Option<u64>,
        max_chunk_size: Option<u64>,
    ) -> Result<SnapshotResumeState, Self::Error>;

    fn chunk_capabilities(&self) -> SnapshotChunkCapabilities {
        SnapshotChunkCapabilities::default()
    }

    fn acknowledge(
        &self,
        session_id: SnapshotSessionId,
        kind: SnapshotItemKind,
        index: u64,
    ) -> Result<(), Self::Error>;

    fn breaker_status(&self) -> SnapshotBreakerStatus {
        SnapshotBreakerStatus::default()
    }

    fn reset_breaker(&self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<T: SnapshotProvider> SnapshotProvider for Arc<T> {
    type Error = T::Error;

    fn open_session(
        &self,
        session_id: SnapshotSessionId,
        peer: &PeerId,
    ) -> Result<(), Self::Error> {
        (**self).open_session(session_id, peer)
    }

    fn start_session(
        &self,
        session_id: SnapshotSessionId,
        peer: &PeerId,
    ) -> Result<(), Self::Error> {
        (**self).start_session(session_id, peer)
    }

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
    ) -> Result<SnapshotChunk, Self::Error> {
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
        plan_id: &str,
        chunk_index: u64,
        update_index: u64,
        chunk_size: Option<u64>,
        min_chunk_size: Option<u64>,
        max_chunk_size: Option<u64>,
    ) -> Result<SnapshotResumeState, Self::Error> {
        (**self).resume_session(
            session_id,
            plan_id,
            chunk_index,
            update_index,
            chunk_size,
            min_chunk_size,
            max_chunk_size,
        )
    }

    fn acknowledge(
        &self,
        session_id: SnapshotSessionId,
        kind: SnapshotItemKind,
        index: u64,
    ) -> Result<(), Self::Error> {
        (**self).acknowledge(session_id, kind, index)
    }

    fn chunk_capabilities(&self) -> SnapshotChunkCapabilities {
        (**self).chunk_capabilities()
    }

    fn breaker_status(&self) -> SnapshotBreakerStatus {
        (**self).breaker_status()
    }

    fn reset_breaker(&self) -> Result<(), Self::Error> {
        (**self).reset_breaker()
    }

    fn finish_session(&self, session_id: SnapshotSessionId) -> Result<(), Self::Error> {
        (**self).finish_session(session_id)
    }

    fn active_sessions(&self) -> Option<usize> {
        (**self).active_sessions()
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
    ) -> Result<SnapshotChunk, Self::Error> {
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
        _plan_id: &str,
        _chunk_index: u64,
        _update_index: u64,
        _chunk_size: Option<u64>,
        _min_chunk_size: Option<u64>,
        _max_chunk_size: Option<u64>,
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

    fn chunk_capabilities(&self) -> SnapshotChunkCapabilities {
        SnapshotChunkCapabilities {
            chunk_size: Some(1),
            min_chunk_size: Some(1),
            max_chunk_size: None,
            max_concurrent_requests: None,
        }
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
        chunk: SnapshotChunk,
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
    pending_chunks: VecDeque<PendingRequest>,
    pending_updates: VecDeque<PendingRequest>,
    in_flight_chunks: usize,
    in_flight_updates: usize,
    in_flight_control: usize,
    last_dispatched_kind: Option<SnapshotItemKind>,
    last_progress: Instant,
    chunk_size: Option<u64>,
    capabilities: SnapshotChunkCapabilities,
    plan_max_concurrent_requests: Option<usize>,
    chunk_sizing: ChunkSizingStrategy,
}

#[cfg(feature = "request-response")]
#[derive(Clone, Copy, Debug)]
struct PendingRequest {
    index: u64,
    enqueued_at: Instant,
}

#[cfg(feature = "request-response")]
impl SessionState {
    fn new(peer: PeerId) -> Self {
        Self::with_capabilities(peer, SnapshotChunkCapabilities::default())
    }

    fn with_capabilities(peer: PeerId, capabilities: SnapshotChunkCapabilities) -> Self {
        let chunk_sizing = Self::chunk_sizing_for(&capabilities);
        Self {
            peer,
            next_chunk_index: 0,
            next_update_index: 0,
            pending_chunks: VecDeque::new(),
            pending_updates: VecDeque::new(),
            in_flight_chunks: 0,
            in_flight_updates: 0,
            in_flight_control: 0,
            last_dispatched_kind: None,
            last_progress: Instant::now(),
            chunk_size: capabilities.chunk_size,
            capabilities,
            plan_max_concurrent_requests: None,
            chunk_sizing,
        }
    }

    fn mark_progress(&mut self) {
        self.last_progress = Instant::now();
    }

    fn chunk_sizing_for(capabilities: &SnapshotChunkCapabilities) -> ChunkSizingStrategy {
        let min = capabilities.min_chunk_size.unwrap_or(1) as usize;
        let max = capabilities
            .max_chunk_size
            .or(capabilities.chunk_size)
            .unwrap_or(min as u64) as usize;
        let initial = capabilities.chunk_size.unwrap_or(min as u64) as usize;
        ChunkSizingStrategy::new(min, max, initial, Duration::from_millis(500))
    }

    fn update_capabilities(&mut self, capabilities: SnapshotChunkCapabilities) {
        self.chunk_size = capabilities.chunk_size.or(self.chunk_size);
        self.capabilities = capabilities.clone();
        self.chunk_sizing = Self::chunk_sizing_for(&capabilities);
    }

    fn set_plan_concurrency_limit(&mut self, limit: Option<u64>) {
        if let Some(limit) = limit.and_then(|value| usize::try_from(value).ok()) {
            self.plan_max_concurrent_requests = Some(limit);
        }
    }

    fn record_chunk_telemetry(&mut self, bytes: usize, rtt: Duration) {
        self.chunk_sizing.record_sample(bytes, rtt);
    }

    fn negotiated_chunk_size(&mut self) -> u64 {
        let size = self.chunk_sizing.next_chunk_size() as u64;
        self.chunk_size = Some(size);
        size
    }

    fn enqueue(&mut self, kind: SnapshotItemKind, index: u64) {
        let request = PendingRequest {
            index,
            enqueued_at: Instant::now(),
        };
        match kind {
            SnapshotItemKind::Chunk => self.pending_chunks.push_back(request),
            SnapshotItemKind::LightClientUpdate => self.pending_updates.push_back(request),
            _ => {}
        }
    }

    fn pop_next_pending(&mut self) -> Option<(SnapshotItemKind, PendingRequest)> {
        let next_kind = match (
            self.pending_chunks.front().copied(),
            self.pending_updates.front().copied(),
        ) {
            (Some(_), Some(_)) => match self.last_dispatched_kind {
                Some(SnapshotItemKind::Chunk) => SnapshotItemKind::LightClientUpdate,
                Some(SnapshotItemKind::LightClientUpdate) => SnapshotItemKind::Chunk,
                _ => SnapshotItemKind::Chunk,
            },
            (Some(_), None) => SnapshotItemKind::Chunk,
            (None, Some(_)) => SnapshotItemKind::LightClientUpdate,
            (None, None) => return None,
        };

        match next_kind {
            SnapshotItemKind::Chunk => self.pending_chunks.pop_front().map(|request| {
                self.last_dispatched_kind = Some(SnapshotItemKind::Chunk);
                (SnapshotItemKind::Chunk, request)
            }),
            SnapshotItemKind::LightClientUpdate => {
                self.pending_updates.pop_front().map(|request| {
                    self.last_dispatched_kind = Some(SnapshotItemKind::LightClientUpdate);
                    (SnapshotItemKind::LightClientUpdate, request)
                })
            }
            _ => None,
        }
    }

    fn record_outbound(&mut self, kind: SnapshotItemKind) {
        match kind {
            SnapshotItemKind::Chunk => {
                self.in_flight_chunks = self.in_flight_chunks.saturating_add(1)
            }
            SnapshotItemKind::LightClientUpdate => {
                self.in_flight_updates = self.in_flight_updates.saturating_add(1)
            }
            _ => self.in_flight_control = self.in_flight_control.saturating_add(1),
        }
    }

    fn finish_outbound(&mut self, kind: SnapshotItemKind) {
        match kind {
            SnapshotItemKind::Chunk => {
                self.in_flight_chunks = self.in_flight_chunks.saturating_sub(1)
            }
            SnapshotItemKind::LightClientUpdate => {
                self.in_flight_updates = self.in_flight_updates.saturating_sub(1)
            }
            _ => self.in_flight_control = self.in_flight_control.saturating_sub(1),
        }
    }

    fn total_in_flight(&self) -> usize {
        self.in_flight_chunks + self.in_flight_updates + self.in_flight_control
    }

    fn effective_concurrency_limit(&self, configured_limit: Option<usize>) -> usize {
        let limits = [
            configured_limit,
            self.capabilities
                .max_concurrent_requests
                .and_then(|limit| usize::try_from(limit).ok()),
            self.plan_max_concurrent_requests,
        ];

        limits.into_iter().flatten().min().unwrap_or(1).max(1)
    }

    fn has_capacity(&self, configured_limit: Option<usize>) -> bool {
        self.total_in_flight() < self.effective_concurrency_limit(configured_limit)
    }

    fn queue_depths(&self) -> (usize, usize) {
        (self.pending_chunks.len(), self.pending_updates.len())
    }

    fn backpressure_since(&self, kind: SnapshotItemKind) -> Option<Duration> {
        match kind {
            SnapshotItemKind::Chunk => self
                .pending_chunks
                .front()
                .map(|request| request.enqueued_at.elapsed()),
            SnapshotItemKind::LightClientUpdate => self
                .pending_updates
                .front()
                .map(|request| request.enqueued_at.elapsed()),
            _ => None,
        }
    }

    fn lag_since_last_progress(&self) -> Duration {
        self.last_progress.elapsed()
    }

    fn lag_since_oldest_pending(&self) -> Duration {
        let oldest_pending = [
            self.backpressure_since(SnapshotItemKind::Chunk),
            self.backpressure_since(SnapshotItemKind::LightClientUpdate),
        ]
        .into_iter()
        .flatten()
        .max()
        .unwrap_or_else(|| Duration::from_secs(0));

        self.lag_since_last_progress().max(oldest_pending)
    }
}

#[cfg(all(feature = "metrics", feature = "request-response"))]
#[derive(Clone)]
struct SnapshotStreamMetrics {
    bytes_transferred: Family<Vec<(String, String)>, Counter>,
    request_telemetry: SnapshotRequestTelemetry,
    lag_seconds: Gauge<f64, AtomicU64>,
    resume_events: Family<Vec<(String, String)>, Counter>,
    failures: Family<Vec<(String, String)>, Counter>,
    chunk_send_latency_seconds: Histogram,
    chunk_send_queue_depth: Gauge<u64, AtomicU64>,
    request_queue_depth: Family<Vec<(String, String)>, Gauge<u64, AtomicU64>>,
    in_flight_requests: Family<Vec<(String, String)>, Gauge<u64, AtomicU64>>,
    concurrency_limit: Family<Vec<(String, String)>, Gauge<u64, AtomicU64>>,
    backpressure_seconds: Family<Vec<(String, String)>, Gauge<f64, AtomicU64>>,
    negotiated_chunk_size_bytes: Family<Vec<(String, String)>, Gauge<u64, AtomicU64>>,
    negotiated_chunk_size_bytes_histogram: Histogram,
    adaptive_chunk_size_bytes: Gauge<u64, AtomicU64>,
    adaptive_chunk_size_bytes_histogram: Histogram,
    breaker_open: Gauge<u64, AtomicU64>,
    breaker_consecutive_failures: Gauge<u64, AtomicU64>,
}

#[cfg(feature = "request-response")]
#[derive(Clone, Copy, Debug)]
struct SnapshotRequestTiming {
    request_kind: SnapshotItemKind,
    response_kind: Option<SnapshotItemKind>,
    started_at: Instant,
    request_bytes: usize,
    response_bytes: Option<usize>,
}

#[cfg(feature = "request-response")]
impl SnapshotRequestTiming {
    fn with_request(request_kind: SnapshotItemKind, request_bytes: usize) -> Self {
        Self {
            request_kind,
            response_kind: None,
            started_at: Instant::now(),
            request_bytes,
            response_bytes: None,
        }
    }

    fn set_response(&mut self, kind: SnapshotItemKind, bytes: usize) {
        self.response_kind = Some(kind);
        self.response_bytes = Some(bytes);
    }
}

#[cfg(feature = "request-response")]
#[derive(Default)]
struct SnapshotRequestMetrics {
    outbound: HashMap<RequestResponseId, SnapshotRequestTiming>,
    inbound: HashMap<RequestResponseInboundId, SnapshotRequestTiming>,
    #[cfg(feature = "metrics")]
    telemetry: Option<SnapshotRequestTelemetry>,
}

#[cfg(feature = "request-response")]
impl SnapshotRequestMetrics {
    #[cfg(feature = "metrics")]
    fn with_telemetry(telemetry: Option<SnapshotRequestTelemetry>) -> Self {
        Self {
            outbound: HashMap::new(),
            inbound: HashMap::new(),
            telemetry,
        }
    }

    #[cfg(not(feature = "metrics"))]
    fn with_telemetry(_telemetry: Option<SnapshotRequestTelemetry>) -> Self {
        Self {
            outbound: HashMap::new(),
            inbound: HashMap::new(),
        }
    }

    fn start_outbound(
        &mut self,
        request_id: RequestResponseId,
        kind: SnapshotItemKind,
        request_bytes: usize,
    ) {
        self.outbound.insert(
            request_id,
            SnapshotRequestTiming::with_request(kind, request_bytes),
        );
    }

    fn start_inbound(
        &mut self,
        request_id: RequestResponseInboundId,
        kind: SnapshotItemKind,
        request_bytes: usize,
    ) {
        self.inbound.insert(
            request_id,
            SnapshotRequestTiming::with_request(kind, request_bytes),
        );
    }

    fn record_inbound_response(
        &mut self,
        request_id: RequestResponseInboundId,
        response_kind: SnapshotItemKind,
        response_bytes: usize,
    ) {
        if let Some(entry) = self.inbound.get_mut(&request_id) {
            entry.set_response(response_kind, response_bytes);
        }
    }

    fn finish_outbound(
        &mut self,
        request_id: RequestResponseId,
        response_kind: SnapshotItemKind,
        response_bytes: usize,
    ) -> Option<SnapshotRequestTiming> {
        if let Some(mut entry) = self.outbound.remove(&request_id) {
            entry.set_response(response_kind, response_bytes);
            let emitted = entry.clone();
            #[cfg(feature = "metrics")]
            {
                Self::emit("outbound", emitted, self.telemetry.as_ref());
            }

            #[cfg(not(feature = "metrics"))]
            {
                Self::emit("outbound", emitted);
            }

            return Some(entry);
        }

        None
    }

    fn finish_inbound(&mut self, request_id: RequestResponseInboundId) {
        if let Some(entry) = self.inbound.remove(&request_id) {
            #[cfg(feature = "metrics")]
            {
                Self::emit("inbound", entry, self.telemetry.as_ref());
            }

            #[cfg(not(feature = "metrics"))]
            {
                Self::emit("inbound", entry);
            }
        }
    }

    fn fail_outbound(&mut self, request_id: RequestResponseId) {
        self.outbound.remove(&request_id);
    }

    fn fail_inbound(&mut self, request_id: RequestResponseInboundId) {
        self.inbound.remove(&request_id);
    }

    fn emit(
        direction: &str,
        entry: SnapshotRequestTiming,
        #[cfg(feature = "metrics")] telemetry: Option<&SnapshotRequestTelemetry>,
    ) {
        let response_kind = entry.response_kind.unwrap_or(entry.request_kind);
        let response_bytes = entry.response_bytes.unwrap_or(0);
        let elapsed = entry.started_at.elapsed();
        let throughput = if elapsed.is_zero() {
            None
        } else {
            Some(response_bytes as f64 / elapsed.as_secs_f64())
        };

        #[cfg(feature = "metrics")]
        if let Some(telemetry) = telemetry {
            telemetry.observe(
                direction,
                entry.request_kind,
                response_kind,
                entry.request_bytes,
                response_bytes,
                elapsed,
                throughput,
            );
        }

        debug!(
            target: "telemetry.snapshots",
            direction,
            request_kind = ?entry.request_kind,
            response_kind = ?response_kind,
            request_bytes = entry.request_bytes,
            response_bytes,
            rtt_ms = elapsed.as_millis(),
            throughput_bytes_per_sec = throughput,
            "snapshot_request_metrics"
        );
    }
}

#[cfg(all(feature = "metrics", feature = "request-response"))]
impl SnapshotStreamMetrics {
    fn register(registry: &mut Registry) -> Self {
        let bytes_transferred = Family::<Vec<(String, String)>, Counter>::default();
        registry.register_with_unit(
            "snapshot_bytes_sent_total",
            "Total snapshot payload bytes transferred grouped by direction and item kind",
            Unit::Bytes,
            bytes_transferred.clone(),
        );

        let request_telemetry = SnapshotRequestTelemetry::register(registry);

        let resume_events = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "snapshot_resume_events_total",
            "Snapshot resume attempts grouped by result",
            resume_events.clone(),
        );

        let lag_seconds = Gauge::<f64, AtomicU64>::default();
        registry.register_with_unit(
            "snapshot_stream_lag_seconds",
            "Maximum observed delay in seconds since the last snapshot item was processed",
            Unit::Seconds,
            lag_seconds.clone(),
        );

        let failures = Family::<Vec<(String, String)>, Counter>::default();
        registry.register(
            "light_client_chunk_failures_total",
            "Count of snapshot chunk and light client update failures grouped by direction",
            failures.clone(),
        );

        let chunk_send_latency_seconds = Histogram::new(exponential_buckets(0.001, 2.0, 16));
        registry.register_with_unit(
            "snapshot_chunk_send_latency_seconds",
            "Time in seconds for snapshot chunk responses to flush to the consumer",
            Unit::Seconds,
            chunk_send_latency_seconds.clone(),
        );

        let chunk_send_queue_depth = Gauge::<u64, AtomicU64>::default();
        registry.register(
            "snapshot_chunk_send_queue_depth",
            "Number of snapshot chunk responses waiting to flush to consumers",
            chunk_send_queue_depth.clone(),
        );

        let request_queue_depth = Family::<Vec<(String, String)>, Gauge<u64, AtomicU64>>::default();
        registry.register(
            "snapshot_request_queue_depth",
            "Number of snapshot protocol requests queued by the consumer grouped by item kind",
            request_queue_depth.clone(),
        );

        let in_flight_requests = Family::<Vec<(String, String)>, Gauge<u64, AtomicU64>>::default();
        registry.register(
            "snapshot_in_flight_requests",
            "Number of snapshot protocol requests in flight grouped by item kind",
            in_flight_requests.clone(),
        );

        let concurrency_limit = Family::<Vec<(String, String)>, Gauge<u64, AtomicU64>>::default();
        registry.register(
            "snapshot_concurrency_limit",
            "Effective snapshot request concurrency limits grouped by source",
            concurrency_limit.clone(),
        );

        let backpressure_seconds =
            Family::<Vec<(String, String)>, Gauge<f64, AtomicU64>>::default();
        registry.register_with_unit(
            "snapshot_request_backpressure_seconds",
            "Age in seconds of the oldest pending snapshot request grouped by item kind",
            Unit::Seconds,
            backpressure_seconds.clone(),
        );

        let negotiated_chunk_size_bytes =
            Family::<Vec<(String, String)>, Gauge<u64, AtomicU64>>::default();
        registry.register_with_unit(
            "snapshot_negotiated_chunk_size_bytes",
            "Last negotiated snapshot chunk size in bytes grouped by role (provider or consumer)",
            Unit::Bytes,
            negotiated_chunk_size_bytes.clone(),
        );

        let negotiated_chunk_size_bytes_histogram =
            Histogram::new(exponential_buckets(64.0, 2.0, 12));
        registry.register_with_unit(
            "snapshot_negotiated_chunk_size_bytes_histogram",
            "Distribution of negotiated snapshot chunk sizes in bytes",
            Unit::Bytes,
            negotiated_chunk_size_bytes_histogram.clone(),
        );

        let adaptive_chunk_size_bytes = Gauge::<u64, AtomicU64>::default();
        registry.register_with_unit(
            "snapshot_adaptive_chunk_size_bytes",
            "Most recent adaptive snapshot chunk size selected by the requester",
            Unit::Bytes,
            adaptive_chunk_size_bytes.clone(),
        );

        let adaptive_chunk_size_bytes_histogram =
            Histogram::new(exponential_buckets(64.0, 2.0, 12));
        registry.register_with_unit(
            "snapshot_adaptive_chunk_size_bytes_histogram",
            "Distribution of adaptive snapshot chunk sizes selected by the requester",
            Unit::Bytes,
            adaptive_chunk_size_bytes_histogram.clone(),
        );

        let breaker_open = Gauge::<u64, AtomicU64>::default();
        registry.register(
            "snapshot_provider_circuit_open",
            "Whether the snapshot serving circuit breaker is open (1) or closed (0)",
            breaker_open.clone(),
        );

        let breaker_consecutive_failures = Gauge::<u64, AtomicU64>::default();
        registry.register(
            "snapshot_provider_consecutive_failures",
            "Consecutive snapshot serving failures observed by the circuit breaker",
            breaker_consecutive_failures.clone(),
        );

        Self {
            bytes_transferred,
            request_telemetry,
            lag_seconds,
            resume_events,
            failures,
            chunk_send_latency_seconds,
            chunk_send_queue_depth,
            request_queue_depth,
            in_flight_requests,
            concurrency_limit,
            backpressure_seconds,
            negotiated_chunk_size_bytes,
            negotiated_chunk_size_bytes_histogram,
            adaptive_chunk_size_bytes,
            adaptive_chunk_size_bytes_histogram,
            breaker_open,
            breaker_consecutive_failures,
        }
    }

    fn record_bytes(&self, direction: &str, kind: SnapshotItemKind, bytes: usize) {
        let kind_label = match kind {
            SnapshotItemKind::Plan => "plan",
            SnapshotItemKind::Chunk => "chunk",
            SnapshotItemKind::LightClientUpdate => "light_client_update",
            SnapshotItemKind::Resume => "resume",
            SnapshotItemKind::Ack => "ack",
            SnapshotItemKind::Error => "error",
        };
        let labels = vec![
            ("direction".to_string(), direction.to_string()),
            ("kind".to_string(), kind_label.to_string()),
        ];
        self.bytes_transferred
            .get_or_create(&labels)
            .inc_by(bytes as u64);
    }

    fn telemetry(&self) -> SnapshotRequestTelemetry {
        self.request_telemetry.clone()
    }

    fn observe_lag(&self, lag: Duration) {
        self.lag_seconds.set(lag.as_secs_f64());
    }

    fn record_resume(&self, result: &str) {
        let labels = vec![("result".to_string(), result.to_string())];
        self.resume_events.get_or_create(&labels).inc();
    }

    fn record_failure(&self, direction: &str, kind: SnapshotItemKind) {
        let failure_kind = match kind {
            SnapshotItemKind::Chunk => Some("chunk"),
            SnapshotItemKind::LightClientUpdate => Some("light_client_update"),
            _ => None,
        };

        if let Some(kind_label) = failure_kind {
            let labels = vec![
                ("direction".to_string(), direction.to_string()),
                ("kind".to_string(), kind_label.to_string()),
            ];
            self.failures.get_or_create(&labels).inc();
        }
    }

    fn record_negotiated_chunk_size(&self, role: &str, size: u64) {
        let labels = vec![("role".to_string(), role.to_string())];
        self.negotiated_chunk_size_bytes
            .get_or_create(&labels)
            .set(size);
        self.negotiated_chunk_size_bytes_histogram
            .observe(size as f64);
    }

    fn record_adaptive_chunk_size(&self, size: u64) {
        self.adaptive_chunk_size_bytes.set(size);
        self.adaptive_chunk_size_bytes_histogram
            .observe(size as f64);
    }

    fn observe_send_latency(&self, kind: SnapshotItemKind, latency: Duration) {
        if matches!(kind, SnapshotItemKind::Chunk) {
            self.chunk_send_latency_seconds
                .observe(latency.as_secs_f64());
        }
    }

    fn record_queue_depth(&self, depth: usize) {
        self.chunk_send_queue_depth.set(depth as u64);
    }

    fn record_request_queue_depths(&self, chunks: usize, updates: usize, control: usize) {
        for (kind, depth) in [
            ("chunk", chunks),
            ("light_client_update", updates),
            ("control", control),
        ] {
            let labels = vec![("kind".to_string(), kind.to_string())];
            self.request_queue_depth
                .get_or_create(&labels)
                .set(depth as u64);
        }
    }

    fn record_in_flight_requests(&self, chunks: usize, updates: usize, control: usize) {
        for (kind, total) in [
            ("chunk", chunks),
            ("light_client_update", updates),
            ("control", control),
        ] {
            let labels = vec![("kind".to_string(), kind.to_string())];
            self.in_flight_requests
                .get_or_create(&labels)
                .set(total as u64);
        }
    }

    fn record_concurrency_limits(
        &self,
        configured: usize,
        provider: Option<usize>,
        plan: Option<usize>,
        effective: usize,
    ) {
        for (source, value) in [
            ("configured", Some(configured)),
            ("provider", provider),
            ("plan", plan),
            ("effective", Some(effective)),
        ] {
            if let Some(limit) = value {
                let labels = vec![("source".to_string(), source.to_string())];
                self.concurrency_limit
                    .get_or_create(&labels)
                    .set(limit as u64);
            }
        }
    }

    fn record_backpressure(&self, kind: SnapshotItemKind, age: Duration) {
        let label = match kind {
            SnapshotItemKind::Chunk => Some("chunk"),
            SnapshotItemKind::LightClientUpdate => Some("light_client_update"),
            _ => None,
        };

        if let Some(kind_label) = label {
            let labels = vec![("kind".to_string(), kind_label.to_string())];
            self.backpressure_seconds
                .get_or_create(&labels)
                .set(age.as_secs_f64());
        }
    }

    fn record_breaker(&self, status: &SnapshotBreakerStatus) {
        self.breaker_open.set(if status.open { 1 } else { 0 });
        self.breaker_consecutive_failures
            .set(status.consecutive_failures);
    }
}

#[cfg(all(feature = "metrics", feature = "request-response"))]
#[derive(Clone)]
struct SnapshotRequestTelemetry {
    bytes_total: Family<Vec<(String, String, String)>, Counter>,
    rtt_seconds: Family<Vec<(String, String)>, Histogram>,
    throughput_bytes_per_second: Family<Vec<(String, String)>, Histogram>,
}

#[cfg(all(feature = "metrics", feature = "request-response"))]
impl SnapshotRequestTelemetry {
    fn register(registry: &mut Registry) -> Self {
        let bytes_total = Family::<Vec<(String, String, String)>, Counter>::default();
        registry.register_with_unit(
            "snapshot_message_bytes_total",
            "Total snapshot request and response payload bytes grouped by direction, flow, and item kind",
            Unit::Bytes,
            bytes_total.clone(),
        );

        let rtt_seconds = Family::<Vec<(String, String)>, Histogram>::new_with_constructor(|| {
            Histogram::new(exponential_buckets(0.001, 2.0, 16))
        });
        registry.register_with_unit(
            "snapshot_request_rtt_seconds",
            "Round-trip time in seconds for snapshot requests grouped by direction and item kind",
            Unit::Seconds,
            rtt_seconds.clone(),
        );

        let throughput_bytes_per_second =
            Family::<Vec<(String, String)>, Histogram>::new_with_constructor(|| {
                Histogram::new(exponential_buckets(1024.0, 2.0, 16))
            });
        registry.register(
            "snapshot_response_throughput_bytes_per_second",
            "Observed throughput in bytes per second for snapshot responses grouped by direction and item kind",
            throughput_bytes_per_second.clone(),
        );

        Self {
            bytes_total,
            rtt_seconds,
            throughput_bytes_per_second,
        }
    }

    fn observe(
        &self,
        direction: &str,
        request_kind: SnapshotItemKind,
        response_kind: SnapshotItemKind,
        request_bytes: usize,
        response_bytes: usize,
        elapsed: Duration,
        throughput: Option<f64>,
    ) {
        let request_flow = if direction == "outbound" {
            "sent"
        } else {
            "received"
        };
        let response_flow = if direction == "outbound" {
            "received"
        } else {
            "sent"
        };
        let request_labels = vec![
            ("direction".to_string(), direction.to_string()),
            ("flow".to_string(), request_flow.to_string()),
            (
                "kind".to_string(),
                SnapshotRequestTelemetry::kind_label(request_kind).to_string(),
            ),
        ];
        let response_labels = vec![
            ("direction".to_string(), direction.to_string()),
            ("flow".to_string(), response_flow.to_string()),
            (
                "kind".to_string(),
                SnapshotRequestTelemetry::kind_label(response_kind).to_string(),
            ),
        ];

        self.bytes_total
            .get_or_create(&request_labels)
            .inc_by(request_bytes as u64);
        self.bytes_total
            .get_or_create(&response_labels)
            .inc_by(response_bytes as u64);

        let response_metrics_labels = vec![
            ("direction".to_string(), direction.to_string()),
            (
                "kind".to_string(),
                SnapshotRequestTelemetry::kind_label(response_kind).to_string(),
            ),
        ];
        self.rtt_seconds
            .get_or_create(&response_metrics_labels)
            .observe(elapsed.as_secs_f64());

        if let Some(throughput) = throughput {
            self.throughput_bytes_per_second
                .get_or_create(&response_metrics_labels)
                .observe(throughput);
        }
    }

    fn kind_label(kind: SnapshotItemKind) -> &'static str {
        match kind {
            SnapshotItemKind::Plan => "plan",
            SnapshotItemKind::Chunk => "chunk",
            SnapshotItemKind::LightClientUpdate => "light_client_update",
            SnapshotItemKind::Resume => "resume",
            SnapshotItemKind::Ack => "ack",
            SnapshotItemKind::Error => "error",
        }
    }
}

#[cfg(feature = "request-response")]
fn snapshot_request_kind(request: &SnapshotsRequest) -> SnapshotItemKind {
    match request {
        SnapshotsRequest::Plan { .. } => SnapshotItemKind::Plan,
        SnapshotsRequest::Chunk { .. } => SnapshotItemKind::Chunk,
        SnapshotsRequest::LightClientUpdate { .. } => SnapshotItemKind::LightClientUpdate,
        SnapshotsRequest::Resume { .. } => SnapshotItemKind::Resume,
        SnapshotsRequest::Ack { .. } => SnapshotItemKind::Ack,
        SnapshotsRequest::Error { .. } => SnapshotItemKind::Error,
    }
}

#[cfg(feature = "request-response")]
fn snapshot_response_kind(response: &SnapshotsResponse) -> SnapshotItemKind {
    match response {
        SnapshotsResponse::Plan { .. } => SnapshotItemKind::Plan,
        SnapshotsResponse::Chunk { .. } => SnapshotItemKind::Chunk,
        SnapshotsResponse::LightClientUpdate { .. } => SnapshotItemKind::LightClientUpdate,
        SnapshotsResponse::Resume { .. } => SnapshotItemKind::Resume,
        SnapshotsResponse::Ack { .. } => SnapshotItemKind::Ack,
        SnapshotsResponse::Error { .. } => SnapshotItemKind::Error,
    }
}

#[cfg(feature = "request-response")]
fn snapshot_message_size<T: Serialize>(message: &T) -> usize {
    serde_json::to_vec(message)
        .map(|bytes| bytes.len())
        .unwrap_or(0)
}

/// Behaviour managing snapshot-related networking logic.
#[cfg(feature = "request-response")]
pub struct SnapshotsBehaviour<P: SnapshotProvider> {
    inner: RequestResponseBehaviour<SnapshotsCodec>,
    provider: P,
    pending_events: VecDeque<SnapshotsEvent>,
    requests: HashMap<RequestResponseId, (SnapshotSessionId, SnapshotItemKind)>,
    sessions: HashMap<SnapshotSessionId, SessionState>,
    provider_sessions: HashSet<SnapshotSessionId>,
    config: SnapshotsBehaviourConfig,
    request_metrics: SnapshotRequestMetrics,
    #[cfg(feature = "metrics")]
    metrics: Option<SnapshotStreamMetrics>,
    #[cfg(feature = "metrics")]
    response_timers: HashMap<RequestResponseInboundId, ResponseInFlight>,
}

#[cfg(all(feature = "metrics", feature = "request-response"))]
struct ResponseInFlight {
    kind: SnapshotItemKind,
    started_at: Instant,
}

/// Configuration for [`SnapshotsBehaviour`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SnapshotsBehaviourConfig {
    /// Maximum number of concurrent outbound requests per session.
    ///
    /// When unset, the behaviour matches the legacy single-request-in-flight
    /// semantics.
    pub max_concurrent_requests: Option<usize>,
    /// Maximum number of inbound snapshot sessions that may be served concurrently.
    pub max_inbound_sessions: Option<usize>,
}

#[cfg(feature = "request-response")]
impl<P: SnapshotProvider> SnapshotsBehaviour<P> {
    /// Creates a new `SnapshotsBehaviour` for the given provider.
    #[cfg(feature = "metrics")]
    pub fn new(provider: P, registry: Option<&mut Registry>) -> Self {
        Self::with_config(provider, SnapshotsBehaviourConfig::default(), registry)
    }

    #[cfg(feature = "metrics")]
    pub fn with_config(
        provider: P,
        config: SnapshotsBehaviourConfig,
        registry: Option<&mut Registry>,
    ) -> Self {
        let protocols = vec![(SNAPSHOTS_PROTOCOL_ID.to_string(), ProtocolSupport::Full)];
        let config = RequestResponseConfig::default();
        let metrics = registry.map(SnapshotStreamMetrics::register);
        let request_metrics = SnapshotRequestMetrics::with_telemetry(
            metrics.as_ref().map(SnapshotStreamMetrics::telemetry),
        );
        Self {
            inner: RequestResponseBehaviour::new(protocols, config),
            provider,
            pending_events: VecDeque::new(),
            requests: HashMap::new(),
            sessions: HashMap::new(),
            provider_sessions: HashSet::new(),
            config,
            request_metrics,
            metrics,
            response_timers: HashMap::new(),
        }
    }

    #[cfg(not(feature = "metrics"))]
    pub fn new(provider: P) -> Self {
        Self::with_config(provider, SnapshotsBehaviourConfig::default())
    }

    #[cfg(not(feature = "metrics"))]
    pub fn with_config(provider: P, config: SnapshotsBehaviourConfig) -> Self {
        let protocols = vec![(SNAPSHOTS_PROTOCOL_ID.to_string(), ProtocolSupport::Full)];
        let config = RequestResponseConfig::default();
        Self {
            inner: RequestResponseBehaviour::new(protocols, config),
            provider,
            pending_events: VecDeque::new(),
            requests: HashMap::new(),
            sessions: HashMap::new(),
            provider_sessions: HashSet::new(),
            config,
            request_metrics: SnapshotRequestMetrics::default(),
        }
    }

    #[cfg(feature = "metrics")]
    fn track_response(&mut self, request_id: RequestResponseInboundId, kind: SnapshotItemKind) {
        if let Some(metrics) = &self.metrics {
            if matches!(kind, SnapshotItemKind::Chunk) {
                self.response_timers.insert(
                    request_id,
                    ResponseInFlight {
                        kind,
                        started_at: Instant::now(),
                    },
                );
                metrics.record_queue_depth(self.response_timers.len());
            }
        }
    }

    #[cfg(feature = "metrics")]
    fn record_response_sent(&mut self, request_id: RequestResponseInboundId) {
        if let Some(metrics) = &self.metrics {
            if let Some(in_flight) = self.response_timers.remove(&request_id) {
                metrics.observe_send_latency(in_flight.kind, in_flight.started_at.elapsed());
                metrics.record_queue_depth(self.response_timers.len());
            }
        }
    }

    #[cfg(feature = "metrics")]
    fn clear_response_timer(&mut self, request_id: RequestResponseInboundId) {
        if let Some(metrics) = &self.metrics {
            if self.response_timers.remove(&request_id).is_some() {
                metrics.record_queue_depth(self.response_timers.len());
            }
        }
    }

    /// Returns a reference to the wrapped provider instance.
    pub fn provider(&self) -> &P {
        &self.provider
    }

    #[cfg(feature = "metrics")]
    fn record_bytes(&self, direction: &str, kind: SnapshotItemKind, bytes: usize) {
        if let Some(metrics) = &self.metrics {
            metrics.record_bytes(direction, kind, bytes);
        }
    }

    #[cfg(not(feature = "metrics"))]
    fn record_bytes(&self, _direction: &str, _kind: SnapshotItemKind, _bytes: usize) {}

    #[cfg(feature = "metrics")]
    fn record_failure(&self, direction: &str, kind: SnapshotItemKind) {
        if let Some(metrics) = &self.metrics {
            metrics.record_failure(direction, kind);
        }
    }

    #[cfg(not(feature = "metrics"))]
    fn record_failure(&self, _direction: &str, _kind: SnapshotItemKind) {}

    #[cfg(feature = "metrics")]
    fn record_negotiated_chunk_size(&self, role: &str, size: u64) {
        if let Some(metrics) = &self.metrics {
            metrics.record_negotiated_chunk_size(role, size);
        }
    }

    #[cfg(not(feature = "metrics"))]
    fn record_negotiated_chunk_size(&self, _role: &str, _size: u64) {}

    #[cfg(feature = "metrics")]
    fn record_adaptive_chunk_size(&self, size: u64) {
        if let Some(metrics) = &self.metrics {
            metrics.record_adaptive_chunk_size(size);
        }
    }

    #[cfg(not(feature = "metrics"))]
    fn record_adaptive_chunk_size(&self, _size: u64) {}

    #[cfg(feature = "metrics")]
    fn update_stream_metrics(&mut self) {
        if let Some(metrics) = &self.metrics {
            let configured_limit = self.configured_concurrency_limit().unwrap_or(1);
            let mut lag = Duration::from_secs(0);
            let mut pending_chunks = 0;
            let mut pending_updates = 0;
            let mut in_flight_chunks = 0;
            let mut in_flight_updates = 0;
            let mut in_flight_control = 0;
            let mut provider_limit: Option<usize> = None;
            let mut plan_limit: Option<usize> = None;
            let mut effective_limit: Option<usize> = None;
            let mut backpressure_chunks = Duration::from_secs(0);
            let mut backpressure_updates = Duration::from_secs(0);

            for state in self.sessions.values() {
                lag = lag.max(state.lag_since_oldest_pending());
                let (chunk_depth, update_depth) = state.queue_depths();
                pending_chunks += chunk_depth;
                pending_updates += update_depth;
                in_flight_chunks += state.in_flight_chunks;
                in_flight_updates += state.in_flight_updates;
                in_flight_control += state.in_flight_control;

                if let Some(limit) = state
                    .capabilities
                    .max_concurrent_requests
                    .and_then(|value| usize::try_from(value).ok())
                {
                    provider_limit =
                        Some(provider_limit.map_or(limit, |current| current.min(limit)));
                }

                if let Some(limit) = state.plan_max_concurrent_requests {
                    plan_limit = Some(plan_limit.map_or(limit, |current| current.min(limit)));
                }

                let state_limit =
                    state.effective_concurrency_limit(self.configured_concurrency_limit());
                effective_limit =
                    Some(effective_limit.map_or(state_limit, |current| current.min(state_limit)));

                if let Some(age) = state.backpressure_since(SnapshotItemKind::Chunk) {
                    backpressure_chunks = backpressure_chunks.max(age);
                }
                if let Some(age) = state.backpressure_since(SnapshotItemKind::LightClientUpdate) {
                    backpressure_updates = backpressure_updates.max(age);
                }
            }

            metrics.observe_lag(lag);
            metrics.record_request_queue_depths(pending_chunks, pending_updates, 0);
            metrics.record_in_flight_requests(
                in_flight_chunks,
                in_flight_updates,
                in_flight_control,
            );
            metrics.record_concurrency_limits(
                configured_limit,
                provider_limit,
                plan_limit,
                effective_limit.unwrap_or(configured_limit),
            );
            metrics.record_backpressure(SnapshotItemKind::Chunk, backpressure_chunks);
            metrics.record_backpressure(SnapshotItemKind::LightClientUpdate, backpressure_updates);
        }
    }

    #[cfg(not(feature = "metrics"))]
    fn update_stream_metrics(&mut self) {}

    fn record_request_update(
        &mut self,
        session_id: SnapshotSessionId,
        kind: SnapshotItemKind,
        stage: &str,
    ) {
        #[cfg(feature = "metrics")]
        self.update_stream_metrics();

        if let Some(state) = self.sessions.get(&session_id) {
            debug!(
                target: "telemetry.snapshots",
                %session_id,
                %stage,
                kind = ?kind,
                peer = ?state.peer,
                pending_chunks = state.pending_chunks.len(),
                pending_updates = state.pending_updates.len(),
                in_flight_chunks = state.in_flight_chunks,
                in_flight_updates = state.in_flight_updates,
                in_flight_control = state.in_flight_control,
                effective_limit = state.effective_concurrency_limit(self.configured_concurrency_limit()),
                "snapshot_request_progress"
            );
        }
    }

    fn configured_concurrency_limit(&self) -> Option<usize> {
        self.config
            .max_concurrent_requests
            .map(|limit| limit.max(1))
    }

    fn track_outbound_request(
        &mut self,
        session_id: SnapshotSessionId,
        kind: SnapshotItemKind,
        request_bytes: usize,
        request_id: RequestResponseId,
    ) {
        self.request_metrics
            .start_outbound(request_id, kind, request_bytes);
        if let Some(state) = self.sessions.get_mut(&session_id) {
            state.record_outbound(kind);
        }
        self.requests.insert(request_id, (session_id, kind));
        #[cfg(feature = "metrics")]
        self.update_stream_metrics();
    }

    fn finish_outbound_request(&mut self, session_id: SnapshotSessionId, kind: SnapshotItemKind) {
        if let Some(state) = self.sessions.get_mut(&session_id) {
            state.finish_outbound(kind);
        }
    }

    fn active_provider_sessions(&self) -> usize {
        self.provider
            .active_sessions()
            .unwrap_or(self.provider_sessions.len())
    }

    fn start_provider_session(
        &mut self,
        session_id: SnapshotSessionId,
        peer: &PeerId,
    ) -> Result<(), String> {
        if self.provider_sessions.contains(&session_id) {
            return Ok(());
        }

        self.provider
            .start_session(session_id, peer)
            .map_err(|err| err.to_string())?;
        self.provider_sessions.insert(session_id);
        Ok(())
    }

    fn finish_provider_session(&mut self, session_id: SnapshotSessionId) {
        if self.provider_sessions.remove(&session_id) {
            if let Err(err) = self.provider.finish_session(session_id) {
                debug!(
                    target: "telemetry.snapshots",
                    session = %session_id,
                    error = %err,
                    "snapshot_provider_finish_failed"
                );
            }
        }
    }

    fn send_outbound_request(
        &mut self,
        peer: &PeerId,
        session_id: SnapshotSessionId,
        request: SnapshotsRequest,
        kind: SnapshotItemKind,
    ) -> RequestResponseId {
        let request_bytes = snapshot_message_size(&request);
        let request_id = self.inner.send_request(peer, request);
        self.track_outbound_request(session_id, kind, request_bytes, request_id);
        request_id
    }

    fn dispatch_pending_requests(
        &mut self,
        session_id: SnapshotSessionId,
        target: Option<(SnapshotItemKind, u64)>,
    ) -> Option<RequestResponseId> {
        let configured_limit = self.configured_concurrency_limit();
        let mut target_request_id = None;
        let mut dispatched = false;

        loop {
            let (peer, kind, request) = {
                let state = match self.sessions.get_mut(&session_id) {
                    Some(state) => state,
                    None => break,
                };

                if !state.has_capacity(configured_limit) {
                    break;
                }

                match state.pop_next_pending() {
                    Some((kind, request)) => (state.peer.clone(), kind, request),
                    None => break,
                }
            };

            let request_id = match kind {
                SnapshotItemKind::Chunk => self.send_outbound_request(
                    &peer,
                    session_id,
                    SnapshotsRequest::Chunk {
                        session_id,
                        chunk_index: request.index,
                    },
                    kind,
                ),
                SnapshotItemKind::LightClientUpdate => self.send_outbound_request(
                    &peer,
                    session_id,
                    SnapshotsRequest::LightClientUpdate {
                        session_id,
                        update_index: request.index,
                    },
                    kind,
                ),
                _ => continue,
            };

            if target.is_some_and(|(target_kind, target_index)| {
                target_kind == kind && target_index == request.index
            }) {
                target_request_id = Some(request_id);
            }

            self.record_request_update(session_id, kind, "dispatched");
            dispatched = true;
        }

        if dispatched {
            #[cfg(feature = "metrics")]
            self.update_stream_metrics();
        }

        target_request_id
    }

    fn send_response_with_metrics(
        &mut self,
        request_id: RequestResponseInboundId,
        channel: RequestResponseChannel<SnapshotsResponse>,
        response: SnapshotsResponse,
    ) -> bool {
        let response_kind = snapshot_response_kind(&response);
        let response_bytes = snapshot_message_size(&response);
        let sent = self.inner.send_response(channel, response).is_ok();
        if sent {
            self.request_metrics
                .record_inbound_response(request_id, response_kind, response_bytes);
        }
        sent
    }

    #[cfg(all(feature = "metrics", feature = "request-response"))]
    fn record_breaker_metrics(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.record_breaker(&self.provider.breaker_status());
        }
    }

    #[cfg(not(all(feature = "metrics", feature = "request-response")))]
    fn record_breaker_metrics(&self) {}

    fn negotiate_chunk_size(
        capabilities: SnapshotChunkCapabilities,
        requested_chunk_size: Option<u64>,
        requested_min_chunk_size: Option<u64>,
        requested_max_chunk_size: Option<u64>,
    ) -> Result<Option<u64>, String> {
        if let (Some(min), Some(max)) = (requested_min_chunk_size, requested_max_chunk_size) {
            if min > max {
                return Err(format!(
                    "requested chunk size bounds invalid: min {min} exceeds max {max}"
                ));
            }
        }
        if let (Some(min), Some(max)) = (capabilities.min_chunk_size, capabilities.max_chunk_size) {
            if min > max {
                return Err(format!(
                    "provider chunk size bounds invalid: min {min} exceeds max {max}"
                ));
            }
        }
        if let (Some(cap_min), Some(req_max)) =
            (capabilities.min_chunk_size, requested_max_chunk_size)
        {
            if req_max < cap_min {
                return Err(format!(
                    "requested max chunk size {req_max} below provider minimum {cap_min}"
                ));
            }
        }
        if let (Some(cap_max), Some(req_min)) =
            (capabilities.max_chunk_size, requested_min_chunk_size)
        {
            if req_min > cap_max {
                return Err(format!(
                    "requested min chunk size {req_min} above provider maximum {cap_max}"
                ));
            }
        }

        let negotiated_chunk_size = requested_chunk_size.or(capabilities.chunk_size);
        if let Some(size) = negotiated_chunk_size {
            if capabilities
                .min_chunk_size
                .map(|min| size < min)
                .unwrap_or(false)
                || capabilities
                    .max_chunk_size
                    .map(|max| size > max)
                    .unwrap_or(false)
                || requested_min_chunk_size
                    .map(|min| size < min)
                    .unwrap_or(false)
                || requested_max_chunk_size
                    .map(|max| size > max)
                    .unwrap_or(false)
            {
                return Err(format!("chunk size {size} out of negotiated bounds"));
            }
            return Ok(Some(size));
        }

        let lower_bound = [capabilities.min_chunk_size, requested_min_chunk_size]
            .into_iter()
            .flatten()
            .max();
        let upper_bound = [capabilities.max_chunk_size, requested_max_chunk_size]
            .into_iter()
            .flatten()
            .min();

        if let (Some(min), Some(max)) = (lower_bound, upper_bound) {
            if min > max {
                return Err(format!(
                    "chunk size bounds have no overlap: min {min} exceeds max {max}"
                ));
            }
        }

        Ok(None)
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
        if !entry.has_capacity(self.configured_concurrency_limit()) {
            return None;
        }
        if entry.peer != peer {
            entry.peer = peer.clone();
        }
        let requested_size = entry.negotiated_chunk_size();
        self.record_adaptive_chunk_size(requested_size);
        let (min_chunk_size, max_chunk_size) = entry.chunk_sizing.bounds();
        let request = SnapshotsRequest::Plan {
            session_id,
            chunk_size: Some(requested_size),
            min_chunk_size: Some(min_chunk_size as u64),
            max_chunk_size: Some(max_chunk_size as u64),
        };
        let request_id =
            self.send_outbound_request(&peer, session_id, request, SnapshotItemKind::Plan);
        self.record_request_update(session_id, SnapshotItemKind::Plan, "dispatched");
        Some(request_id)
    }

    /// Requests a chunk from the remote peer.
    pub fn request_chunk(
        &mut self,
        peer: PeerId,
        session_id: SnapshotSessionId,
        chunk_index: u64,
    ) -> Option<RequestResponseId> {
        if self
            .sessions
            .get(&session_id)
            .map(|entry| entry.peer != peer)
            .unwrap_or(true)
        {
            return None;
        }
        if let Some(entry) = self.sessions.get_mut(&session_id) {
            entry.enqueue(SnapshotItemKind::Chunk, chunk_index);
            self.record_request_update(session_id, SnapshotItemKind::Chunk, "enqueued");
        }

        self.dispatch_pending_requests(session_id, Some((SnapshotItemKind::Chunk, chunk_index)))
    }

    /// Requests a light client update from the remote peer.
    pub fn request_update(
        &mut self,
        peer: PeerId,
        session_id: SnapshotSessionId,
        update_index: u64,
    ) -> Option<RequestResponseId> {
        if self
            .sessions
            .get(&session_id)
            .map(|entry| entry.peer != peer)
            .unwrap_or(true)
        {
            return None;
        }
        if let Some(entry) = self.sessions.get_mut(&session_id) {
            entry.enqueue(SnapshotItemKind::LightClientUpdate, update_index);
            self.record_request_update(session_id, SnapshotItemKind::LightClientUpdate, "enqueued");
        }

        self.dispatch_pending_requests(
            session_id,
            Some((SnapshotItemKind::LightClientUpdate, update_index)),
        )
    }

    /// Requests the remote peer to resume a snapshot session from the stored indices.
    pub fn request_resume(
        &mut self,
        peer: PeerId,
        session_id: SnapshotSessionId,
        plan_id: String,
    ) -> Option<RequestResponseId> {
        let entry = self.sessions.get_mut(&session_id)?;
        if !entry.has_capacity(self.configured_concurrency_limit()) || entry.peer != peer {
            return None;
        }
        let requested_size = entry.negotiated_chunk_size();
        self.record_adaptive_chunk_size(requested_size);
        let (min_chunk_size, max_chunk_size) = entry.chunk_sizing.bounds();
        let request = SnapshotsRequest::Resume {
            session_id,
            plan_id,
            chunk_index: entry.next_chunk_index,
            update_index: entry.next_update_index,
            chunk_size: Some(requested_size),
            min_chunk_size: Some(min_chunk_size as u64),
            max_chunk_size: Some(max_chunk_size as u64),
        };
        let request_id =
            self.send_outbound_request(&peer, session_id, request, SnapshotItemKind::Resume);
        self.record_request_update(session_id, SnapshotItemKind::Resume, "dispatched");
        self.record_resume_attempt();
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
        let request_bytes = snapshot_message_size(&request);
        let request_id = self.inner.send_request(&peer, request);
        self.request_metrics
            .start_outbound(request_id, SnapshotItemKind::Error, request_bytes);
        self.requests
            .insert(request_id, (session_id, SnapshotItemKind::Error));
        #[cfg(feature = "metrics")]
        self.update_stream_metrics();
        self.record_request_update(session_id, SnapshotItemKind::Error, "dispatched");
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
                        SnapshotsRequest::Plan { session_id, .. }
                        | SnapshotsRequest::Chunk { session_id, .. }
                        | SnapshotsRequest::LightClientUpdate { session_id, .. }
                        | SnapshotsRequest::Resume { session_id, .. }
                        | SnapshotsRequest::Ack { session_id, .. }
                        | SnapshotsRequest::Error { session_id, .. } => *session_id,
                    };
                    let request_kind = snapshot_request_kind(&request);
                    let request_bytes = snapshot_message_size(&request);
                    self.request_metrics
                        .start_inbound(request_id, request_kind, request_bytes);
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
                    let response_kind = snapshot_response_kind(&response);
                    let response_bytes = snapshot_message_size(&response);
                    if let Some((session_id, kind)) = self.requests.remove(&request_id) {
                        self.finish_outbound_request(session_id, kind);
                        let timing = self.request_metrics.finish_outbound(
                            request_id,
                            response_kind,
                            response_bytes,
                        );
                        self.handle_response(peer, session_id, response, timing);
                        self.dispatch_pending_requests(session_id, None);
                        self.record_request_update(session_id, kind, "completed");
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
                    self.finish_outbound_request(session_id, kind);
                    self.request_metrics.fail_outbound(request_id);
                    self.record_failure("outbound", kind);
                    if matches!(kind, SnapshotItemKind::Resume) {
                        self.record_resume_failure();
                    }
                    self.pending_events.push_back(SnapshotsEvent::Error {
                        peer,
                        session_id,
                        error: SnapshotProtocolError::Outbound { kind, error },
                    });
                    self.dispatch_pending_requests(session_id, None);
                    self.record_request_update(session_id, kind, "failed");
                }
            }
            RequestResponseEvent::InboundFailure { request_id, .. } => {
                #[cfg(feature = "metrics")]
                self.clear_response_timer(request_id);
                self.request_metrics.fail_inbound(request_id);
            }
            RequestResponseEvent::ResponseSent { request_id, .. } => {
                #[cfg(feature = "metrics")]
                self.record_response_sent(request_id);
                self.request_metrics.finish_inbound(request_id);
            }
        }
    }

    fn handle_inbound_request(
        &mut self,
        peer: PeerId,
        request_id: RequestResponseInboundId,
        request: SnapshotsRequest,
        channel: RequestResponseChannel<SnapshotsResponse>,
    ) {
        let session_id = match &request {
            SnapshotsRequest::Plan { session_id, .. }
            | SnapshotsRequest::Chunk { session_id, .. }
            | SnapshotsRequest::LightClientUpdate { session_id, .. }
            | SnapshotsRequest::Resume { session_id, .. }
            | SnapshotsRequest::Ack { session_id, .. }
            | SnapshotsRequest::Error { session_id, .. } => *session_id,
        };

        let capabilities = self.provider.chunk_capabilities();
        self.record_breaker_metrics();

        let breaker_status = self.provider.breaker_status();
        if breaker_status.open {
            let suffix = breaker_status
                .last_error
                .as_deref()
                .map(|err| format!(": {err}"))
                .unwrap_or_default();
            let message = format!(
                "snapshot serving circuit open after {} failures{suffix}",
                breaker_status.consecutive_failures
            );
            let _ = self.send_response_with_metrics(
                request_id,
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
            self.record_breaker_metrics();
            return;
        }
        let is_new_session = !self.provider_sessions.contains(&session_id);
        if is_new_session {
            if let Some(limit) = self.config.max_inbound_sessions {
                let active_sessions = self.active_provider_sessions();
                if active_sessions >= limit {
                    let message = format!(
                        "snapshot provider saturated: {active_sessions} active sessions (limit {limit}); please retry later with backoff",
                    );
                    let _ = self.send_response_with_metrics(
                        request_id,
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
                    return;
                }
            }
        }
        let state = self
            .sessions
            .entry(session_id)
            .or_insert_with(|| SessionState::with_capabilities(peer.clone(), capabilities));
        state.capabilities = capabilities;
        if state.chunk_size.is_none() {
            state.chunk_size = capabilities.chunk_size;
            if let Some(size) = state.chunk_size {
                self.record_negotiated_chunk_size("provider", size);
            }
        }
        if state.peer != peer {
            state.peer = peer.clone();
        }

        if is_new_session {
            if let Err(err) = self.provider.open_session(session_id, &peer) {
                let message = err.to_string();
                let _ = self.send_response_with_metrics(
                    request_id,
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
                return;
            }

            if let Err(message) = self.start_provider_session(session_id, &peer) {
                let _ = self.send_response_with_metrics(
                    request_id,
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
                return;
            }
        }

        match request {
            SnapshotsRequest::Plan {
                session_id,
                chunk_size,
                min_chunk_size,
                max_chunk_size,
            } => {
                let negotiated_chunk_size = match Self::negotiate_chunk_size(
                    capabilities,
                    chunk_size,
                    min_chunk_size,
                    max_chunk_size,
                ) {
                    Ok(size) => size.or(state.chunk_size).or(capabilities.chunk_size),
                    Err(message) => {
                        let _ = self.send_response_with_metrics(
                            request_id,
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
                        self.finish_provider_session(session_id);
                        self.record_failure("outbound", SnapshotItemKind::Plan);
                        return;
                    }
                };
                state.chunk_size = negotiated_chunk_size;
                if let Some(size) = negotiated_chunk_size {
                    self.record_negotiated_chunk_size("provider", size);
                }

                match self.provider.fetch_plan(session_id) {
                    Ok(plan) => match serde_json::to_vec(&plan) {
                        Ok(plan) => {
                            self.record_bytes("outbound", SnapshotItemKind::Plan, plan.len());
                            if self.send_response_with_metrics(
                                request_id,
                                channel,
                                SnapshotsResponse::Plan {
                                    session_id,
                                    plan,
                                    chunk_size: negotiated_chunk_size,
                                    min_chunk_size: capabilities.min_chunk_size,
                                    max_chunk_size: capabilities.max_chunk_size,
                                    max_concurrent_requests: capabilities.max_concurrent_requests,
                                },
                            ) {
                                #[cfg(feature = "metrics")]
                                self.track_response(request_id, SnapshotItemKind::Plan);
                            }
                        }
                        Err(err) => {
                            let message = format!("encode plan: {err}");
                            let _ = self.send_response_with_metrics(
                                request_id,
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
                            self.finish_provider_session(session_id);
                            self.record_failure("outbound", SnapshotItemKind::Plan);
                        }
                    },
                    Err(err) => {
                        let message = err.to_string();
                        let _ = self.send_response_with_metrics(
                            request_id,
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
                        self.finish_provider_session(session_id);
                        self.record_failure("outbound", SnapshotItemKind::Plan);
                    }
                }
            }
            SnapshotsRequest::Chunk {
                session_id,
                chunk_index,
            } => match self.provider.fetch_chunk(session_id, chunk_index) {
                Ok(chunk) => match serde_json::to_vec(&chunk) {
                    Ok(chunk) => {
                        self.record_bytes("outbound", SnapshotItemKind::Chunk, chunk.len());
                        if self.send_response_with_metrics(
                            request_id,
                            channel,
                            SnapshotsResponse::Chunk {
                                session_id,
                                chunk_index,
                                chunk,
                            },
                        ) {
                            #[cfg(feature = "metrics")]
                            self.track_response(request_id, SnapshotItemKind::Chunk);
                        }
                    }
                    Err(err) => {
                        let message = format!("encode chunk: {err}");
                        let _ = self.send_response_with_metrics(
                            request_id,
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
                        self.finish_provider_session(session_id);
                        self.record_failure("outbound", SnapshotItemKind::Chunk);
                    }
                },
                Err(err) => {
                    let message = err.to_string();
                    let _ = self.send_response_with_metrics(
                        request_id,
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
                    self.finish_provider_session(session_id);
                    self.record_failure("outbound", SnapshotItemKind::Chunk);
                }
            },
            SnapshotsRequest::LightClientUpdate {
                session_id,
                update_index,
            } => match self.provider.fetch_update(session_id, update_index) {
                Ok(update) => match serde_json::to_vec(&update) {
                    Ok(update) => {
                        self.record_bytes(
                            "outbound",
                            SnapshotItemKind::LightClientUpdate,
                            update.len(),
                        );
                        if self.send_response_with_metrics(
                            request_id,
                            channel,
                            SnapshotsResponse::LightClientUpdate {
                                session_id,
                                update_index,
                                update,
                            },
                        ) {
                            #[cfg(feature = "metrics")]
                            self.track_response(request_id, SnapshotItemKind::LightClientUpdate);
                        }
                    }
                    Err(err) => {
                        let message = format!("encode update: {err}");
                        let _ = self.send_response_with_metrics(
                            request_id,
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
                        self.finish_provider_session(session_id);
                        self.record_failure("outbound", SnapshotItemKind::LightClientUpdate);
                    }
                },
                Err(err) => {
                    let message = err.to_string();
                    let _ = self.send_response_with_metrics(
                        request_id,
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
                    self.finish_provider_session(session_id);
                    self.record_failure("outbound", SnapshotItemKind::LightClientUpdate);
                }
            },
            SnapshotsRequest::Resume {
                session_id,
                plan_id,
                chunk_index,
                update_index,
                chunk_size,
                min_chunk_size,
                max_chunk_size,
            } => {
                let negotiated_chunk_size = match Self::negotiate_chunk_size(
                    capabilities,
                    chunk_size,
                    min_chunk_size,
                    max_chunk_size,
                ) {
                    Ok(size) => size.or(state.chunk_size).or(capabilities.chunk_size),
                    Err(message) => {
                        let _ = self.send_response_with_metrics(
                            request_id,
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
                        self.record_failure("outbound", SnapshotItemKind::Resume);
                        self.record_breaker_metrics();
                        self.finish_provider_session(session_id);
                        return;
                    }
                };
                state.chunk_size = negotiated_chunk_size;
                if let Some(size) = negotiated_chunk_size {
                    self.record_negotiated_chunk_size("provider", size);
                }

                match self.provider.resume_session(
                    session_id,
                    &plan_id,
                    chunk_index,
                    update_index,
                    negotiated_chunk_size,
                    capabilities.min_chunk_size,
                    capabilities.max_chunk_size,
                ) {
                    Ok(resume) => {
                        if self.send_response_with_metrics(
                            request_id,
                            channel,
                            SnapshotsResponse::Resume {
                                session_id,
                                chunk_index: resume.next_chunk_index,
                                update_index: resume.next_update_index,
                                chunk_size: negotiated_chunk_size,
                                min_chunk_size: capabilities.min_chunk_size,
                                max_chunk_size: capabilities.max_chunk_size,
                                max_concurrent_requests: capabilities.max_concurrent_requests,
                            },
                        ) {
                            #[cfg(feature = "metrics")]
                            self.track_response(request_id, SnapshotItemKind::Resume);
                        }
                    }
                    Err(err) => {
                        let message = err.to_string();
                        let _ = self.send_response_with_metrics(
                            request_id,
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
                        self.record_failure("outbound", SnapshotItemKind::Resume);
                        self.finish_provider_session(session_id);
                    }
                }
            }
            SnapshotsRequest::Ack {
                session_id,
                kind,
                index,
            } => match self.provider.acknowledge(session_id, kind, index) {
                Ok(()) => {
                    if self.send_response_with_metrics(
                        request_id,
                        channel,
                        SnapshotsResponse::Ack {
                            session_id,
                            kind,
                            index,
                        },
                    ) {
                        #[cfg(feature = "metrics")]
                        self.track_response(request_id, kind);
                    }
                }
                Err(err) => {
                    let message = err.to_string();
                    let _ = self.send_response_with_metrics(
                        request_id,
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
                    self.finish_provider_session(session_id);
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
                self.finish_provider_session(session_id);
                if self.send_response_with_metrics(
                    request_id,
                    channel,
                    SnapshotsResponse::Ack {
                        session_id,
                        kind: SnapshotItemKind::Error,
                        index: 0,
                    },
                ) {
                    #[cfg(feature = "metrics")]
                    self.track_response(request_id, SnapshotItemKind::Error);
                }
            }
        }

        self.record_breaker_metrics();
    }

    fn handle_response(
        &mut self,
        peer: PeerId,
        session_id: SnapshotSessionId,
        response: SnapshotsResponse,
        timing: Option<SnapshotRequestTiming>,
    ) {
        let kind = snapshot_response_kind(&response);
        match response {
            SnapshotsResponse::Plan {
                plan,
                chunk_size,
                min_chunk_size,
                max_chunk_size,
                max_concurrent_requests,
                ..
            } => match serde_json::from_slice(&plan) {
                Ok(plan) => {
                    self.record_bytes("inbound", SnapshotItemKind::Plan, plan.len());
                    let state = self
                        .sessions
                        .entry(session_id)
                        .or_insert_with(|| SessionState::new(peer.clone()));
                    state.update_capabilities(SnapshotChunkCapabilities {
                        chunk_size,
                        min_chunk_size,
                        max_chunk_size,
                        max_concurrent_requests,
                    });
                    state.set_plan_concurrency_limit(plan.max_concurrent_requests);
                    if let Some(size) = chunk_size {
                        self.record_negotiated_chunk_size("consumer", size);
                    }
                    state.next_chunk_index = 0;
                    state.next_update_index = 0;
                    state.mark_progress();
                    self.update_stream_metrics();
                    self.pending_events.push_back(SnapshotsEvent::Plan {
                        peer,
                        session_id,
                        plan,
                    });
                }
                Err(err) => {
                    self.record_failure("inbound", SnapshotItemKind::Plan);
                    self.pending_events.push_back(SnapshotsEvent::Error {
                        peer,
                        session_id,
                        error: SnapshotProtocolError::Remote(format!("decode plan: {err}")),
                    });
                }
            },
            SnapshotsResponse::Chunk {
                chunk_index, chunk, ..
            } => match serde_json::from_slice(&chunk) {
                Ok(chunk) => {
                    if let Some(state) = self.sessions.get_mut(&session_id) {
                        state.next_chunk_index = chunk_index.saturating_add(1);
                        if let Some(timing) = timing {
                            state.record_chunk_telemetry(
                                chunk.data.len(),
                                timing.started_at.elapsed(),
                            );
                        }
                        state.mark_progress();
                    }
                    self.record_bytes("inbound", SnapshotItemKind::Chunk, chunk.len());
                    self.update_stream_metrics();
                    self.pending_events.push_back(SnapshotsEvent::Chunk {
                        peer,
                        session_id,
                        chunk_index,
                        chunk,
                    });
                }
                Err(err) => {
                    self.record_failure("inbound", SnapshotItemKind::Chunk);
                    self.pending_events.push_back(SnapshotsEvent::Error {
                        peer,
                        session_id,
                        error: SnapshotProtocolError::Remote(format!("decode chunk: {err}")),
                    });
                }
            },
            SnapshotsResponse::LightClientUpdate {
                update_index,
                update,
                ..
            } => match serde_json::from_slice(&update) {
                Ok(update) => {
                    if let Some(state) = self.sessions.get_mut(&session_id) {
                        state.next_update_index = update_index.saturating_add(1);
                        state.mark_progress();
                    }
                    self.record_bytes("inbound", SnapshotItemKind::LightClientUpdate, update.len());
                    self.update_stream_metrics();
                    self.pending_events
                        .push_back(SnapshotsEvent::LightClientUpdate {
                            peer,
                            session_id,
                            update_index,
                            update,
                        });
                }
                Err(err) => {
                    self.record_failure("inbound", SnapshotItemKind::LightClientUpdate);
                    self.pending_events.push_back(SnapshotsEvent::Error {
                        peer,
                        session_id,
                        error: SnapshotProtocolError::Remote(format!("decode update: {err}")),
                    });
                }
            },
            SnapshotsResponse::Resume {
                chunk_index,
                update_index,
                chunk_size,
                min_chunk_size,
                max_chunk_size,
                max_concurrent_requests,
                ..
            } => {
                if let Some(state) = self.sessions.get_mut(&session_id) {
                    state.update_capabilities(SnapshotChunkCapabilities {
                        chunk_size,
                        min_chunk_size,
                        max_chunk_size,
                        max_concurrent_requests,
                    });
                    state.set_plan_concurrency_limit(max_concurrent_requests);
                    if let Some(size) = chunk_size {
                        self.record_negotiated_chunk_size("consumer", size);
                    }
                    state.next_chunk_index = chunk_index;
                    state.next_update_index = update_index;
                    state.mark_progress();
                }
                self.update_stream_metrics();
                self.record_resume_success();
                self.pending_events.push_back(SnapshotsEvent::Resume {
                    peer,
                    session_id,
                    chunk_index,
                    update_index,
                });
            }
            SnapshotsResponse::Ack { kind, index, .. } => {
                if let Some(state) = self.sessions.get_mut(&session_id) {
                    state.mark_progress();
                }
                self.update_stream_metrics();
                self.pending_events.push_back(SnapshotsEvent::Ack {
                    peer,
                    session_id,
                    kind,
                    index,
                });
            }
            SnapshotsResponse::Error { message, .. } => {
                if matches!(
                    timing.as_ref().map(|timing| timing.request_kind),
                    Some(SnapshotItemKind::Resume)
                ) {
                    self.record_resume_failure();
                }
                self.pending_events.push_back(SnapshotsEvent::Error {
                    peer,
                    session_id,
                    error: SnapshotProtocolError::Remote(message),
                });
            }
        }
        if matches!(kind, SnapshotItemKind::Ack | SnapshotItemKind::Error) {
            self.finish_provider_session(session_id);
            self.sessions.remove(&session_id);
            self.update_stream_metrics();
        }
    }

    #[cfg(feature = "metrics")]
    fn record_resume_attempt(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.record_resume("attempt");
        }
    }

    #[cfg(not(feature = "metrics"))]
    fn record_resume_attempt(&self) {}

    #[cfg(feature = "metrics")]
    fn record_resume_success(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.record_resume("success");
        }
    }

    #[cfg(not(feature = "metrics"))]
    fn record_resume_success(&self) {}

    #[cfg(feature = "metrics")]
    fn record_resume_failure(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.record_resume("failure");
        }
    }

    #[cfg(not(feature = "metrics"))]
    fn record_resume_failure(&self) {}
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

    fn on_swarm_event(&mut self, event: FromSwarm<'_>) {
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
        self.update_stream_metrics();
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

#[cfg(all(test, feature = "request-response"))]
mod tests {
    use std::thread::sleep;
    use std::time::Duration;

    use futures::{channel::oneshot, executor};
    use prometheus_client::encoding::text::encode;
    use prometheus_client::registry::Registry;

    use super::*;

    fn inbound_request_id(id: u64) -> RequestResponseInboundId {
        // `InboundRequestId` does not expose a public constructor; this is only used in tests.
        unsafe { std::mem::transmute(id) }
    }

    fn outbound_request_id(id: u64) -> RequestResponseId {
        // `RequestResponseId` does not expose a public constructor; this is only used in tests.
        unsafe { std::mem::transmute(id) }
    }

    fn metric_value(metrics: &str, name: &str) -> Option<f64> {
        metrics.lines().find_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                return None;
            }
            if trimmed.starts_with(name) {
                trimmed
                    .split_whitespace()
                    .nth(1)
                    .and_then(|value| value.parse::<f64>().ok())
            } else {
                None
            }
        })
    }

    fn metric_value_with_labels(metrics: &str, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
        metrics.lines().find_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with('#') {
                return None;
            }

            if !trimmed.starts_with(name) {
                return None;
            }

            if labels.iter().all(|(key, value)| {
                let label = format!("{key}=\"{value}\"");
                trimmed.contains(&label)
            }) {
                trimmed
                    .split_whitespace()
                    .nth(1)
                    .and_then(|value| value.parse::<f64>().ok())
            } else {
                None
            }
        })
    }

    #[test]
    fn chunk_send_metrics_capture_backpressure() {
        let mut registry = Registry::default();
        let mut behaviour =
            SnapshotsBehaviour::new(NullSnapshotProvider::default(), Some(&mut registry));

        let request_id = inbound_request_id(7);
        behaviour.track_response(request_id, SnapshotItemKind::Chunk);
        assert_eq!(
            behaviour
                .metrics
                .as_ref()
                .unwrap()
                .chunk_send_queue_depth
                .get(),
            1
        );

        sleep(Duration::from_millis(25));
        behaviour.record_response_sent(request_id);

        let mut buffer = String::new();
        encode(&mut buffer, &registry).expect("encode metrics");

        assert_eq!(
            behaviour
                .metrics
                .as_ref()
                .unwrap()
                .chunk_send_queue_depth
                .get(),
            0
        );

        let latency_sum = metric_value(&buffer, "snapshot_chunk_send_latency_seconds_sum")
            .expect("latency sum recorded");
        assert!(
            latency_sum > 0.0,
            "latency histogram updated: {latency_sum}"
        );
    }

    #[test]
    fn request_response_telemetry_tracks_bytes_and_rtts() {
        let mut registry = Registry::default();
        let stream_metrics = SnapshotStreamMetrics::register(&mut registry);
        let mut request_metrics =
            SnapshotRequestMetrics::with_telemetry(Some(stream_metrics.telemetry()));

        let plan_request_bytes = 32_usize;
        let plan_response_bytes = 96_usize;
        let outbound_plan = outbound_request_id(11);
        request_metrics.start_outbound(outbound_plan, SnapshotItemKind::Plan, plan_request_bytes);
        sleep(Duration::from_millis(10));
        request_metrics.finish_outbound(outbound_plan, SnapshotItemKind::Plan, plan_response_bytes);
        stream_metrics.record_bytes("inbound", SnapshotItemKind::Plan, plan_response_bytes);

        let chunk_request_bytes = 64_usize;
        let chunk_response_bytes = 128_usize;
        let inbound_chunk = inbound_request_id(12);
        request_metrics.start_inbound(inbound_chunk, SnapshotItemKind::Chunk, chunk_request_bytes);
        request_metrics.record_inbound_response(
            inbound_chunk,
            SnapshotItemKind::Chunk,
            chunk_response_bytes,
        );
        sleep(Duration::from_millis(5));
        request_metrics.finish_inbound(inbound_chunk);
        stream_metrics.record_bytes("outbound", SnapshotItemKind::Chunk, chunk_response_bytes);

        let resume_request_bytes = 48_usize;
        let resume_response_bytes = 24_usize;
        let outbound_resume = outbound_request_id(13);
        request_metrics.start_outbound(
            outbound_resume,
            SnapshotItemKind::Resume,
            resume_request_bytes,
        );
        sleep(Duration::from_millis(8));
        request_metrics.finish_outbound(
            outbound_resume,
            SnapshotItemKind::Resume,
            resume_response_bytes,
        );
        stream_metrics.record_bytes("inbound", SnapshotItemKind::Resume, resume_response_bytes);

        let mut buffer = String::new();
        encode(&mut buffer, &registry).expect("encode metrics");

        // Bytes per message (request + response) recorded by the telemetry helper.
        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_message_bytes_total",
                &[
                    ("direction", "outbound"),
                    ("flow", "sent"),
                    ("kind", "plan")
                ],
            ),
            Some(plan_request_bytes as f64)
        );
        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_message_bytes_total",
                &[
                    ("direction", "outbound"),
                    ("flow", "received"),
                    ("kind", "plan")
                ],
            ),
            Some(plan_response_bytes as f64)
        );
        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_message_bytes_total",
                &[
                    ("direction", "inbound"),
                    ("flow", "received"),
                    ("kind", "chunk")
                ],
            ),
            Some(chunk_request_bytes as f64)
        );
        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_message_bytes_total",
                &[
                    ("direction", "inbound"),
                    ("flow", "sent"),
                    ("kind", "chunk")
                ],
            ),
            Some(chunk_response_bytes as f64)
        );
        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_message_bytes_total",
                &[
                    ("direction", "outbound"),
                    ("flow", "sent"),
                    ("kind", "resume")
                ],
            ),
            Some(resume_request_bytes as f64)
        );
        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_message_bytes_total",
                &[
                    ("direction", "outbound"),
                    ("flow", "received"),
                    ("kind", "resume")
                ],
            ),
            Some(resume_response_bytes as f64)
        );

        // Stream-level bytes transferred counters for inbound responses and outbound sends.
        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_bytes_sent_total",
                &[("direction", "outbound"), ("kind", "chunk")],
            ),
            Some(chunk_response_bytes as f64)
        );
        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_bytes_sent_total",
                &[("direction", "inbound"), ("kind", "plan")],
            ),
            Some(plan_response_bytes as f64)
        );
        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_bytes_sent_total",
                &[("direction", "inbound"), ("kind", "resume")],
            ),
            Some(resume_response_bytes as f64)
        );

        // Histograms capture non-zero RTTs and throughput for each observed response.
        for (direction, kind) in [
            ("outbound", "plan"),
            ("inbound", "chunk"),
            ("outbound", "resume"),
        ] {
            let rtt_sum = metric_value_with_labels(
                &buffer,
                "snapshot_request_rtt_seconds_sum",
                &[("direction", direction), ("kind", kind)],
            )
            .expect("rtt histogram has data");
            assert!(rtt_sum > 0.0, "rtt recorded for {direction} {kind}");

            let throughput_sum = metric_value_with_labels(
                &buffer,
                "snapshot_response_throughput_bytes_per_second_sum",
                &[("direction", direction), ("kind", kind)],
            )
            .expect("throughput histogram has data");
            assert!(
                throughput_sum > 0.0,
                "throughput recorded for {direction} {kind}"
            );
        }
    }

    #[test]
    fn resume_metrics_track_attempts_and_outcomes() {
        let mut registry = Registry::default();
        let provider = NullSnapshotProvider::default();
        let mut behaviour = SnapshotsBehaviour::with_config(
            provider,
            SnapshotsBehaviourConfig::default(),
            Some(&mut registry),
        );

        let peer = PeerId::random();
        let session = SnapshotSessionId::new(41);
        behaviour
            .sessions
            .insert(session, SessionState::new(peer.clone()));

        behaviour
            .request_resume(peer.clone(), session, "plan-a".to_string())
            .expect("resume attempt dispatched");

        behaviour.handle_response(
            peer.clone(),
            session,
            SnapshotsResponse::Resume {
                session_id: session,
                chunk_index: 2,
                update_index: 1,
                chunk_size: Some(8),
                min_chunk_size: Some(4),
                max_chunk_size: Some(16),
                max_concurrent_requests: Some(2),
            },
            None,
        );

        let failed_session = SnapshotSessionId::new(42);
        behaviour
            .sessions
            .insert(failed_session, SessionState::new(peer.clone()));
        behaviour
            .request_resume(peer.clone(), failed_session, "plan-b".to_string())
            .expect("second resume attempt dispatched");

        let timing = SnapshotRequestTiming::with_request(SnapshotItemKind::Resume, 0);
        behaviour.handle_response(
            peer,
            failed_session,
            SnapshotsResponse::Error {
                session_id: failed_session,
                message: "resume failed".into(),
            },
            Some(timing),
        );

        let mut buffer = String::new();
        encode(&mut buffer, &registry).expect("encode metrics");

        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_resume_events_total",
                &[("result", "attempt")],
            ),
            Some(2.0)
        );
        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_resume_events_total",
                &[("result", "success")],
            ),
            Some(1.0)
        );
        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_resume_events_total",
                &[("result", "failure")],
            ),
            Some(1.0)
        );
    }

    #[test]
    fn chunk_size_metrics_track_negotiated_and_adaptive_sizes() {
        let mut registry = Registry::default();
        let metrics = SnapshotStreamMetrics::register(&mut registry);

        metrics.record_negotiated_chunk_size("provider", 256);
        metrics.record_negotiated_chunk_size("consumer", 128);
        metrics.record_adaptive_chunk_size(192);

        let mut buffer = String::new();
        encode(&mut buffer, &registry).expect("encode metrics");

        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_negotiated_chunk_size_bytes",
                &[("role", "provider")],
            ),
            Some(256.0)
        );
        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_negotiated_chunk_size_bytes",
                &[("role", "consumer")],
            ),
            Some(128.0)
        );

        let negotiated_sum = metric_value(
            &buffer,
            "snapshot_negotiated_chunk_size_bytes_histogram_sum",
        )
        .expect("negotiated histogram updated");
        assert!(negotiated_sum >= 384.0);

        assert_eq!(
            metric_value(&buffer, "snapshot_adaptive_chunk_size_bytes"),
            Some(192.0)
        );

        let adaptive_sum =
            metric_value(&buffer, "snapshot_adaptive_chunk_size_bytes_histogram_sum")
                .expect("adaptive histogram updated");
        assert!(adaptive_sum >= 192.0);
    }

    #[test]
    fn breaker_metrics_reflect_status() {
        let mut registry = Registry::default();
        let metrics = SnapshotStreamMetrics::register(&mut registry);

        let status = SnapshotBreakerStatus {
            open: true,
            consecutive_failures: 4,
            last_error: Some("auth failed".to_string()),
        };

        metrics.record_breaker(&status);

        let mut buffer = String::new();
        encode(&mut buffer, &registry).expect("encode metrics");

        assert_eq!(
            metric_value(&buffer, "snapshot_provider_circuit_open"),
            Some(1.0)
        );
        assert_eq!(
            metric_value(&buffer, "snapshot_provider_consecutive_failures"),
            Some(4.0)
        );
    }

    #[test]
    fn stream_metrics_cover_queue_depths_and_backpressure() {
        let mut registry = Registry::default();
        let mut behaviour =
            SnapshotsBehaviour::new(NullSnapshotProvider::default(), Some(&mut registry));

        let session_id = SnapshotSessionId::new(42);
        let peer = PeerId::random();
        let state = behaviour
            .sessions
            .entry(session_id)
            .or_insert_with(|| SessionState::new(peer));

        state.enqueue(SnapshotItemKind::Chunk, 0);
        state.enqueue(SnapshotItemKind::LightClientUpdate, 0);
        state.record_outbound(SnapshotItemKind::Chunk);
        state.record_outbound(SnapshotItemKind::LightClientUpdate);

        sleep(Duration::from_millis(5));
        behaviour.update_stream_metrics();

        let mut buffer = String::new();
        encode(&mut buffer, &registry).expect("encode metrics");

        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_request_queue_depth",
                &[("kind", "chunk")],
            ),
            Some(1.0)
        );
        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_request_queue_depth",
                &[("kind", "light_client_update")],
            ),
            Some(1.0)
        );
        assert_eq!(
            metric_value_with_labels(&buffer, "snapshot_in_flight_requests", &[("kind", "chunk")],),
            Some(1.0)
        );
        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_in_flight_requests",
                &[("kind", "light_client_update")],
            ),
            Some(1.0)
        );
        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_concurrency_limit",
                &[("source", "configured")],
            ),
            Some(1.0)
        );
        assert_eq!(
            metric_value_with_labels(
                &buffer,
                "snapshot_concurrency_limit",
                &[("source", "effective")],
            ),
            Some(1.0)
        );

        let chunk_backpressure = metric_value_with_labels(
            &buffer,
            "snapshot_request_backpressure_seconds",
            &[("kind", "chunk")],
        )
        .expect("backpressure recorded");
        assert!(chunk_backpressure > 0.0);
    }

    #[test]
    fn provider_limit_denies_new_sessions_at_capacity() {
        let mut behaviour = SnapshotsBehaviour::with_config(
            NullSnapshotProvider::default(),
            SnapshotsBehaviourConfig {
                max_concurrent_requests: None,
                max_inbound_sessions: Some(1),
            },
            None,
        );

        let active_session = SnapshotSessionId::new(1);
        behaviour.provider_sessions.insert(active_session);

        let new_session = SnapshotSessionId::new(2);
        let request = SnapshotsRequest::Plan {
            session_id: new_session,
            chunk_size: None,
            min_chunk_size: None,
            max_chunk_size: None,
        };

        let peer = PeerId::random();
        let (tx, rx) = oneshot::channel();
        let channel: RequestResponseChannel<SnapshotsResponse> = unsafe { std::mem::transmute(tx) };

        behaviour.handle_inbound_request(peer.clone(), inbound_request_id(7), request, channel);

        let response = executor::block_on(async { rx.await.expect("response channel open") });
        match response {
            SnapshotsResponse::Error {
                session_id,
                message,
            } => {
                assert_eq!(session_id, new_session);
                assert!(message.contains("saturated"));
            }
            other => panic!("unexpected response: {:?}", other),
        }

        let event = behaviour
            .pending_events
            .pop_front()
            .expect("pending error event");
        match event {
            SnapshotsEvent::Error {
                session_id,
                error: SnapshotProtocolError::Provider(message),
                ..
            } => {
                assert_eq!(session_id, new_session);
                assert!(message.contains("saturated"));
            }
            other => panic!("unexpected event: {:?}", other),
        }

        assert_eq!(behaviour.provider_sessions.len(), 1);
        assert!(behaviour.provider_sessions.contains(&active_session));
    }
}
