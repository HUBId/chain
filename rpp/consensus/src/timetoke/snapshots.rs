use std::fmt;

use blake3::Hash;
use rpp_p2p::{PipelineError, SnapshotChunk, SnapshotChunkStream, SnapshotStore};
use serde::{Deserialize, Serialize};

/// Snapshot representation for Timetoke ledger state.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimetokeSnapshot {
    /// Hex-encoded Timetoke commitment expected by the ledger.
    pub timetoke_root: String,
    /// Ordered records that reconstruct the Timetoke ledger.
    pub records: Vec<TimetokeRecord>,
}

/// Canonical Timetoke ledger record mirrored from the blueprint schema.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimetokeRecord {
    pub identity: String,
    pub balance: u128,
    pub epoch_accrual: u64,
    pub decay_rate: f32,
    pub last_update: u64,
    pub last_sync: u64,
    pub last_decay: u64,
}

impl Default for TimetokeRecord {
    fn default() -> Self {
        Self {
            identity: String::new(),
            balance: 0,
            epoch_accrual: 0,
            decay_rate: 1.0,
            last_update: 0,
            last_sync: 0,
            last_decay: 0,
        }
    }
}

/// Handle describing a published snapshot inside the producer store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimetokeSnapshotHandle {
    /// Blake3 root of the encoded snapshot payload.
    pub root: Hash,
    /// Number of chunks emitted by the snapshot stream.
    pub total_chunks: u64,
    /// Number of records contained in the snapshot.
    pub record_count: usize,
    /// Hex encoded Timetoke commitment carried by the snapshot payload.
    pub timetoke_root: String,
}

/// Produces snapshot streams for Timetoke records and exposes the payload to the
/// libp2p snapshot protocol.
#[derive(Debug)]
pub struct TimetokeSnapshotProducer {
    store: SnapshotStore,
}

impl TimetokeSnapshotProducer {
    /// Creates a new producer backed by a snapshot store using the provided
    /// chunk size.
    pub fn new(chunk_size: usize) -> Self {
        Self {
            store: SnapshotStore::new(chunk_size.max(1)),
        }
    }

    /// Persists a snapshot payload and returns the associated handle.
    pub fn publish(
        &mut self,
        records: Vec<TimetokeRecord>,
        timetoke_root: [u8; 32],
    ) -> Result<TimetokeSnapshotHandle, TimetokeSnapshotError> {
        let snapshot = TimetokeSnapshot {
            timetoke_root: hex::encode(timetoke_root),
            records,
        };
        let payload = serde_json::to_vec(&snapshot)
            .map_err(|err| TimetokeSnapshotError::Encoding(err.to_string()))?;
        let root = self.store.insert(payload);
        let stream = self
            .store
            .stream(&root)
            .map_err(TimetokeSnapshotError::from)?;
        Ok(TimetokeSnapshotHandle {
            root,
            total_chunks: stream.total(),
            record_count: snapshot.records.len(),
            timetoke_root: snapshot.timetoke_root,
        })
    }

    /// Returns whether the store contains the referenced snapshot.
    pub fn has_snapshot(&self, root: &Hash) -> bool {
        self.store.has_snapshot(root)
    }

    /// Opens a chunk stream for the referenced snapshot.
    pub fn stream(&self, root: &Hash) -> Result<SnapshotChunkStream, TimetokeSnapshotError> {
        self.store.stream(root).map_err(TimetokeSnapshotError::from)
    }

    /// Fetches an individual chunk from the snapshot store.
    pub fn chunk(&self, root: &Hash, index: u64) -> Result<SnapshotChunk, TimetokeSnapshotError> {
        self.store
            .chunk(root, index)
            .map_err(TimetokeSnapshotError::from)
    }
}

/// Incrementally reconstructs a Timetoke snapshot from snapshot chunks.
#[derive(Debug)]
pub struct TimetokeSnapshotConsumer {
    expected_root: Hash,
    expected_total: Option<u64>,
    next_index: u64,
    finished: bool,
    buffer: Vec<u8>,
}

impl TimetokeSnapshotConsumer {
    /// Initialises a consumer expecting the provided snapshot root.
    pub fn new(expected_root: Hash) -> Self {
        Self {
            expected_root,
            expected_total: None,
            next_index: 0,
            finished: false,
            buffer: Vec::new(),
        }
    }

    /// Returns the expected snapshot root.
    pub fn expected_root(&self) -> Hash {
        self.expected_root
    }

    /// Returns the number of chunks processed so far.
    pub fn received_chunks(&self) -> u64 {
        self.next_index
    }

    /// Returns whether all chunks have been processed.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Applies the next chunk. The method returns `Ok(Some(snapshot))` once the
    /// payload has been fully reconstructed, or `Ok(None)` if more chunks are
    /// required.
    pub fn ingest_chunk(
        &mut self,
        chunk: SnapshotChunk,
    ) -> Result<Option<TimetokeSnapshot>, TimetokeSnapshotError> {
        if self.finished {
            return Err(TimetokeSnapshotError::UnexpectedChunk(chunk.index));
        }
        if chunk.root != self.expected_root {
            return Err(TimetokeSnapshotError::InvalidRoot {
                expected: self.expected_root.to_hex().to_string(),
                found: chunk.root.to_hex().to_string(),
            });
        }
        match self.expected_total {
            Some(total) => {
                if total != chunk.total {
                    return Err(TimetokeSnapshotError::MismatchedTotal {
                        expected: total,
                        found: chunk.total,
                    });
                }
            }
            None => {
                self.expected_total = Some(chunk.total);
            }
        }
        if chunk.index != self.next_index {
            return Err(TimetokeSnapshotError::OutOfOrderChunk {
                expected: self.next_index,
                found: chunk.index,
            });
        }
        self.next_index += 1;
        self.buffer.extend_from_slice(&chunk.data);
        let Some(total) = self.expected_total else {
            return Ok(None);
        };
        if self.next_index < total {
            return Ok(None);
        }
        let computed_root = blake3::hash(&self.buffer);
        if computed_root != self.expected_root {
            return Err(TimetokeSnapshotError::InvalidRoot {
                expected: self.expected_root.to_hex().to_string(),
                found: computed_root.to_hex().to_string(),
            });
        }
        let snapshot: TimetokeSnapshot = serde_json::from_slice(&self.buffer)
            .map_err(|err| TimetokeSnapshotError::Decoding(err.to_string()))?;
        self.finished = true;
        Ok(Some(snapshot))
    }
}

/// Errors emitted by snapshot production or reconstruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimetokeSnapshotError {
    /// Payload encoding failed during snapshot publication.
    Encoding(String),
    /// Payload decoding failed when reconstructing the snapshot.
    Decoding(String),
    /// The producer store reported an error.
    Pipeline(String),
    /// Chunks were ingested out of order.
    OutOfOrderChunk { expected: u64, found: u64 },
    /// The total chunk count was inconsistent across messages.
    MismatchedTotal { expected: u64, found: u64 },
    /// The chunk root or reconstructed payload did not match the advertised root.
    InvalidRoot { expected: String, found: String },
    /// Additional chunks were supplied after the stream completed.
    UnexpectedChunk(u64),
}

impl fmt::Display for TimetokeSnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimetokeSnapshotError::Encoding(err) => write!(f, "encode timetoke snapshot: {err}"),
            TimetokeSnapshotError::Decoding(err) => write!(f, "decode timetoke snapshot: {err}"),
            TimetokeSnapshotError::Pipeline(err) => write!(f, "snapshot store error: {err}"),
            TimetokeSnapshotError::OutOfOrderChunk { expected, found } => {
                write!(f, "received chunk {found} but expected index {expected}")
            }
            TimetokeSnapshotError::MismatchedTotal { expected, found } => {
                write!(
                    f,
                    "chunk total mismatch: expected {expected}, received {found}"
                )
            }
            TimetokeSnapshotError::InvalidRoot { expected, found } => {
                write!(
                    f,
                    "snapshot root mismatch: expected {expected}, found {found}"
                )
            }
            TimetokeSnapshotError::UnexpectedChunk(index) => {
                write!(f, "received unexpected chunk {index} after completion")
            }
        }
    }
}

impl std::error::Error for TimetokeSnapshotError {}

impl From<PipelineError> for TimetokeSnapshotError {
    fn from(err: PipelineError) -> Self {
        TimetokeSnapshotError::Pipeline(err.to_string())
    }
}
