//! Firewood's append-only key/value store backed by a write-ahead log.
//!
//! Transactions are encoded as a `Begin` marker, the staged `Put`/`Delete` mutations, and a
//! terminal `Commit` record carrying the resulting state root. During recovery the mutations are
//! buffered until the matching `Commit` marker is observed so partially written transactions are
//! discarded instead of being materialised.

use std::{
    collections::{BTreeMap, VecDeque},
    env, fs,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::wal::{FileWal, SequenceNumber, WalError};

/// 32-byte hash output used when sealing commits.
pub type Hash = [u8; 32];

/// WAL retention policy: keep the most recent block plus two historical
/// checkpoints.
const WAL_RETENTION_WINDOW: usize = 3;

const WAL_TRANSACTION_METRIC: &str = "firewood.wal.transactions";
const WAL_TRANSACTION_RESULT_LABEL: &str = "result";
const WAL_TRANSACTION_COMMITTED: &str = "committed";
const WAL_TRANSACTION_ROLLED_BACK: &str = "rolled_back";
const COMMIT_PAUSE_ENV: &str = "FIREWOOD_KV_COMMIT_PAUSE_PATH";

/// Representation of a staged mutation recorded in the WAL.
#[derive(Debug, Clone)]
enum Mutation {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
}

impl Mutation {
    fn apply(self, state: &mut BTreeMap<Vec<u8>, Vec<u8>>) {
        match self {
            Mutation::Put { key, value } => {
                state.insert(key, value);
            }
            Mutation::Delete { key } => {
                state.remove(&key);
            }
        }
    }

    fn into_record(self) -> LogRecord {
        match self {
            Mutation::Put { key, value } => LogRecord::Put { key, value },
            Mutation::Delete { key } => LogRecord::Delete { key },
        }
    }
}

#[derive(Debug, Default)]
struct InflightTransaction {
    begin_seq: SequenceNumber,
    mutations: Vec<Mutation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CommitBoundary {
    begin: SequenceNumber,
    commit: SequenceNumber,
}

/// Binary log record encoded into the WAL.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum LogRecord {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
    Commit { root: Hash },
    Begin { id: u64 },
}

/// Error type reported by the Firewood KV engine.
#[derive(Debug, Error)]
pub enum KvError {
    /// Failure caused by the underlying WAL subsystem.
    #[error("wal error: {0}")]
    Wal(#[from] WalError),
    /// Persistence layer failure.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Attempted to commit without any staged mutations.
    #[error("no pending mutations to commit")]
    EmptyCommit,
}

/// Firewood key-value engine that stores all data inside a single append-only
/// log. The engine keeps an in-memory map for hot data while the log provides a
/// durable history that can be replayed to recover the latest state.
#[derive(Debug)]
pub struct FirewoodKv {
    wal: FileWal,
    state: BTreeMap<Vec<u8>, Vec<u8>>,
    pending: Vec<Mutation>,
    commit_boundaries: VecDeque<CommitBoundary>,
    pending_wal_gc: Option<CommitBoundary>,
    replay_inflight: Option<InflightTransaction>,
    next_tx_id: u64,
    directory: PathBuf,
}

impl FirewoodKv {
    /// Open (or create) a new Firewood key-value store located at `directory`.
    pub fn open<P: AsRef<Path>>(directory: P) -> Result<Self, KvError> {
        let directory = directory.as_ref();
        fs::create_dir_all(directory)?;
        let wal = FileWal::open(directory)?;

        let mut kv = FirewoodKv {
            wal,
            state: BTreeMap::new(),
            pending: Vec::new(),
            commit_boundaries: VecDeque::new(),
            pending_wal_gc: None,
            replay_inflight: None,
            next_tx_id: 0,
            directory: directory.to_path_buf(),
        };

        let (records, rolled_back) = kv.replay()?;
        for (seq, record) in records {
            kv.apply_record(seq, record);
        }
        if rolled_back > 0 {
            metrics::counter!(
                WAL_TRANSACTION_METRIC,
                WAL_TRANSACTION_RESULT_LABEL => WAL_TRANSACTION_ROLLED_BACK
            )
            .increment(rolled_back as u64);
        }
        Ok(kv)
    }

    pub fn base_dir(&self) -> &Path {
        &self.directory
    }

    fn replay(&self) -> Result<(Vec<(SequenceNumber, LogRecord)>, u64), KvError> {
        let records = self.wal.replay_from(0)?;
        let mut decoded = Vec::with_capacity(records.len());
        let mut last_commit_index = None;

        for (index, (seq, raw)) in records.into_iter().enumerate() {
            let record = bincode::deserialize(&raw).map_err(|_| WalError::Corrupt)?;
            if matches!(record, LogRecord::Commit { .. }) {
                last_commit_index = Some(index);
            }
            decoded.push((seq, record));
        }

        let rolled_back_transactions = if let Some(index) = last_commit_index {
            let tail = decoded.split_off(index + 1);
            tail.iter()
                .filter(|(_, record)| matches!(record, LogRecord::Begin { .. }))
                .count() as u64
        } else {
            let count = decoded
                .iter()
                .filter(|(_, record)| matches!(record, LogRecord::Begin { .. }))
                .count() as u64;
            decoded.clear();
            count
        };

        Ok((decoded, rolled_back_transactions))
    }

    fn apply_record(&mut self, sequence: SequenceNumber, record: LogRecord) {
        match record {
            LogRecord::Put { key, value } => {
                if let Some(inflight) = &mut self.replay_inflight {
                    inflight.mutations.push(Mutation::Put { key, value });
                } else {
                    Mutation::Put { key, value }.apply(&mut self.state);
                }
            }
            LogRecord::Delete { key } => {
                if let Some(inflight) = &mut self.replay_inflight {
                    inflight.mutations.push(Mutation::Delete { key });
                } else {
                    Mutation::Delete { key }.apply(&mut self.state);
                }
            }
            LogRecord::Commit { root } => {
                let begin_seq = if let Some(inflight) = self.replay_inflight.take() {
                    for mutation in inflight.mutations {
                        mutation.apply(&mut self.state);
                    }
                    debug_assert_eq!(
                        self.hash_state(),
                        root,
                        "replayed state hash diverged from WAL commit"
                    );
                    inflight.begin_seq
                } else {
                    sequence
                };
                self.record_commit_boundary(sequence, begin_seq);
            }
            LogRecord::Begin { id } => {
                self.replay_inflight = Some(InflightTransaction {
                    begin_seq: sequence,
                    mutations: Vec::new(),
                });
                self.next_tx_id = self.next_tx_id.max(id + 1);
            }
        }
    }

    fn hash_state(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();
        for (key, value) in &self.state {
            hasher.update(&(key.len() as u32).to_le_bytes());
            hasher.update(key);
            hasher.update(&(value.len() as u32).to_le_bytes());
            hasher.update(value);
        }
        hasher.finalize().into()
    }

    /// Compute the hash of the in-memory state without mutating it.
    pub fn root_hash(&self) -> Hash {
        self.hash_state()
    }

    fn record_put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.state.insert(key.clone(), value.clone());
        self.pending.push(Mutation::Put { key, value });
    }

    fn record_delete(&mut self, key: &[u8]) {
        self.state.remove(key);
        self.pending.push(Mutation::Delete { key: key.to_vec() });
    }

    fn retain_recent(&mut self) -> Result<(), KvError> {
        if let Some(boundary) = self.pending_wal_gc {
            self.wal.truncate(boundary.begin)?;
            self.pending_wal_gc = None;
        }
        Ok(())
    }

    fn record_commit_boundary(
        &mut self,
        commit_sequence: SequenceNumber,
        begin_sequence: SequenceNumber,
    ) {
        let boundary = CommitBoundary {
            begin: begin_sequence,
            commit: commit_sequence,
        };
        self.commit_boundaries.push_back(boundary);
        if self.commit_boundaries.len() > WAL_RETENTION_WINDOW {
            self.commit_boundaries.pop_front();
            self.pending_wal_gc = self.commit_boundaries.front().copied();
        }
    }

    fn commit_pause_path() -> Option<PathBuf> {
        match env::var(COMMIT_PAUSE_ENV) {
            Ok(path) if !path.is_empty() => Some(PathBuf::from(path)),
            _ => None,
        }
    }

    /// Stage a put mutation.
    pub fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.record_put(key, value);
    }

    /// Fetch a value by key.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.state.get(key).cloned()
    }

    /// Stage a delete mutation.
    pub fn delete(&mut self, key: &[u8]) {
        self.record_delete(key);
    }

    /// Flush staged mutations to the WAL and return the resulting commit hash.
    pub fn commit(&mut self) -> Result<Hash, KvError> {
        if self.pending.is_empty() {
            return Err(KvError::EmptyCommit);
        }

        let root = self.hash_state();
        let tx_id = self.next_tx_id;
        self.next_tx_id = self.next_tx_id.wrapping_add(1);

        let mutations = self.pending.clone();

        let begin_record = LogRecord::Begin { id: tx_id };
        let begin_raw = bincode::serialize(&begin_record).expect("serialize begin record");
        let begin_seq = self.wal.append(&begin_raw)?;

        for mutation in &mutations {
            let record = mutation.clone().into_record();
            let raw = bincode::serialize(&record).expect("serialize log record");
            self.wal.append(&raw)?;
        }

        if let Some(pause_path) = Self::commit_pause_path() {
            let _ = fs::write(&pause_path, b"ready");
            while pause_path.exists() {
                thread::sleep(Duration::from_millis(50));
            }
        }

        let commit_record = LogRecord::Commit { root };
        let commit_raw = bincode::serialize(&commit_record).expect("serialize commit record");
        let commit_seq = self.wal.append(&commit_raw)?;
        self.record_commit_boundary(commit_seq, begin_seq);

        self.wal.sync()?;

        self.pending.clear();

        metrics::counter!(
            WAL_TRANSACTION_METRIC,
            WAL_TRANSACTION_RESULT_LABEL => WAL_TRANSACTION_COMMITTED
        )
        .increment(1);

        Ok(root)
    }

    /// Garbage-collect WAL segments that have fallen out of the retention window.
    ///
    /// This should be invoked after a durable checkpoint or pruning cycle has
    /// completed so only fully replayable commit ranges remain in the log.
    pub fn gc_wal(&mut self) -> Result<(), KvError> {
        self.retain_recent()
    }

    /// Iterate over the in-memory state for a specific prefix.
    pub fn scan_prefix<'a>(
        &'a self,
        prefix: &'a [u8],
    ) -> impl Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a {
        let start = prefix.to_vec();
        self.state
            .range(start..)
            .take_while(move |(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn wal_gc_truncates_only_full_commits() {
        let temp_dir = TempDir::new().expect("create wal gc temp dir");
        let data_dir = temp_dir.path().join("kv");

        let mut kv = FirewoodKv::open(&data_dir).expect("open kv for gc probe");
        kv.put(b"key-0".to_vec(), b"value-0".to_vec());
        kv.commit().expect("commit checkpoint baseline");
        let checkpoint_state = kv.state.clone();

        for index in 1..4 {
            kv.put(
                format!("key-{index}").into_bytes(),
                format!("value-{index}").into_bytes(),
            );
            kv.commit().expect("commit staged mutation");
        }

        assert!(
            kv.pending_wal_gc.is_some(),
            "expected pending wal gc after exceeding window",
        );
        let pre_gc = kv
            .wal
            .replay_from(0)
            .expect("replay wal before gc");

        kv.gc_wal().expect("run wal gc");

        let post_gc = kv
            .wal
            .replay_from(0)
            .expect("replay wal after gc");
        assert!(post_gc.len() < pre_gc.len(), "gc should drop stale wal prefix");
        let expected_start = kv
            .commit_boundaries
            .front()
            .expect("retain window boundary")
            .begin;
        assert_eq!(post_gc.first().map(|(seq, _)| *seq), Some(expected_start));

        drop(kv);

        let wal = FileWal::open(&data_dir).expect("open wal after gc");
        let mut reopened = FirewoodKv {
            wal,
            state: checkpoint_state,
            pending: Vec::new(),
            commit_boundaries: VecDeque::new(),
            pending_wal_gc: None,
            replay_inflight: None,
            next_tx_id: 0,
            directory: data_dir.clone(),
        };
        let (records, _) = reopened.replay().expect("replay truncated wal");
        for (sequence, record) in records {
            reopened.apply_record(sequence, record);
        }

        for retained in 0..4 {
            let key = format!("key-{retained}").into_bytes();
            let value = format!("value-{retained}").into_bytes();
            assert_eq!(
                reopened.get(&key),
                Some(value),
                "checkpoint + wal replay should retain committed keys",
            );
        }
    }

    #[test]
    fn wal_gc_noops_without_pending_window() {
        let temp_dir = TempDir::new().expect("create wal gc noop dir");
        let data_dir = temp_dir.path().join("kv");

        let mut kv = FirewoodKv::open(&data_dir).expect("open kv for noop gc");
        kv.put(b"only".to_vec(), b"value".to_vec());
        kv.commit().expect("commit single entry");

        let pre_gc_len = kv
            .wal
            .replay_from(0)
            .expect("replay wal before noop gc")
            .len();
        kv.gc_wal().expect("noop gc call should succeed");
        let post_gc_len = kv
            .wal
            .replay_from(0)
            .expect("replay wal after noop gc")
            .len();

        assert_eq!(
            pre_gc_len, post_gc_len,
            "noop gc must not truncate within retention window",
        );
        assert_eq!(kv.pending_wal_gc, None, "noop gc should not enqueue pending work");
    }
}
