use std::{collections::{BTreeMap, VecDeque}, fs, path::Path};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::wal::{FileWal, SequenceNumber, WalError};

/// 32-byte hash output used when sealing commits.
pub type Hash = [u8; 32];

/// WAL retention policy: keep the most recent block plus two historical
/// checkpoints.
const WAL_RETENTION_WINDOW: usize = 3;

/// Binary log record encoded into the WAL.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum LogRecord {
    Put { key: Vec<u8>, value: Vec<u8> },
    Delete { key: Vec<u8> },
    Commit { root: Hash },
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
    pending: Vec<LogRecord>,
    commit_boundaries: VecDeque<SequenceNumber>,
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
        };

        kv.replay()?
            .into_iter()
            .for_each(|(seq, record)| kv.apply_record(seq, record));
        Ok(kv)
    }

    fn replay(&self) -> Result<Vec<(SequenceNumber, LogRecord)>, KvError> {
        let records = self.wal.replay_from(0)?;
        let mut decoded = Vec::with_capacity(records.len());
        for (seq, raw) in records {
            let record = bincode::deserialize(&raw).map_err(|_| WalError::Corrupt)?;
            decoded.push((seq, record));
        }
        Ok(decoded)
    }

    fn apply_record(&mut self, sequence: SequenceNumber, record: LogRecord) {
        match record {
            LogRecord::Put { key, value } => {
                self.state.insert(key, value);
            }
            LogRecord::Delete { key } => {
                self.state.remove(&key);
            }
            LogRecord::Commit { .. } => {
                self.commit_boundaries.push_back(sequence);
                if self.commit_boundaries.len() > WAL_RETENTION_WINDOW {
                    self.commit_boundaries.pop_front();
                }
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

    fn record_put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.state.insert(key.clone(), value.clone());
        self.pending.push(LogRecord::Put { key, value });
    }

    fn record_delete(&mut self, key: &[u8]) {
        self.state.remove(key);
        self.pending.push(LogRecord::Delete { key: key.to_vec() });
    }

    fn seal_commit(&mut self, root: Hash) {
        self.pending.push(LogRecord::Commit { root });
    }

    fn retain_recent(&mut self) -> Result<(), KvError> {
        if self.commit_boundaries.len() < WAL_RETENTION_WINDOW {
            return Ok(());
        }
        if self.commit_boundaries.len() > WAL_RETENTION_WINDOW {
            let keep_index = self.commit_boundaries.len() - WAL_RETENTION_WINDOW;
            if let Some(&sequence) = self.commit_boundaries.get(keep_index) {
                self.wal.truncate(sequence)?;
            }
            while self.commit_boundaries.len() > WAL_RETENTION_WINDOW {
                self.commit_boundaries.pop_front();
            }
        }
        Ok(())
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
        self.seal_commit(root);

        for record in self.pending.drain(..) {
            let raw = bincode::serialize(&record).expect("serialize log record");
            let seq = self.wal.append(&raw)?;
            if matches!(record, LogRecord::Commit { .. }) {
                self.commit_boundaries.push_back(seq);
            }
        }

        self.wal.sync()?;
        self.retain_recent()?;
        Ok(root)
    }

    /// Iterate over the in-memory state for a specific prefix.
    pub fn scan_prefix<'a>(&'a self, prefix: &'a [u8]) -> impl Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a {
        let start = prefix.to_vec();
        self.state
            .range(start..)
            .take_while(move |(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.clone(), value.clone()))
    }
}

