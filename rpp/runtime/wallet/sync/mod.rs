use sha2::{Digest, Sha256};
use std::fmt;

/// Deterministic representation of a synchronization checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncCheckpoint {
    pub height: u64,
    pub hash: [u8; 32],
}

impl fmt::Display for SyncCheckpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "height={} hash=0x{}",
            self.height,
            hex::encode(self.hash)
        )
    }
}

/// Trait representing an object capable of producing synchronization checkpoints.
pub trait SyncProvider: Send + Sync {
    /// Returns the latest checkpoint if one is available.
    fn latest_checkpoint(&self) -> Option<SyncCheckpoint>;
}

/// A deterministic sync provider used for tests and lightweight runtimes.
#[derive(Clone, Debug)]
pub struct DeterministicSync {
    namespace: String,
    height: u64,
}

impl DeterministicSync {
    /// Constructs a deterministic provider scoped to a namespace.
    pub fn new(namespace: impl Into<String>) -> Self {
        Self {
            namespace: namespace.into(),
            height: 0,
        }
    }

    /// Overrides the checkpoint height returned by the provider.
    pub fn with_height(mut self, height: u64) -> Self {
        self.height = height;
        self
    }

    fn compute_checkpoint(&self) -> SyncCheckpoint {
        let mut hasher = Sha256::new();
        hasher.update(self.namespace.as_bytes());
        hasher.update(self.height.to_be_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        SyncCheckpoint {
            height: self.height,
            hash,
        }
    }
}

impl SyncProvider for DeterministicSync {
    fn latest_checkpoint(&self) -> Option<SyncCheckpoint> {
        Some(self.compute_checkpoint())
    }
}
