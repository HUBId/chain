use std::fmt;

/// Identifier associated with a snapshot session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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

/// Trait describing a provider that can service snapshot data requests.
pub trait SnapshotProvider: Send + Sync + 'static {}

/// Placeholder behaviour managing snapshot-related networking logic.
pub struct SnapshotsBehaviour<P: SnapshotProvider> {
    provider: P,
}

impl<P: SnapshotProvider> SnapshotsBehaviour<P> {
    /// Creates a new `SnapshotsBehaviour` for the given provider.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    /// Returns a reference to the wrapped provider instance.
    pub fn provider(&self) -> &P {
        &self.provider
    }
}
