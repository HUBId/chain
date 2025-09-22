/// Canonical representation of the state root hash produced after every commit.
pub type StateRoot = Vec<u8>;

/// Read-only view over a committed state snapshot.
pub trait StateReader {
    /// Error type returned by reader implementations.
    type Error;

    /// Fetch a raw value for the provided `schema` and `key` combination.
    fn get_raw(&self, schema: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Return the root hash for this snapshot.
    fn root_hash(&self) -> StateRoot;
}

/// Mutable transaction that stages updates prior to a commit.
pub trait StateTransaction {
    /// Error type surfaced during transaction processing.
    type Error;

    /// Insert or update a value in the given `schema`.
    fn put_raw(&mut self, schema: &str, key: Vec<u8>, value: Vec<u8>) -> Result<(), Self::Error>;

    /// Remove an entry from the given `schema`.
    fn delete_raw(&mut self, schema: &str, key: &[u8]) -> Result<(), Self::Error>;

    /// Finalize the transaction and return the resulting state root.
    fn commit(self) -> Result<StateRoot, Self::Error>;

    /// Abort the transaction, discarding staged changes.
    fn rollback(self) -> Result<(), Self::Error>;
}

/// High-level state manager that coordinates snapshot access and transactional updates.
pub trait StateManager {
    /// Unified error type returned by the manager and its associated components.
    type Error;
    /// Transaction type created by `begin_transaction`.
    type Transaction: StateTransaction<Error = Self::Error>;
    /// Reader type returned when accessing committed state.
    type Reader: StateReader<Error = Self::Error>;

    /// Acquire a read-only handle to the latest committed state.
    fn reader(&self) -> Result<Self::Reader, Self::Error>;

    /// Start a new state transaction.
    fn begin_transaction(&self) -> Result<Self::Transaction, Self::Error>;
}
