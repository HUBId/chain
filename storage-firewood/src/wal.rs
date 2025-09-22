use std::iter::Iterator;

/// Abstraction over the write-ahead log used to guarantee durability and ordering.
pub trait WriteAheadLog {
    /// Error type emitted by the WAL implementation.
    type Error;

    /// Logical sequence identifier that monotonically increases with every append.
    type SequenceNumber: Copy + Ord;

    /// Append a raw record to the log, returning the assigned sequence number.
    fn append(&mut self, record: &[u8]) -> Result<Self::SequenceNumber, Self::Error>;

    /// Force buffered log data to be persisted.
    fn sync(&mut self) -> Result<(), Self::Error>;

    /// Replay the log starting at `sequence`, yielding each record payload in order.
    fn replay_from(
        &self,
        sequence: Self::SequenceNumber,
    ) -> Result<Box<dyn Iterator<Item = Vec<u8>> + '_>, Self::Error>;

    /// Discard all log entries with sequence numbers strictly greater than `sequence`.
    fn truncate(&mut self, sequence: Self::SequenceNumber) -> Result<(), Self::Error>;
}
