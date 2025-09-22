/// Trait describing the pruning subsystem that reclaims historical data while
/// preserving proof material.
pub trait PruningLayer {
    /// Error emitted by the pruning logic.
    type Error;
    /// Marker type that identifies prune checkpoints (e.g. block heights or epochs).
    type Marker: Clone + Ord;

    /// Register that data up to `marker` has become eligible for pruning.
    fn mark_compactable(&mut self, marker: Self::Marker) -> Result<(), Self::Error>;

    /// Remove all compacted data whose marker is less than or equal to `marker`.
    fn prune_until(&mut self, marker: &Self::Marker) -> Result<usize, Self::Error>;

    /// Inspect the oldest marker that still requires pruning.
    fn oldest_pending(&self) -> Option<Self::Marker>;
}
