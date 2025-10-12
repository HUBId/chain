//! Utility helpers for the `rpp-stark` engine.
//! Includes deterministic randomness and serialization helpers.

pub mod parallel;
pub mod randomness;
pub mod serialization;

pub use randomness::{ChallengeStreamExt, TranscriptHook};
pub use serialization::ProofBytes;

#[cfg(feature = "parallel")]
pub use parallel::{parallelism_enabled, set_parallelism, ParallelismGuard};

#[cfg(not(feature = "parallel"))]
pub use parallel::ParallelismGuard;

pub use parallel::preferred_chunk_size;
