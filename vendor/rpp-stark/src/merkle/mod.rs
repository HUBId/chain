//! Canonical Merkle commitment layer for `rpp-stark`.
//!
//! The module fixes the following protocol knobs:
//!
//! * **Arity:** Binary (`2`) and quaternary (`4`) trees are supported.  Missing
//!   children on the rightmost edge are deterministically duplicated from the
//!   last present child (Rightmost-Child Duplication – RMD).
//! * **Leaf layout:** leaves are encoded as the concatenation of `leaf_width`
//!   field elements in little-endian byte order.  The order is always
//!   row-major.  No length prefix or index tag is added.
//! * **Domain separation:** every hash invocation receives the `domain_sep`
//!   parameter from [`StarkParams`](crate::params::StarkParams), preceded by a one byte node tag (`0x00`
//!   for leaves, `0x01` for internal nodes).
//! * **Hash family:** the hashing backend is selected through
//!   [`StarkParams::hash`](crate::params::StarkParams::hash).  The [`MerkleHasher`] trait abstracts the concrete
//!   implementation to keep the commitment layer family-neutral.
//!
//! The public API re-exports the most relevant types for convenience.

mod deterministic;
mod proof;
mod ser;
pub mod traits;
mod tree;
mod types;

pub use proof::{verify_proof, MerkleProof, ProofBuilder};
pub use ser::{decode_commit_aux, decode_proof, encode_commit_aux, encode_proof};
pub use traits::{MerkleCommit, MerkleHasher};
pub use tree::{CommitAux, MerkleTree};
pub use types::{Digest, EndianEncoding, Leaf, MerkleArityExt, MerkleError, ProofNode, SerKind};

pub use deterministic::DeterministicMerkleHasher;
pub use types::{Node, TreeDepth};
