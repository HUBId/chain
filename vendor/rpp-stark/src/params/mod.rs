#![forbid(unsafe_code)]

//! Canonical parameter registry for the STARK pipeline.
//!
//! This module defines [`StarkParams`] as the single source of truth for every
//! security and performance relevant parameter in the proving stack.  The
//! structure is intentionally explicit and designed to be serialised into a
//! deterministic byte layout that is shared between the prover, verifier and
//! tooling such as auditors or snapshot tests.
//!
//! # Overview
//!
//! The parameter space is split into themed sub-structures and enums.  The
//! following table summarises the high level groupings:
//!
//! | Group | Description |
//! |-------|-------------|
//! | Field & Hash | Selection of the prime field and hash function family used throughout the pipeline. |
//! | LDE & FRI | Low Degree Extension and Fast Reed–Solomon IOP knobs governing blowup factors and folding strategies. |
//! | Merkle & Transcript | Commitment encoding rules and Fiat–Shamir transcript framing. |
//! | Proof & Security | Envelope size limits and overall soundness budgeting. |
//!
//! All validation logic lives in the internal `validate` module, canonical
//! serialisation lives in the `ser` module, and the stable digest computation is
//! exposed via
//! [`StarkParams::params_hash`].  Consumers are expected to use the
//! [`StarkParamsBuilder`] helper which offers safe defaults and pre-defined
//! [`BuiltinProfile`] presets.
//!
//! # Invariants
//!
//! * The canonical serialisation is strictly ordered as documented in the `ser`
//!   module and is stable across Rust versions.
//! * [`StarkParams::params_hash`] commits to this serialisation and therefore
//!   uniquely identifies compatible parameter sets.
//! * [`StarkParams::is_compatible_with`] only allows variations on
//!   non-critical fields, permitting for example different proof size budgets
//!   while still sharing the same security assumptions.
//!
//! # Examples
//!
//! While the module intentionally avoids executable examples to keep the
//! specification deterministic, the tests and snapshot fixtures demonstrate how
//! `BuiltinProfile::PROFILE_X8` and `BuiltinProfile::PROFILE_HISEC_X16` expand
//! into complete parameter sets.

mod builder;
mod hash;
mod ser;
mod stark_params;
mod types;
mod validate;

pub use crate::ser::{SerError, SerKind};
pub use builder::{BuiltinProfile, StarkParamsBuilder};
pub use hash::params_hash;
pub use ser::{deserialize_params, serialize_params};
pub use stark_params::StarkParams;
pub use types::{
    ChallengeBounds, Endianness, FieldKind, FriFolding, FriParams, HashFamily, HashKind, LdeOrder,
    LdeParams, MerkleArity, MerkleParams, ProofParams, SecurityBudget, TranscriptParams,
};
pub use validate::{ParamsError, ValidationReport};
