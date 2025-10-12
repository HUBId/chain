//! # Proof module overview
//!
//! ```text
//! proof
//! ├── types      — canonical data models such as [`types::Proof`]
//! ├── ser        — serialization helpers binding the stable byte layout
//! ├── envelope   — deterministic encoding/decoding for [`types::Proof`]
//! └── verifier   — verification contracts mirroring the specification
//! ```
//!
//! ## Versioning policy
//!
//! The [`types::Proof`] container records the canonical proof version and
//! layout declared by the specification. Minor revisions may extend telemetry or
//! auxiliary metadata, but the header ordering and byte tags remain stable for
//! a full major release. Any incompatible change to [`types::Proof`] must bump
//! the crate's major version and update the documented constants exported by the
//! `types` module.
//!
//! ## Compatibility guarantees
//!
//! Proof builders and verifiers are expected to treat the structure described by
//! [`types::Proof`] as authoritative. New fields are appended in a
//! backward-compatible manner and always guarded by explicit length prefixes.
//! Consumers can therefore safely decode envelopes emitted by older minor
//! releases while rejecting payloads that advertise an unsupported `version`.

pub mod envelope;
pub mod params;
pub mod ser;
pub mod types;
pub mod verifier;

pub(crate) mod aggregation;
pub(crate) mod api;
pub mod prover;
pub mod public_inputs;
pub mod transcript;

pub use public_inputs::ProofKind;
pub use types::{
    CompositionBinding, FriHandle, Openings, OpeningsDescriptor, Proof, ProofHandles, Telemetry,
    TelemetryOption, VerifyError, VerifyReport,
};
pub use verifier::verify;
