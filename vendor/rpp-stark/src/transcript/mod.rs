//! Fiat–Shamir transcript orchestration for the STARK pipeline.
//!
//! The transcript follows a fixed sequence of phases that bind public inputs,
//! commitments and derived challenges.  Every label is an enum variant to ensure
//! compile-time domain separation.  The canonical order is summarised below:
//!
//! | Phase | Label | Source | Purpose |
//! |-------|-------|--------|---------|
//! | Init | [`TranscriptLabel::ParamsHash`] | [`StarkParams::params_hash`](crate::params::StarkParams::params_hash) | Binds parameter framing. |
//! | Init | [`TranscriptLabel::ProtocolTag`] | `StarkParams::transcript().protocol_tag` | Separates transcript families. |
//! | Init | [`TranscriptLabel::Seed`] | `StarkParams::transcript().seed` | Seeds the deterministic sponge. |
//! | Init | [`TranscriptLabel::ContextTag`] | [`TranscriptContext`] | Domain separation for prover components. |
//! | Public | [`TranscriptLabel::PublicInputsDigest`] | Canonical public input digest | Binds the instance public data. |
//! | TraceCommit | [`TranscriptLabel::TraceRoot`] | Trace commitment root | Pins the execution trace commitment. |
//! | TraceCommit | [`TranscriptLabel::TraceChallengeA`] | Challenge derived from transcript | First algebraic challenge after trace commitment. |
//! | CompCommit | [`TranscriptLabel::CompRoot`] | Constraint commitment root | Binds composition polynomial commitment. |
//! | CompCommit | [`TranscriptLabel::CompChallengeA`] | Transcript challenge | Folding seed for constraint composition. |
//! | FRI | [`TranscriptLabel::FriRoot(i)`](TranscriptLabel::FriRoot) | Layer `i` Merkle root | Commits each FRI layer in sequence. |
//! | FRI | [`TranscriptLabel::FriFoldChallenge(i)`](TranscriptLabel::FriFoldChallenge) | Transcript challenge | Folding randomness for layer `i`. |
//! | Queries | [`TranscriptLabel::QueryCount`] | `StarkParams::fri().queries` | Documents query multiplicity. |
//! | Queries | [`TranscriptLabel::QueryIndexStream`] | Transcript challenges | Index stream for trace/Fri openings. |
//! | Final | [`TranscriptLabel::ProofClose`] | Transcript challenge | Final binding digest stored in the proof. |
//!
//! Determinism guarantee: identical [`StarkParams`](crate::params::StarkParams) (including `params_hash` and
//! transcript seed), the same [`TranscriptContext`], identical label ordering
//! and payloads yield identical challenge sequences and state digests for both
//! prover and verifier.  Forking via [`Transcript::fork`] produces independent
//! yet deterministic transcripts that inherit the parent state digest.

mod core;
mod ser;
mod types;

pub use core::Transcript;
pub use types::{Felt, TranscriptContext, TranscriptError, TranscriptLabel, TranscriptPhase};
