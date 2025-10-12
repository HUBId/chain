//! # Algebraic Intermediate Representation (AIR)
//!
//! The AIR layer binds together the complete STARK proving pipeline described in
//! Kap. 2–4 and 7 of the accompanying design notes. This module serves as the
//! routing table: it introduces the data structures, naming, and sequencing
//! guarantees that all concrete AIR implementations must preserve.
//!
//! ## End-to-end pipeline
//!
//! ```text
//! Trace → Low-Degree Extension → Constraint Composition → Merkle Commitments
//!      → Transcript (Fiat–Shamir) → FRI Queries
//! ```
//!
//! * [`types`] (Kap. 2) describes the canonical containers exchanged between the
//!   prover and verifier and documents their deterministic byte encodings.
//! * [`trace`] (Kap. 2–3) provides read-only accessors over execution columns
//!   and time-steps; its iterator order fixes how witnesses feed the LDE stage.
//! * [`composition`] (Kap. 3–4) defines how transition and boundary constraints
//!   are lifted into composition polynomials before commitment.
//! * [`traits`] (Kap. 4) formalises the interfaces that concrete AIRs must
//!   implement so that transcripts and challenge derivations remain reproducible.
//! * [`example`] (Kap. 7) contains reference AIRs that demonstrate the
//!   determinism rules in practice.
//!
//! ## Trace schema
//!
//! | Segment | Columns | Description |
//! |---------|---------|-------------|
//! | `main`  | `columns::MAIN_WIDTH` | Execution registers sampled over all steps. |
//! | `aux`   | `columns::AUX_WIDTH`  | Auxiliary witnesses consumed by constraints. |
//! | `permutation` | `columns::PERM_WIDTH` | Optional permutation argument state. |
//! | `lookup` | `columns::LOOKUP_WIDTH` | Lookup table witnesses for Kap. 3. |
//!
//! The trace row iterator yields rows in strictly increasing step order and
//! column-major storage is prohibited. Each concrete AIR must document its
//! column labelling in Kap. 2 so that verifier reproduces the same layout.
//!
//! ## Public input schema
//!
//! | Field | Encoding | Purpose |
//! |-------|----------|---------|
//! | `context_tag` | 32-byte array | Names the execution instance (Kap. 2). |
//! | `trace_length` | `u32` LE | Fixes the evaluation domain used for the LDE. |
//! | `public_values` | `Vec<FieldElement>` | Registers exposed to the verifier. |
//! | `challenge_bound` | `u32` LE | Upper bound on transcript challenges (Kap. 4). |
//!
//! Serialisation rules are centralised in the [`types`] module and shared with
//! the transcript module to guarantee that both prover and verifier feed the
//! exact byte stream during the `PublicInputsDigest` absorption phase.
//!
//! ## Determinism guarantees
//!
//! * **Trace → LDE.** The LDE stage described in Kap. 3 consumes columns in the
//!   iterator order mandated by [`trace`]. Any deviation changes the coset
//!   enumeration and is therefore rejected by the verifier.
//! * **Composition.** [`composition`] derives transition challenges in the
//!   sequence emitted by the transcript (`TraceChallengeA`, then
//!   `CompChallengeA`). Composition polynomials must be generated in lockstep so
//!   their Merkle leaves match the verifier derivation.
//! * **Merkle.** Commitment ordering follows the stage boundary: trace roots are
//!   absorbed before composition roots. Branch encodings are fixed in Kap. 4.
//! * **Transcript and FRI.** The [`traits`] module enumerates every label and
//!   enforces the Fiat–Shamir challenge ordering: `TraceChallengeA` →
//!   `CompChallengeA` → `FriFoldChallenge(i)` → `QueryIndexStream`. Kap. 7 shows
//!   the resulting deterministic proof objects.
//!
//! Consumers that rely on this module can therefore reproduce identical Merkle
//! roots, transcripts, challenge streams, and FRI query sets whenever they replay
//! the same inputs and parameter set.

pub mod composition;
pub mod example;
pub mod trace;
pub mod traits;
pub mod types;
