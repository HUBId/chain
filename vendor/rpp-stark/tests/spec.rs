//! Test specification for the `rpp-stark` documentation crate.
//!
//! The following scenarios must be covered by downstream implementers:
//!
//! 1. Determinism: identical inputs (kind, public inputs, witness, config,
//!    contexts) must produce bit-identical `proof_bytes`.
//! 2. Parameter digest mismatch: modifying any byte in `ParamDigest` must
//!    surface the `ErrParamsHashMismatch` failure.
//! 3. Merkle sibling order: swapping siblings in a FRI path must return
//!    the `ErrMerkleVerifyFailed(FriPath)` failure.
//! 4. Query position bounds: queries outside the evaluation domain must be
//!    flagged as `ErrFriVerifyFailed(QueryOutOfRange)`.
//! 5. Proof size guard: exceeding `limits.max_proof_size_bytes` must trigger
//!    the `ErrProofTooLarge` failure.
//! 6. Batch rejection: any failing proof in a batch must reject the batch,
//!    report the failing index and include the original failure class.
