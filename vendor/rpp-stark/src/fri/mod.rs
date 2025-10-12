//! Deterministic binary FRI subsystem shared by the [`fri_prove`] and
//! [`fri_verify`] entry points.
//!
//! # Layer definitions
//!
//! The [`FoldingLayout`] abstraction maps the evaluation domain into a sequence
//! of [`FoldingLayer`] descriptors, one per Merkle commitment emitted during the
//! folding cascade. Each layer records its logarithmic domain size, the
//! [`LayerCommitment`] digest attached to the transcript, and the optional coset
//! shift derived from [`StarkParams`](crate::params::StarkParams).
//!
//! | Layer index | Domain log₂ | Transcript label | Notes |
//! |-------------|-------------|------------------|-------|
//! | 0           | `log₂(n)`   | `"fri-layer"`    | Root commitment over the raw codeword |
//! | 1..L-1      | decrements  | `"fri-layer"`    | Intermediate folds using the active coset shift |
//! | L           | residual    | `"fri-layer"`    | Binding digest for the residual polynomial |
//!
//! # Folding formula
//!
//! Binary folding groups evaluations `(a, b)` and applies the canonical linear
//! combination described in the specification:
//!
//! ```text
//! gᵢ = a + β · (σ · b)
//! ```
//!
//! where `β` is sampled via [`crate::transcript::TranscriptLabel::FriFoldChallenge`], `σ` is the
//! coset shift supplied by [`coset_shift_schedule`], and arithmetic takes place
//! over the Goldilocks field via `fe_add` and `fe_mul`. This formula mirrors
//! the domain squaring performed by [`phi`].
//!
//! # Index and point mappings
//!
//! | Child index pair | [`parent_index`] output |
//! |------------------|-------------------------|
//! | `{0, 1}`         | `0`                     |
//! | `{2, 3}`         | `1`                     |
//! | `…`              | `⌊child / 2⌋`           |
//!
//! The multiplicative generator follows the same deterministic schedule. Each
//! fold maps the coset representative `σᵢ` to `σᵢ₊₁ = φ(σᵢ) = σᵢ²`, ensuring the
//! evaluation domain mirrors the quotienting performed by `parent_index`.
//!
//! # Transcript label inventory
//!
//! Commitments and challenges are absorbed using the explicit labels defined in
//! [`crate::transcript::TranscriptLabel`]. The prover and verifier apply them in
//! the following order: `FriRoot(i)` for each layer commitment,
//! `FriFoldChallenge(i)` for the folding coefficient, `QueryCount` to bind the
//! sampling budget, and `QueryIndexStream` to derive the deterministic query
//! positions. This matches the sequencing enforced by [`fri_prove`] and
//! [`fri_verify`].
//!
//! # DEEP/OODS overview
//!
//! When a DEEP out-of-domain sample is requested, the optional [`DeepOodsProof`]
//! payload binds the evaluation point and its composition evaluations. The
//! verifier replays the same transcript sequence before checking the
//! [`FriProof::deep_oods`] field, keeping the proof structure deterministic and
//! versioned via [`FriProofVersion::CURRENT`].
//!
//! # Serialization and determinism
//!
//! Canonical encoding of digests, field elements, and witness material relies on
//! the shared helpers from [`crate::utils::serialization`]. The resulting byte
//! streams are stable across runs, enabling deterministic replays and explicit
//! versioning through [`SerKind`] and [`FriProofVersion`]. Integrators should
//! treat these contracts as part of the compatibility surface.
//!
//! ```rust,no_run
//! # #![forbid(unsafe_code)]
//! use rpp_stark::fri::{fri_prove, fri_verify, FriError};
//! use rpp_stark::params::StarkParams;
//! use rpp_stark::transcript::{Felt, Transcript};
//!
//! fn prove_then_verify(
//!     mut transcript: Transcript,
//!     params: StarkParams,
//!     evaluations: Vec<Felt>,
//! ) -> Result<(), FriError> {
//!     let proof = fri_prove(&evaluations, &params, &mut transcript)?;
//!     fri_verify(&proof, &params, &mut transcript)?;
//!     Ok(())
//! }
//! ```

mod batch;
pub mod config;
mod folding;
mod layer;
mod proof;
mod prover;
pub mod types;
mod verifier;

pub(crate) use crate::hash::{hash, Blake2sXof};
pub use batch::{BatchDigest, BatchQueryPosition, BatchSeed, FriBatch, FriBatchVerificationApi};
pub use folding::{
    binary_fold, coset_shift_schedule, next_domain_size, parent_index, phi, FoldingLayer,
    FoldingLayout, LayerCommitment, BINARY_FOLD_ARITY,
};
pub use layer::FriLayer;
pub(crate) use proof::derive_query_positions;
pub use proof::{
    derive_query_plan_id, DeepOodsProof, FriProof, FriQueryLayerProof, FriQueryProof, FriVerifier,
};
pub use prover::fri_prove;
pub use types::{
    FriError, FriParamsView, FriProofVersion, FriSecurityLevel, FriTranscriptSeed, SerKind,
};
pub use verifier::fri_verify;

use crate::field::prime_field::{CanonicalSerialize, FieldConstraintError};
use crate::field::FieldElement;

/// Prime modulus used by the Goldilocks field.
const MODULUS: u128 = FieldElement::MODULUS.value as u128;

/// Adds two field elements using canonical modular arithmetic.
#[inline]
pub(crate) fn fe_add(a: FieldElement, b: FieldElement) -> FieldElement {
    let sum = (a.0 as u128 + b.0 as u128) % MODULUS;
    FieldElement(sum as u64)
}

/// Subtracts `b` from `a` modulo the field modulus.
#[inline]
#[allow(dead_code)]
pub(crate) fn fe_sub(a: FieldElement, b: FieldElement) -> FieldElement {
    let lhs = a.0 as i128;
    let rhs = b.0 as i128;
    let modulus = MODULUS as i128;
    let mut diff = lhs - rhs;
    diff %= modulus;
    if diff < 0 {
        diff += modulus;
    }
    FieldElement(diff as u64)
}

/// Multiplies two field elements.
#[inline]
pub(crate) fn fe_mul(a: FieldElement, b: FieldElement) -> FieldElement {
    let product = (a.0 as u128 * b.0 as u128) % MODULUS;
    FieldElement(product as u64)
}

/// Squares a field element.
#[inline]
#[allow(dead_code)]
pub(crate) fn fe_square(value: FieldElement) -> FieldElement {
    fe_mul(value, value)
}

/// Exponentiates a field element using square-and-multiply.
#[allow(dead_code)]
pub(crate) fn fe_pow(mut base: FieldElement, mut exponent: u64) -> FieldElement {
    let mut result = FieldElement::ONE;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = fe_mul(result, base);
        }
        base = fe_square(base);
        exponent >>= 1;
    }
    result
}

/// Converts a 32-byte pseudo-hash into a field element.
pub(crate) fn field_from_hash(bytes: &[u8; 32]) -> FieldElement {
    let mut acc = 0u128;
    for (i, chunk) in bytes.chunks(8).enumerate() {
        if i == 4 {
            break;
        }
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        let value = u64::from_le_bytes(buf);
        acc = (acc << 64) ^ value as u128;
        acc %= MODULUS;
    }
    FieldElement(acc as u64)
}

/// Helper converting a field element into canonical little-endian bytes.
#[inline]
pub(crate) fn field_to_bytes(value: &FieldElement) -> Result<[u8; 8], FieldConstraintError> {
    value.to_bytes()
}

/// Hashes a field element into a leaf digest using the canonical leaf framing.
#[inline]
pub(crate) fn hash_leaf(value: &FieldElement) -> Result<[u8; 32], FieldConstraintError> {
    let mut payload = Vec::with_capacity(12);
    payload.extend_from_slice(&(8u32.to_le_bytes()));
    payload.extend_from_slice(&field_to_bytes(value)?);
    Ok(hash(&payload).into())
}

/// Hashes two child digests into their parent digest.
#[inline]
pub(crate) fn hash_internal(children: &[[u8; 32]; 2]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(64);
    for child in children {
        payload.extend_from_slice(child);
    }
    hash(&payload).into()
}
