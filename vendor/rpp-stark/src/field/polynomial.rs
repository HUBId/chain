//! Polynomial utilities operating over the prime field.
//!
//! The module defines *descriptive* types and traits that document how
//! polynomial data is expected to flow through the `rpp-stark` engine.  No
//! arithmetic logic is provided; back-ends embed the required algorithms while
//! conforming to the contracts outlined here.  Coefficients are assumed to live
//! in Montgomery representation to avoid redundant conversions when switching
//! between field arithmetic and FFT-based evaluation domains.

use super::FieldElement;

/// Dense polynomial represented by coefficients in ascending order.
///
/// # Representation
///
/// * `coefficients[0]` stores the constant term, and higher indices correspond
///   to increasing powers of `x`.
/// * All coefficients are encoded in Montgomery form to keep multiplication and
///   accumulation routines compatible with FFT twiddle factors that are also
///   precomputed in Montgomery form.
/// * Consumers are expected to follow the deterministic chunking strategy
///   documented by [`PolynomialChunking`] when distributing work across threads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial {
    /// Backing storage for the dense coefficient vector.
    pub coefficients: Vec<FieldElement>,
}

/// Lightweight view into an existing polynomial.
///
/// This type enables borrowing coefficient slices without requiring an owned
/// allocation.  It mirrors [`Polynomial`] in layout but leaves lifetime
/// management to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolynomialView<'a> {
    /// Borrowed coefficients in Montgomery form.
    pub coefficients: &'a [FieldElement],
}

/// Trait describing evaluation of a polynomial at a single point.
pub trait PolynomialEvaluation {
    /// Evaluates the polynomial at the provided point.
    ///
    /// Implementations typically rely on Horner's method while remaining within
    /// Montgomery form for intermediate products.  Any domain-specific
    /// acceleration (e.g. batching, SIMD) must preserve the deterministic
    /// ordering guarantees defined by [`PolynomialChunking`].
    fn evaluate_at(&self, point: &FieldElement) -> FieldElement;
}

/// Trait exposing degree queries for a polynomial.
pub trait PolynomialDegree {
    /// Returns the degree of the polynomial or `None` if it is identically
    /// zero.
    fn degree(&self) -> Option<usize>;
}

/// Trait providing access to raw coefficients.
pub trait PolynomialCoefficients {
    /// Returns an immutable view over all coefficients in Montgomery form.
    fn coefficients(&self) -> &[FieldElement];

    /// Fetches the coefficient at `index`, returning `None` when the index lies
    /// outside the stored dense range.
    fn coefficient(&self, index: usize) -> Option<FieldElement>;
}

/// Trait documenting deterministic chunking rules used for parallel execution.
///
/// Chunk boundaries must be reproducible across platforms to maintain
/// transcript consistency in interactive oracle proofs.  Implementations should
/// always derive offsets from the canonical dense layout of the polynomial and
/// avoid heuristics that depend on runtime characteristics such as CPU core
/// count.
pub trait PolynomialChunking {
    /// Returns the canonical chunk size used for partitioning the coefficient
    /// vector.
    fn chunk_size(&self) -> usize;

    /// Returns the starting coefficient index for the provided chunk.
    fn chunk_offset(&self, chunk_index: usize) -> usize;
}
