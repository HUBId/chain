//! FRI folding schedule descriptors and binary folding helpers.
//!
//! The folding utilities operate over the Goldilocks field and leverage the
//! deterministic pseudo-hashing primitives defined in [`crate::fri`].

use crate::field::FieldElement;
use crate::fri::config::FriProfile;
use crate::fri::{fe_add, fe_mul};
use crate::params::{FriFolding, StarkParams};

/// Constant folding arity used by the binary FRI variant supported in this crate.
pub const BINARY_FOLD_ARITY: usize = 2;

/// Returns the parent index produced when folding a child position with the
/// [`BINARY_FOLD_ARITY`].
///
/// The helper captures the canonical `floor(child / 2)` mapping used when
/// collapsing a binary FRI layer.  The mapping is stable for coset-based FRI
/// executions because the quotient operation mirrors the domain squaring
/// described by [`phi`].
///
/// ```
/// use rpp_stark::fri::parent_index;
/// assert_eq!(parent_index(0), 0);
/// assert_eq!(parent_index(1), 0);
/// assert_eq!(parent_index(2), 1);
/// ```
#[inline]
pub fn parent_index(child: usize) -> usize {
    child / BINARY_FOLD_ARITY
}

/// Computes the next evaluation domain size after applying the binary fold.
///
/// The helper performs the canonical ceiling division so that odd domain sizes
/// retain the final unpaired element.  Conceptually this matches the `φ` map on
/// the multiplicative subgroup used when switching cosets.
///
/// ```
/// use rpp_stark::fri::next_domain_size;
/// assert_eq!(next_domain_size(8), 4);
/// assert_eq!(next_domain_size(7), 4); // odd sizes round up
/// ```
#[inline]
pub fn next_domain_size(current: usize) -> usize {
    current.div_ceil(BINARY_FOLD_ARITY)
}

/// Canonical FRI map `φ(x) = x²` describing how coset generators evolve while
/// folding the domain.
///
/// ```
/// use rpp_stark::field::FieldElement;
/// use rpp_stark::fri::phi;
///
/// let generator = FieldElement::GENERATOR;
/// assert_eq!(phi(generator), generator.pow(2));
/// ```
#[inline]
pub fn phi(point: FieldElement) -> FieldElement {
    fe_mul(point, point)
}

/// Canonical digest for commitments produced at a given layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LayerCommitment {
    /// Optional transcript digest emitted after committing to the layer.
    pub digest: Option<[u8; 32]>,
    /// Optional textual label describing how the layer contributes to the transcript.
    pub label: &'static str,
}

/// Describes how a layer is produced while folding the evaluation domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldingLayer {
    /// Sequential index of the layer with respect to the original codeword.
    pub layer_index: usize,
    /// Logarithmic size of the evaluation domain at this layer.
    pub log_size: usize,
    /// Commitment emitted for the layer.
    pub commitment: LayerCommitment,
    /// Optional coset shift applied when deriving the folding challenge.
    pub coset_shift: Option<FieldElement>,
}

/// Full schedule tying a FRI profile to an ordered sequence of layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldingLayout {
    /// Reference to the canonical profile driving the schedule.
    pub profile: &'static FriProfile,
    /// Layers enumerated from root (codeword) to the residual polynomial.
    pub layers: Vec<FoldingLayer>,
}

impl FoldingLayout {
    /// Constructs the layout from layer roots and the initial domain size.
    ///
    /// The optional `coset_shifts` slice provides per-layer offsets applied to
    /// the folding challenge when operating in coset-switching mode.
    pub fn new(
        profile: &'static FriProfile,
        initial_size: usize,
        roots: &[[u8; 32]],
        coset_shifts: Option<&[FieldElement]>,
    ) -> Self {
        let mut layers = Vec::with_capacity(roots.len());
        let mut size = initial_size;
        for (layer_index, root) in roots.iter().copied().enumerate() {
            let log_size = log2(size);
            layers.push(FoldingLayer {
                layer_index,
                log_size,
                commitment: LayerCommitment {
                    digest: Some(root),
                    label: "fri-layer",
                },
                coset_shift: coset_shifts.and_then(|shifts| shifts.get(layer_index).copied()),
            });
            size = next_domain_size(size);
        }
        Self { profile, layers }
    }
}

/// Logarithm base two rounded down. `size` must be non-zero.
fn log2(size: usize) -> usize {
    assert!(size > 0, "domain size must be positive");
    usize::BITS as usize - 1 - size.leading_zeros() as usize
}

/// Applies the binary fold to `values` using the challenge `beta`.
///
/// The function groups evaluations into pairs `(a, b)` and produces the linear
/// combination described in the specification:
///
/// `g_i = a + beta * (coset_shift * b)`.
///
/// Coset shifts are derived from the [`StarkParams`] FRI configuration.  When
/// the last pair is incomplete the missing value is treated as zero which keeps
/// the combination well-defined.
pub fn binary_fold(
    values: &[FieldElement],
    beta: FieldElement,
    coset_shift: FieldElement,
) -> Vec<FieldElement> {
    #[cfg(feature = "parallel")]
    if crate::utils::parallelism_enabled() {
        use rayon::prelude::*;
        let pair_count = values.len() / BINARY_FOLD_ARITY;
        let chunk = crate::utils::preferred_chunk_size(pair_count.max(1));
        let mut result: Vec<FieldElement> = values
            .par_chunks_exact(BINARY_FOLD_ARITY)
            .with_min_len(chunk)
            .with_max_len(chunk)
            .map(|pair| {
                let a = pair[0];
                let b = pair[1];
                let shifted_b = fe_mul(b, coset_shift);
                fe_add(a, fe_mul(beta, shifted_b))
            })
            .collect();
        if let Some(&last) = values.chunks_exact(BINARY_FOLD_ARITY).remainder().first() {
            result.push(last);
        }
        return result;
    }

    let mut result = Vec::with_capacity(values.len().div_ceil(BINARY_FOLD_ARITY));
    let mut chunks = values.chunks_exact(BINARY_FOLD_ARITY);

    for pair in chunks.by_ref() {
        let a = pair[0];
        let b = pair[1];
        let shifted_b = fe_mul(b, coset_shift);
        result.push(fe_add(a, fe_mul(beta, shifted_b)));
    }

    if let Some(&last) = chunks.remainder().first() {
        result.push(last);
    }

    result
}

pub(crate) fn derive_coset_shift(params: &StarkParams) -> FieldElement {
    match params.fri().folding {
        FriFolding::Natural => FieldElement::ONE,
        FriFolding::Coset => FieldElement::GENERATOR,
    }
}

/// Builds a per-layer coset shift schedule based on the FRI folding mode.
///
/// Each layer squares the previous coset representative as dictated by
/// [`phi`], mirroring the fact that the evaluation domain is iteratively
/// restricted to even exponents.  Natural folding simply returns the identity
/// shift for every layer.
pub fn coset_shift_schedule(params: &StarkParams, layers: usize) -> Vec<FieldElement> {
    let mut shifts = Vec::with_capacity(layers);
    let mut current = derive_coset_shift(params);
    for _ in 0..layers {
        shifts.push(current);
        current = phi(current);
    }
    shifts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{BuiltinProfile, StarkParamsBuilder};

    #[test]
    fn parent_index_matches_binary_tree_projection() {
        let children: Vec<_> = (0..8).collect();
        let parents: Vec<_> = children.iter().map(|&child| parent_index(child)).collect();
        assert_eq!(parents, vec![0, 0, 1, 1, 2, 2, 3, 3]);
    }

    #[test]
    fn next_domain_size_retains_remainders() {
        assert_eq!(next_domain_size(8), 4);
        assert_eq!(next_domain_size(7), 4);
        assert_eq!(next_domain_size(1), 1);
    }

    #[test]
    fn coset_shift_schedule_tracks_phi_mapping() {
        let params = StarkParamsBuilder::from_profile(BuiltinProfile::PROFILE_X8)
            .build()
            .unwrap();
        let schedule = coset_shift_schedule(&params, 3);
        assert_eq!(schedule.len(), 3);
        assert_eq!(schedule[0], derive_coset_shift(&params));
        assert_eq!(schedule[1], phi(schedule[0]));
        assert_eq!(schedule[2], phi(schedule[1]));
    }
}
