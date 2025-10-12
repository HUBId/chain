//! Fast Fourier Transform utilities for the `rpp-stark` engine.
//!
//! This module captures the type-level contracts for radix-2 FFT execution
//! without providing concrete algorithms.  The documented traits explicitly
//! state how Montgomery-encoded field elements, generator tables, and
//! deterministic chunking interplay to guarantee reproducibility across
//! platforms.

use core::marker::PhantomData;

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::field::{prime_field::FieldElementOps, FieldElement};

pub mod ifft;
pub mod lde;

pub use ifft::Ifft;

/// Maximum supported radix-2 domain size expressed as `log2(n)`.
///
/// Implementations are expected to enforce this bound when building FFT plans
/// to ensure generator tables remain precomputed and cache-friendly.
pub const RADIX2_MAX_LOG2_SIZE: usize = 32;

/// Ordering used when iterating evaluation domain elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Radix2Ordering {
    /// Natural (lexicographic) ordering.
    Natural,
    /// Bit-reversed ordering compatible with iterative Cooley-Tukey FFTs.
    BitReversed,
}

/// Placeholder table describing radix-2 generators in Montgomery form.
#[derive(Debug, Clone, Copy)]
pub struct Radix2GeneratorTable<F: 'static> {
    /// Successive powers of the primitive root used for the forward FFT.
    pub forward: &'static [F],
    /// Successive powers of the inverse root used for the inverse FFT.
    pub inverse: &'static [F],
    /// Marker tying the table to the field implementation.
    pub _field: PhantomData<F>,
}

impl<F: 'static> Radix2GeneratorTable<F> {
    /// Returns an empty placeholder table.
    pub const fn empty() -> Self {
        Self {
            forward: &[],
            inverse: &[],
            _field: PhantomData,
        }
    }
}

/// Canonical radix-2 evaluation domain descriptor.
#[derive(Debug, Clone, Copy)]
pub struct Radix2Domain<F: 'static> {
    /// Logarithm of the domain size.
    pub log2_size: usize,
    /// Element ordering used during iteration.
    pub ordering: Radix2Ordering,
    /// Precomputed generator tables in Montgomery form.
    pub generators: Radix2GeneratorTable<F>,
}

/// Number of butterflies executed by each deterministic tile.
///
/// FFT implementations must honour this bound to ensure chunk scheduling stays
/// deterministic across platforms irrespective of the number of workers.  Each
/// tile processes exactly this many butterflies before yielding, guaranteeing a
/// reproducible execution trace when parallelised.
pub const RADIX2_FFT_BUTTERFLIES_PER_TILE: usize = 128;

const RADIX2_CHUNKING_DESCRIPTION: &str =
    "Radix-2 FFTs are chunked into fixed 128-butterfly tiles.  Each worker \
     processes whole tiles in Montgomery form before synchronising on the next \
     stage, guaranteeing identical transcript ordering across platforms.";

static RADIX2_GENERATOR_CACHE: OnceLock<Mutex<HashMap<usize, Radix2GeneratorTable<FieldElement>>>> =
    OnceLock::new();

fn generator_cache() -> &'static Mutex<HashMap<usize, Radix2GeneratorTable<FieldElement>>> {
    RADIX2_GENERATOR_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn leak_field_elements(elements: Vec<FieldElement>) -> &'static [FieldElement] {
    let slice: &'static mut [FieldElement] = elements.leak();
    slice as &'static [FieldElement]
}

fn derive_primitive_root(log2_size: usize) -> FieldElement {
    assert!(
        log2_size <= RADIX2_MAX_LOG2_SIZE,
        "log2 size exceeds supported maximum"
    );
    if log2_size == 0 {
        return FieldElement::ONE;
    }
    let order = 1u64 << log2_size;
    let cofactor = (FieldElement::MODULUS.value - 1) / order;
    let mut base = 2u64;
    loop {
        let candidate = pow_mod(FieldElement::from(base), cofactor);
        if is_primitive_radix2_root(candidate, log2_size) {
            return candidate;
        }
        base += 1;
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn canonical_add(a: FieldElement, b: FieldElement) -> FieldElement {
    let modulus = FieldElement::MODULUS.value as u128;
    let mut sum = a.0 as u128 + b.0 as u128;
    if sum >= modulus {
        sum -= modulus;
    }
    FieldElement::from(sum as u64)
}

#[cfg_attr(not(test), allow(dead_code))]
fn canonical_mul(a: FieldElement, b: FieldElement) -> FieldElement {
    let modulus = FieldElement::MODULUS.value as u128;
    let product = (a.0 as u128 * b.0 as u128) % modulus;
    FieldElement::from(product as u64)
}

#[cfg_attr(not(test), allow(dead_code))]
fn canonical_sub(a: FieldElement, b: FieldElement) -> FieldElement {
    let modulus = FieldElement::MODULUS.value as u128;
    let lhs = a.0 as u128;
    let rhs = b.0 as u128;
    let result = if lhs >= rhs {
        lhs - rhs
    } else {
        lhs + modulus - rhs
    };
    FieldElement::from(result as u64)
}

fn pow_mod(base: FieldElement, mut exponent: u64) -> FieldElement {
    let modulus = FieldElement::MODULUS.value as u128;
    let mut result = 1u128;
    let mut base_val = base.0 as u128 % modulus;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = (result * base_val) % modulus;
        }
        base_val = (base_val * base_val) % modulus;
        exponent >>= 1;
    }
    FieldElement::from(result as u64)
}

fn inv_mod(value: FieldElement) -> FieldElement {
    let exponent = FieldElement::MODULUS.value - 2;
    pow_mod(value, exponent)
}

fn r_inverse() -> FieldElement {
    static R_INV: OnceLock<FieldElement> = OnceLock::new();
    *R_INV.get_or_init(|| {
        let r = FieldElement::from(FieldElement::R);
        pow_mod(r, FieldElement::MODULUS.value - 2)
    })
}

fn to_montgomery_repr(value: FieldElement) -> FieldElement {
    canonical_mul(value, FieldElement::from(FieldElement::R))
}

#[cfg_attr(not(test), allow(dead_code))]
fn from_montgomery_repr(value: FieldElement) -> FieldElement {
    canonical_mul(value, r_inverse())
}

fn is_primitive_radix2_root(root: FieldElement, log2_size: usize) -> bool {
    if log2_size == 0 {
        return root == FieldElement::ONE;
    }

    let order = 1u64 << log2_size;
    if pow_mod(root, order) != FieldElement::ONE {
        return false;
    }

    let half_order = 1u64 << (log2_size - 1);
    pow_mod(root, half_order) != FieldElement::ONE
}

fn build_twiddle_tables(
    primitive_root: FieldElement,
    log2_size: usize,
) -> (Vec<FieldElement>, Vec<FieldElement>) {
    assert!(
        log2_size <= RADIX2_MAX_LOG2_SIZE,
        "log2 size exceeds supported maximum"
    );
    let size = 1usize << log2_size;

    let mut forward = Vec::with_capacity(size);
    let mut inverse = Vec::with_capacity(size);

    let root_inverse = inv_mod(primitive_root);

    let mut current_forward = FieldElement::ONE;
    let mut current_inverse = FieldElement::ONE;

    for _ in 0..size {
        forward.push(to_montgomery_repr(current_forward));
        inverse.push(to_montgomery_repr(current_inverse));
        current_forward = canonical_mul(current_forward, primitive_root);
        current_inverse = canonical_mul(current_inverse, root_inverse);
    }

    (forward, inverse)
}

fn generator_table_for(log2_size: usize) -> Radix2GeneratorTable<FieldElement> {
    let cache = generator_cache();
    let mut guard = match cache.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            guard.remove(&log2_size);
            guard
        }
    };
    let entry = guard.entry(log2_size).or_insert_with(|| {
        let primitive_root = derive_primitive_root(log2_size);
        let (forward, inverse) = build_twiddle_tables(primitive_root, log2_size);
        Radix2GeneratorTable {
            forward: leak_field_elements(forward),
            inverse: leak_field_elements(inverse),
            _field: PhantomData,
        }
    });
    *entry
}

impl Radix2Domain<FieldElement> {
    /// Builds a radix-2 evaluation domain using the deterministic generator cache.
    pub fn new(log2_size: usize, ordering: Radix2Ordering) -> Self {
        assert!(
            log2_size <= RADIX2_MAX_LOG2_SIZE,
            "log2 size exceeds supported maximum"
        );
        let generators = generator_table_for(log2_size);
        Self {
            log2_size,
            ordering,
            generators,
        }
    }
}

impl EvaluationDomain<FieldElement> for Radix2Domain<FieldElement> {
    fn log2_size(&self) -> usize {
        self.log2_size
    }

    fn ordering(&self) -> Radix2Ordering {
        self.ordering
    }

    fn generators(&self) -> &Radix2GeneratorTable<FieldElement> {
        &self.generators
    }

    fn chunking_description(&self) -> &'static str {
        RADIX2_CHUNKING_DESCRIPTION
    }
}

/// Trait describing evaluation domains used for FFTs.
pub trait EvaluationDomain<F> {
    /// Returns the logarithm of the domain size.
    fn log2_size(&self) -> usize;

    /// Returns the concrete ordering of the domain elements.
    fn ordering(&self) -> Radix2Ordering;

    /// Returns the generator table used for twiddle factor lookups.
    fn generators(&self) -> &Radix2GeneratorTable<F>;

    /// Provides a canonical description of the deterministic chunking strategy
    /// that must be used when parallelizing FFT butterflies.  The description is
    /// returned as a free-form string to keep the API descriptive while allowing
    /// implementors to document platform specific nuances (e.g. Montgomery
    /// conversion boundaries).
    fn chunking_description(&self) -> &'static str;
}

/// Trait documenting forward FFT execution contracts.
pub trait Fft<F> {
    /// Associated evaluation domain for the plan.
    type Domain: EvaluationDomain<F>;

    /// Returns the evaluation domain descriptor used by the plan.
    fn domain(&self) -> &Self::Domain;

    /// Executes the forward transform in-place on Montgomery encoded values.
    fn forward(&self, values: &mut [F]);
}

/// Plan describing an in-place radix-2 FFT over [`FieldElement`].
#[derive(Debug, Clone, Copy)]
pub struct Radix2Fft {
    domain: Radix2Domain<FieldElement>,
}

/// Returns the size of a radix-2 evaluation domain.
pub(super) fn radix2_domain_size(log2_size: usize) -> usize {
    1usize << log2_size
}

/// Applies the canonical bit-reversal permutation to `values` in-place.
pub(super) fn apply_bit_reversal(values: &mut [FieldElement], log2_size: usize) {
    let size = values.len();
    let tile = RADIX2_FFT_BUTTERFLIES_PER_TILE;
    for chunk_start in (0..size).step_by(tile) {
        let chunk_end = (chunk_start + tile).min(size);
        for index in chunk_start..chunk_end {
            let reversed = reverse_bits(index, log2_size);
            if index < reversed {
                values.swap(index, reversed);
            }
        }
    }
}

/// Executes all radix-2 stages using the provided twiddle table.
pub(super) fn execute_cooley_tukey_stages(
    values: &mut [FieldElement],
    log2_size: usize,
    twiddles: &[FieldElement],
) {
    let size = radix2_domain_size(log2_size);
    for stage in 0..log2_size {
        let m = 1usize << (stage + 1);
        let half_m = m / 2;
        let twiddle_stride = size / m;
        let stage_twiddles: Vec<FieldElement> =
            (0..half_m).map(|j| twiddles[j * twiddle_stride]).collect();

        #[cfg(feature = "parallel")]
        {
            use crate::utils::parallelism_enabled;
            use crate::utils::preferred_chunk_size;
            use rayon::prelude::*;

            if parallelism_enabled() {
                let chunk = preferred_chunk_size((size / m).max(1));
                values
                    .par_chunks_exact_mut(m)
                    .with_min_len(chunk)
                    .with_max_len(chunk)
                    .for_each(|block| apply_stage_block(block, half_m, &stage_twiddles));
            } else {
                for block in values.chunks_exact_mut(m) {
                    apply_stage_block(block, half_m, &stage_twiddles);
                }
            }
        }
        #[cfg(not(feature = "parallel"))]
        for block in values.chunks_exact_mut(m) {
            apply_stage_block(block, half_m, &stage_twiddles);
        }
    }
}

fn apply_stage_block(block: &mut [FieldElement], half_m: usize, stage_twiddles: &[FieldElement]) {
    for j in 0..half_m {
        let twiddle = stage_twiddles[j];
        let u = block[j];
        let v = block[j + half_m];
        let t = montgomery_mul(&twiddle, &v);
        block[j] = u.add(&t);
        block[j + half_m] = u.sub(&t);
    }
}

impl Radix2Fft {
    /// Creates a plan for the provided domain size and element ordering.
    pub fn new(log2_size: usize, ordering: Radix2Ordering) -> Self {
        assert!(RADIX2_FFT_BUTTERFLIES_PER_TILE.is_power_of_two());
        Self {
            domain: Radix2Domain::new(log2_size, ordering),
        }
    }

    /// Convenience constructor returning a natural-order plan.
    pub fn natural_order(log2_size: usize) -> Self {
        Self::new(log2_size, Radix2Ordering::Natural)
    }

    /// Convenience constructor returning a bit-reversed plan.
    pub fn bit_reversed(log2_size: usize) -> Self {
        Self::new(log2_size, Radix2Ordering::BitReversed)
    }

    fn bit_reverse(values: &mut [FieldElement], log2_size: usize) {
        apply_bit_reversal(values, log2_size);
    }
}

fn montgomery_mul(a: &FieldElement, b: &FieldElement) -> FieldElement {
    let canonical_a = from_montgomery_repr(*a);
    let canonical_b = from_montgomery_repr(*b);
    let canonical_product = canonical_mul(canonical_a, canonical_b);
    to_montgomery_repr(canonical_product)
}

fn reverse_bits(value: usize, bits: usize) -> usize {
    if bits == 0 {
        value
    } else {
        value.reverse_bits() >> (usize::BITS as usize - bits)
    }
}

impl Fft<FieldElement> for Radix2Fft {
    type Domain = Radix2Domain<FieldElement>;

    fn domain(&self) -> &Self::Domain {
        &self.domain
    }

    fn forward(&self, values: &mut [FieldElement]) {
        let size = radix2_domain_size(self.domain.log2_size);
        assert_eq!(
            values.len(),
            size,
            "input length must match the FFT domain size"
        );

        match self.domain.ordering {
            Radix2Ordering::Natural => Self::bit_reverse(values, self.domain.log2_size),
            Radix2Ordering::BitReversed => {}
        }

        let forward_twiddles = self.domain.generators.forward;
        execute_cooley_tukey_stages(values, self.domain.log2_size, forward_twiddles);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        canonical_add, canonical_mul, canonical_sub, from_montgomery_repr, montgomery_mul, pow_mod,
        reverse_bits, to_montgomery_repr, EvaluationDomain, Fft, FieldElement, Radix2Fft,
    };
    use crate::fft::ifft::{Ifft, Radix2InverseFft};
    use crate::field::prime_field::MontgomeryConvertible;

    fn naive_dft(values: &[FieldElement], omega: FieldElement) -> Vec<FieldElement> {
        let size = values.len();
        let mut result = vec![FieldElement::ZERO; size];
        for k in 0..size {
            let mut acc = FieldElement::ZERO;
            let exponent = pow_mod(omega, k as u64);
            let mut power = FieldElement::ONE;
            for value in values {
                let term = canonical_mul(*value, power);
                acc = canonical_add(acc, term);
                power = canonical_mul(power, exponent);
            }
            result[k] = acc;
        }
        result
    }

    fn reference_fft(
        mut values: Vec<FieldElement>,
        primitive_root: FieldElement,
        log2_size: usize,
    ) -> Vec<FieldElement> {
        let size = values.len();
        assert_eq!(size, 1 << log2_size);
        for i in 0..size {
            let j = reverse_bits(i, log2_size);
            if i < j {
                values.swap(i, j);
            }
        }

        for stage in 0..log2_size {
            let m = 1usize << (stage + 1);
            let half_m = m / 2;
            let twiddle_stride = size / m;
            for block in 0..(size / m) {
                let base = block * m;
                for j in 0..half_m {
                    let twiddle_index = j * twiddle_stride;
                    let twiddle = pow_mod(primitive_root, twiddle_index as u64);
                    let u = values[base + j];
                    let v = values[base + j + half_m];
                    let t = canonical_mul(v, twiddle);
                    values[base + j] = canonical_add(u, t);
                    values[base + j + half_m] = canonical_sub(u, t);
                }
            }
        }

        values
    }

    #[test]
    fn generator_cache_recovers_from_poisoning() {
        let baseline = super::generator_table_for(3);
        let baseline_forward = baseline.forward;
        let baseline_inverse = baseline.inverse;

        let cache = super::generator_cache();
        let poison_result = std::panic::catch_unwind(|| {
            let _guard = cache.lock().unwrap();
            panic!("intentional cache poison");
        });
        assert!(poison_result.is_err(), "poison simulation must panic");

        let recovered = super::generator_table_for(3);
        assert_eq!(recovered.forward, baseline_forward);
        assert_eq!(recovered.inverse, baseline_inverse);
    }

    #[test]
    fn mandated_fft_roundtrip() {
        let log2_size = 4;
        let forward = Radix2Fft::natural_order(log2_size);
        let inverse = Radix2InverseFft::natural_order(log2_size);
        let mut values: Vec<FieldElement> = (0..(1 << log2_size))
            .map(|i| FieldElement::from((i as u64) * 17 + 5))
            .map(to_montgomery_repr)
            .collect();

        let original = values.clone();
        forward.forward(&mut values);
        inverse.inverse(&mut values);

        assert_eq!(
            values, original,
            "FFT followed by IFFT must recover the input"
        );
    }

    #[test]
    fn mandated_fft_root_selection_is_stable() {
        let log2_size = 5;
        let first = super::derive_primitive_root(log2_size);
        let second = super::derive_primitive_root(log2_size);
        assert_eq!(first, second, "primitive root derivation must be stable");

        let plan = Radix2Fft::natural_order(log2_size);
        let cached_root = from_montgomery_repr(plan.domain().generators.forward[1]);
        assert_eq!(
            cached_root, first,
            "generator table must reuse the derived primitive root"
        );
    }

    #[test]
    fn natural_order_matches_naive_dft() {
        let plan = Radix2Fft::natural_order(3);
        let size = 1 << plan.domain().log2_size;
        let canonical: Vec<FieldElement> = (0..size)
            .map(|i| FieldElement::from((i as u64) + 1))
            .collect();
        let montgomery: Vec<FieldElement> =
            canonical.iter().map(|v| to_montgomery_repr(*v)).collect();

        let mut transformed = montgomery.clone();
        plan.forward(&mut transformed);
        let result: Vec<FieldElement> = transformed
            .iter()
            .copied()
            .map(from_montgomery_repr)
            .collect();

        let omega = from_montgomery_repr(plan.domain().generators.forward[1]);
        let expected = naive_dft(&canonical, omega);
        let reference = reference_fft(canonical.clone(), omega, plan.domain().log2_size());
        assert_eq!(expected, reference, "reference FFT mismatch");
        assert_eq!(result, expected);
    }

    #[test]
    fn bit_reversal_helper_matches_manual() {
        let log2_size = 4;
        let size = 1usize << log2_size;
        let mut values: Vec<FieldElement> =
            (0..size).map(|i| FieldElement::from(i as u64)).collect();

        let mut expected = values.clone();
        for i in 0..size {
            let j = reverse_bits(i, log2_size);
            if i < j {
                expected.swap(i, j);
            }
        }

        Radix2Fft::bit_reverse(&mut values, log2_size);
        assert_eq!(values, expected);
    }

    #[test]
    fn natural_and_bit_reversed_agree() {
        let log2_size = 3;
        let natural_plan = Radix2Fft::natural_order(log2_size);
        let bit_reversed_plan = Radix2Fft::bit_reversed(log2_size);

        let size = 1usize << log2_size;
        let mut natural_values: Vec<FieldElement> = (0..size)
            .map(|i| to_montgomery_repr(FieldElement::from((i as u64) * 3 + 7)))
            .collect();

        let mut bit_reversed_values = natural_values.clone();
        Radix2Fft::bit_reverse(&mut bit_reversed_values, log2_size);

        natural_plan.forward(&mut natural_values);
        bit_reversed_plan.forward(&mut bit_reversed_values);

        assert_eq!(natural_values, bit_reversed_values);
    }

    #[test]
    fn montgomery_mul_matches_identity_cases() {
        let one = to_montgomery_repr(FieldElement::ONE);
        let two = to_montgomery_repr(FieldElement::from(2));
        let product = montgomery_mul(&one, &two);
        assert_eq!(product, two);
    }

    #[test]
    fn montgomery_mul_matches_canonical_multiplication() {
        let root = super::derive_primitive_root(3);
        let mont_root = to_montgomery_repr(root);
        let mont_squared = montgomery_mul(&mont_root, &mont_root);
        let canonical = canonical_mul(root, root);
        assert_eq!(from_montgomery_repr(mont_squared), canonical);
    }

    #[test]
    fn montgomery_mul_matches_canonical_for_small_values() {
        for a in 0..32u64 {
            for b in 0..32u64 {
                let canonical_a = FieldElement::from(a);
                let canonical_b = FieldElement::from(b);
                let mont_a = to_montgomery_repr(canonical_a);
                let mont_b = to_montgomery_repr(canonical_b);
                let product = montgomery_mul(&mont_a, &mont_b);
                let expected = canonical_mul(canonical_a, canonical_b);
                assert_eq!(
                    from_montgomery_repr(product),
                    expected,
                    "mismatch for a={a}, b={b}"
                );
            }
        }
    }

    #[test]
    fn pow_mod_smoke() {
        let base = FieldElement::from(3);
        let value = super::pow_mod(base, 8);
        let expected = FieldElement::from(6561 % FieldElement::MODULUS.value);
        assert_eq!(value, expected);
    }

    #[test]
    fn primitive_root_generation() {
        let root = super::derive_primitive_root(3);
        assert!(super::is_primitive_radix2_root(root, 3));
    }

    #[test]
    fn montgomery_roundtrip_matches_canonical() {
        for value in 0..8u64 {
            let canonical = FieldElement::from(value);
            let mont = to_montgomery_repr(canonical);
            let roundtrip = from_montgomery_repr(mont);
            assert_eq!(roundtrip, canonical);
        }
        let root = super::derive_primitive_root(3);
        let roundtrip_root = from_montgomery_repr(to_montgomery_repr(root));
        assert_eq!(roundtrip_root, root);
    }

    #[test]
    fn manual_and_builtin_montgomery_agree() {
        for value in 0..32u64 {
            let canonical = FieldElement::from(value);
            assert_eq!(
                to_montgomery_repr(canonical),
                canonical.to_montgomery(),
                "mismatch for value {value}"
            );
        }
    }
}
