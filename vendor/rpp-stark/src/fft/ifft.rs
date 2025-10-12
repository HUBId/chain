//! Inverse FFT routines for polynomial reconstruction.
//!
//! The module documents the inverse transform side of the radix-2 pipeline.
//! Implementations operate entirely in Montgomery space to keep consistency with
//! forward transforms and polynomial storage.  Deterministic chunking mirrors the
//! forward transform to preserve transcript stability in interactive protocols.
//! Plans preserve natural-order input/output conventions regardless of the
//! domain descriptor while keeping all intermediate state in Montgomery form.

use super::{
    apply_bit_reversal, execute_cooley_tukey_stages, inv_mod, montgomery_mul, radix2_domain_size,
    EvaluationDomain, Radix2Domain, Radix2Ordering,
};
use crate::field::FieldElement;

/// Trait documenting inverse FFT execution contracts.
pub trait Ifft<F> {
    /// Associated evaluation domain.
    type Domain: EvaluationDomain<F>;

    /// Returns the evaluation domain descriptor used during interpolation.
    fn domain(&self) -> &Self::Domain;

    /// Executes the inverse transform, mutating the provided evaluations in
    /// place.
    fn inverse(&self, values: &mut [F]);
}

/// Descriptor for radix-2 inverse FFT plans.
#[derive(Debug, Clone, Copy)]
pub struct Radix2InverseFft<F: 'static> {
    /// Domain carrying ordering and generator metadata.
    pub domain: Radix2Domain<F>,
}

impl Radix2InverseFft<FieldElement> {
    /// Creates an inverse FFT plan mirroring the forward radix-2 configuration.
    pub fn new(log2_size: usize, ordering: Radix2Ordering) -> Self {
        Self {
            domain: Radix2Domain::new(log2_size, ordering),
        }
    }

    /// Convenience constructor returning a natural-order inverse plan.
    pub fn natural_order(log2_size: usize) -> Self {
        Self::new(log2_size, Radix2Ordering::Natural)
    }

    /// Convenience constructor returning a bit-reversed inverse plan.
    pub fn bit_reversed(log2_size: usize) -> Self {
        Self::new(log2_size, Radix2Ordering::BitReversed)
    }
}

impl Ifft<FieldElement> for Radix2InverseFft<FieldElement> {
    type Domain = Radix2Domain<FieldElement>;

    fn domain(&self) -> &Self::Domain {
        &self.domain
    }

    fn inverse(&self, values: &mut [FieldElement]) {
        let size = radix2_domain_size(self.domain.log2_size);
        assert_eq!(
            values.len(),
            size,
            "input length must match the FFT domain size",
        );

        if let Radix2Ordering::Natural = self.domain.ordering {
            apply_bit_reversal(values, self.domain.log2_size);
        }

        let inverse_twiddles = self.domain.generators.inverse;
        execute_cooley_tukey_stages(values, self.domain.log2_size, inverse_twiddles);

        let size_field = FieldElement::from(size as u64);
        let size_inv = inv_mod(size_field);
        let mont_size_inv = super::to_montgomery_repr(size_inv);
        for value in values.iter_mut() {
            *value = montgomery_mul(value, &mont_size_inv);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Ifft, Radix2InverseFft};
    use crate::fft::{to_montgomery_repr, Fft, Radix2Fft};
    use crate::field::FieldElement;

    #[test]
    fn mandated_ifft_roundtrip() {
        let log2_size = 4;
        let forward = Radix2Fft::natural_order(log2_size);
        let inverse = Radix2InverseFft::natural_order(log2_size);
        let mut values: Vec<FieldElement> = (0..(1 << log2_size))
            .map(|i| FieldElement::from((i as u64) * 19 + 7))
            .map(to_montgomery_repr)
            .collect();

        let original = values.clone();
        forward.forward(&mut values);
        inverse.inverse(&mut values);

        assert_eq!(
            values, original,
            "IFFT must invert the natural-order forward transform"
        );
    }

    #[test]
    fn inverse_is_left_inverse_of_forward_natural() {
        let log2_size = 3;
        let forward = Radix2Fft::natural_order(log2_size);
        let inverse = Radix2InverseFft::natural_order(log2_size);
        let size = 1usize << log2_size;
        let mut values: Vec<FieldElement> = (0..size)
            .map(|i| FieldElement::from((i as u64) * 5 + 3))
            .map(to_montgomery_repr)
            .collect();

        let original = values.clone();
        forward.forward(&mut values);
        inverse.inverse(&mut values);

        assert_eq!(values, original);
    }

    #[test]
    fn inverse_respects_bit_reversed_ordering() {
        let log2_size = 3;
        let forward = Radix2Fft::bit_reversed(log2_size);
        let inverse = Radix2InverseFft::bit_reversed(log2_size);
        let size = 1usize << log2_size;
        let values: Vec<FieldElement> = (0..size)
            .map(|i| FieldElement::from((i as u64) * 7 + 11))
            .map(to_montgomery_repr)
            .collect();

        let mut bit_reversed = values.clone();
        Radix2Fft::bit_reverse(&mut bit_reversed, log2_size);

        forward.forward(&mut bit_reversed);

        let mut inverse_input = bit_reversed.clone();
        Radix2Fft::bit_reverse(&mut inverse_input, log2_size);
        inverse.inverse(&mut inverse_input);

        assert_eq!(inverse_input, values);
    }
}
