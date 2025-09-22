use crate::params::FieldElement;

/// Evaluate a polynomial described by coefficients `values` at the provided
/// evaluation points.  The routine is intentionally naive (O(n^2)) which keeps
/// the implementation small and suitable for deterministic unit tests.
pub fn evaluate_polynomial(coefficients: &[FieldElement], points: &[FieldElement]) -> Vec<FieldElement> {
    points
        .iter()
        .map(|point| {
            let mut acc = FieldElement::zero();
            let mut power = FieldElement::one();
            for coeff in coefficients {
                acc = acc + (*coeff * power);
                power = power * *point;
            }
            acc
        })
        .collect()
}
