//! Domain parameters and primitives for STWO/STARK integration.

use blake2::{Blake2s256, Digest};
use num_bigint::{BigInt, BigUint, Sign};
use num_traits::{One, Signed, Zero};
use serde::{Deserialize, Serialize};

/// Convenience alias for results returned by field arithmetic helpers.
pub type FieldResult<T> = Result<T, FieldError>;

/// Errors that can be raised while working inside the STARK field.
#[derive(Debug, thiserror::Error)]
pub enum FieldError {
    #[error("field modulus mismatch")]
    ModulusMismatch,
    #[error("element has no multiplicative inverse")]
    NotInvertible,
}

/// Represents an element of the prime field used by the STARK circuits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldElement {
    value: BigUint,
    modulus: BigUint,
}

impl FieldElement {
    /// Create a new field element reducing `value` modulo `modulus`.
    pub fn new(value: BigUint, modulus: BigUint) -> Self {
        debug_assert!(!modulus.is_zero(), "field modulus must be non-zero");
        let value = value % &modulus;
        Self { value, modulus }
    }

    /// Construct an element from a native `u64` value.
    pub fn from_u64(value: u64, modulus: &BigUint) -> Self {
        Self::new(BigUint::from(value), modulus.clone())
    }

    /// Construct an element from a native `u128` value.
    pub fn from_u128(value: u128, modulus: &BigUint) -> Self {
        Self::new(BigUint::from(value), modulus.clone())
    }

    /// Construct an element from an arbitrary byte slice.
    pub fn from_bytes(bytes: &[u8], modulus: &BigUint) -> Self {
        Self::new(BigUint::from_bytes_be(bytes), modulus.clone())
    }

    /// Return the canonical big integer representation of the element.
    pub fn value(&self) -> &BigUint {
        &self.value
    }

    /// Return the modulus that defines the prime field.
    pub fn modulus(&self) -> &BigUint {
        &self.modulus
    }

    fn ensure_same_modulus(&self, other: &FieldElement) -> FieldResult<()> {
        if self.modulus == other.modulus {
            Ok(())
        } else {
            Err(FieldError::ModulusMismatch)
        }
    }

    /// Add two field elements.
    pub fn add(&self, other: &FieldElement) -> FieldResult<FieldElement> {
        self.ensure_same_modulus(other)?;
        Ok(FieldElement::new(
            (&self.value + &other.value) % &self.modulus,
            self.modulus.clone(),
        ))
    }

    /// Subtract one field element from another.
    pub fn sub(&self, other: &FieldElement) -> FieldResult<FieldElement> {
        self.ensure_same_modulus(other)?;
        let mut lhs = self.value.clone();
        if lhs >= other.value {
            lhs -= &other.value;
        } else {
            lhs = (&lhs + &self.modulus) - &other.value;
        }
        Ok(FieldElement::new(lhs % &self.modulus, self.modulus.clone()))
    }

    /// Multiply two field elements.
    pub fn mul(&self, other: &FieldElement) -> FieldResult<FieldElement> {
        self.ensure_same_modulus(other)?;
        Ok(FieldElement::new(
            (&self.value * &other.value) % &self.modulus,
            self.modulus.clone(),
        ))
    }

    /// Compute the multiplicative inverse of the element.
    pub fn inverse(&self) -> FieldResult<FieldElement> {
        if self.value.is_zero() {
            return Err(FieldError::NotInvertible);
        }
        match mod_inverse(&self.value, &self.modulus) {
            Some(inv) => Ok(FieldElement::new(inv, self.modulus.clone())),
            None => Err(FieldError::NotInvertible),
        }
    }

    /// Raise the element to an unsigned power.
    pub fn pow(&self, exponent: u64) -> FieldElement {
        if exponent == 0 {
            return FieldElement::new(BigUint::one(), self.modulus.clone());
        }
        let mut result = FieldElement::new(BigUint::one(), self.modulus.clone());
        let mut base = self.clone();
        let mut exp = exponent;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(&base).expect("modulus matches");
            }
            base = base.mul(&base).expect("modulus matches");
            exp >>= 1;
        }
        result
    }

    /// Return the canonical big-endian bytes of the element.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_bytes_be()
    }

    /// Encode the element as a hex string for public inputs.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Create the additive identity of the field.
    pub fn zero(modulus: &BigUint) -> Self {
        FieldElement::new(BigUint::zero(), modulus.clone())
    }

    /// Create the multiplicative identity of the field.
    pub fn one(modulus: &BigUint) -> Self {
        FieldElement::new(BigUint::one(), modulus.clone())
    }

    /// Returns `true` when the element equals zero.
    pub fn is_zero(&self) -> bool {
        self.value.is_zero()
    }
}

fn mod_inverse(value: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = BigInt::from_biguint(Sign::Plus, modulus.clone());
    let mut new_r = BigInt::from_biguint(Sign::Plus, value.clone());

    while !new_r.is_zero() {
        let quotient = &r / &new_r;

        let temp_t = t - &quotient * &new_t;
        t = new_t;
        new_t = temp_t;

        let temp_r = r - &quotient * &new_r;
        r = new_r;
        new_r = temp_r;
    }

    if r != BigInt::one() {
        return None;
    }

    if t.is_negative() {
        t += BigInt::from_biguint(Sign::Plus, modulus.clone());
    }

    t.to_biguint()
}

/// Poseidon hash configuration parameters derived from the blueprint.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoseidonConfig {
    /// State width parameter (t).
    pub width: usize,
    /// Number of full rounds.
    pub full_rounds: usize,
    /// Number of partial rounds.
    pub partial_rounds: usize,
}

impl Default for PoseidonConfig {
    fn default() -> Self {
        Self {
            width: 3,
            full_rounds: 8,
            partial_rounds: 57,
        }
    }
}

/// Centralized container combining field and hash parameters.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StarkParameters {
    pub field_modulus: BigUint,
    pub poseidon: PoseidonConfig,
}

impl StarkParameters {
    /// Returns the default parameters matching the STWO blueprint.
    pub fn blueprint_default() -> Self {
        let modulus = BigUint::parse_bytes(
            b"18446744069414584321", // 2^64 - 2^32 + 1, a 64-bit prime.
            10,
        )
        .expect("valid prime modulus");
        Self {
            field_modulus: modulus,
            poseidon: PoseidonConfig::default(),
        }
    }

    /// Return the prime field modulus.
    pub fn modulus(&self) -> &BigUint {
        &self.field_modulus
    }

    /// Convert a byte slice into a field element under the blueprint modulus.
    pub fn element_from_bytes(&self, bytes: &[u8]) -> FieldElement {
        FieldElement::from_bytes(bytes, &self.field_modulus)
    }

    /// Convert an unsigned 64-bit value into a field element.
    pub fn element_from_u64(&self, value: u64) -> FieldElement {
        FieldElement::from_u64(value, &self.field_modulus)
    }

    /// Convert an unsigned 128-bit value into a field element.
    pub fn element_from_u128(&self, value: u128) -> FieldElement {
        FieldElement::from_u128(value, &self.field_modulus)
    }

    /// Instantiate a Poseidon sponge over the blueprint parameters.
    pub fn poseidon_hasher(&self) -> PoseidonHasher {
        PoseidonHasher::new(self.poseidon.clone(), self.field_modulus.clone())
    }
}

/// Minimal Poseidon permutation and sponge used for hashing public inputs. The
/// parameters follow the STWO blueprint (t = 3, full = 8, partial = 57).
#[derive(Clone, Debug)]
pub struct PoseidonHasher {
    params: PoseidonConfig,
    modulus: BigUint,
    round_constants: Vec<FieldElement>,
    mds_matrix: Vec<Vec<FieldElement>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_arithmetic_behaves_under_blueprint_modulus() {
        let params = StarkParameters::blueprint_default();
        let modulus = params.modulus().clone();
        let a = FieldElement::from_u64(5, &modulus);
        let b = FieldElement::from_u64(7, &modulus);

        let sum = a.add(&b).expect("matching moduli");
        assert_eq!(sum, FieldElement::from_u64(12, &modulus));

        let product = a.mul(&b).expect("matching moduli");
        assert_eq!(product, FieldElement::from_u64(35, &modulus));

        let inverse = a.inverse().expect("element invertible");
        let identity = a.mul(&inverse).expect("matching moduli");
        assert_eq!(identity, FieldElement::one(&modulus));

        let power = b.pow(3);
        assert_eq!(power, FieldElement::from_u64(343, &modulus));
    }

    #[test]
    fn poseidon_hash_is_deterministic_and_input_sensitive() {
        let params = StarkParameters::blueprint_default();
        let hasher = params.poseidon_hasher();

        let inputs = vec![
            params.element_from_u64(1),
            params.element_from_u64(2),
            params.element_from_u64(3),
        ];

        let first = hasher.hash(&inputs);
        let second = hasher.hash(&inputs);
        assert_eq!(first, second, "hashing must be deterministic");

        let mut tweaked = inputs.clone();
        tweaked[1] = params.element_from_u64(5);
        let different = hasher.hash(&tweaked);
        assert_ne!(first, different, "different inputs must change the digest");
    }
}

impl PoseidonHasher {
    pub fn new(params: PoseidonConfig, modulus: BigUint) -> Self {
        let round_constants = Self::derive_round_constants(&params, &modulus);
        let mds_matrix = Self::derive_mds_matrix(&params, &modulus);
        Self {
            params,
            modulus,
            round_constants,
            mds_matrix,
        }
    }

    /// Return the underlying field modulus.
    pub fn modulus(&self) -> &BigUint {
        &self.modulus
    }

    fn derive_round_constants(params: &PoseidonConfig, modulus: &BigUint) -> Vec<FieldElement> {
        let total_rounds = params.full_rounds + params.partial_rounds;
        let mut constants = Vec::with_capacity(total_rounds * params.width);
        for round in 0..total_rounds {
            for position in 0..params.width {
                let mut hasher = Blake2s256::new();
                hasher.update(b"STWO_POSEIDON_RC");
                hasher.update(&(round as u64).to_be_bytes());
                hasher.update(&(position as u64).to_be_bytes());
                let digest = hasher.finalize();
                constants.push(FieldElement::from_bytes(&digest, modulus));
            }
        }
        constants
    }

    fn derive_mds_matrix(params: &PoseidonConfig, modulus: &BigUint) -> Vec<Vec<FieldElement>> {
        let width = params.width;
        let mut attempt: u64 = 0;
        loop {
            let mut rows = Vec::with_capacity(width);
            for row_idx in 0..width {
                let mut row = Vec::with_capacity(width);
                for col_idx in 0..width {
                    let mut hasher = Blake2s256::new();
                    hasher.update(b"STWO_POSEIDON_MDS");
                    hasher.update(&attempt.to_be_bytes());
                    hasher.update(&(row_idx as u64).to_be_bytes());
                    hasher.update(&(col_idx as u64).to_be_bytes());
                    let digest = hasher.finalize();
                    let element = FieldElement::from_bytes(&digest, modulus);
                    row.push(element);
                }
                rows.push(row);
            }

            if matrix_is_invertible(&rows) {
                return rows;
            }
            attempt = attempt.checked_add(1).expect("attempt counter overflow");
        }
    }

    fn apply_sbox(&self, state: &mut [FieldElement]) {
        for element in state.iter_mut() {
            *element = element.pow(5);
        }
    }

    fn apply_partial_sbox(&self, state: &mut [FieldElement]) {
        if let Some(first) = state.first_mut() {
            *first = first.pow(5);
        }
    }

    fn apply_mds(&self, state: &mut [FieldElement]) {
        let mut new_state = Vec::with_capacity(state.len());
        for row in &self.mds_matrix {
            let mut acc = FieldElement::zero(&self.modulus);
            for (value, coeff) in state.iter().zip(row.iter()) {
                let product = coeff.mul(value).expect("modulus matches");
                acc = acc.add(&product).expect("modulus matches");
            }
            new_state.push(acc);
        }
        for (slot, updated) in state.iter_mut().zip(new_state.into_iter()) {
            *slot = updated;
        }
    }

    fn add_round_constants(&self, state: &mut [FieldElement], round: usize) {
        let offset = round * self.params.width;
        for (idx, element) in state.iter_mut().enumerate() {
            let constant = &self.round_constants[offset + idx];
            *element = element.add(constant).expect("modulus matches");
        }
    }

    fn permute_state(&self, state: &mut [FieldElement]) {
        let total_rounds = self.params.full_rounds + self.params.partial_rounds;
        for round in 0..total_rounds {
            self.add_round_constants(state, round);
            if round < self.params.full_rounds / 2
                || round >= self.params.full_rounds / 2 + self.params.partial_rounds
            {
                self.apply_sbox(state);
            } else {
                self.apply_partial_sbox(state);
            }
            self.apply_mds(state);
        }
    }

    /// Create a new sponge instance backed by this permutation.
    pub fn sponge(&self) -> PoseidonSponge {
        PoseidonSponge::new(self.clone())
    }

    /// Hash a slice of field elements into a single field element commitment.
    pub fn hash(&self, inputs: &[FieldElement]) -> FieldElement {
        let mut sponge = self.sponge();
        sponge.absorb_elements(inputs);
        sponge.finish_absorbing();
        sponge.squeeze()
    }

    /// Convenience helper hashing raw byte slices.
    pub fn hash_bytes(&self, inputs: &[Vec<u8>]) -> FieldElement {
        let elements: Vec<FieldElement> = inputs
            .iter()
            .map(|bytes| FieldElement::from_bytes(bytes, &self.modulus))
            .collect();
        self.hash(&elements)
    }
}

/// Sponge wrapper around the Poseidon permutation.
#[derive(Clone, Debug)]
pub struct PoseidonSponge {
    hasher: PoseidonHasher,
    state: Vec<FieldElement>,
    rate: usize,
    _capacity: usize,
    position: usize,
    mode: SpongeMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SpongeMode {
    Absorbing,
    Squeezing,
}

impl PoseidonSponge {
    fn new(hasher: PoseidonHasher) -> Self {
        let state = vec![FieldElement::zero(hasher.modulus()); hasher.params.width];
        let rate = hasher.params.width - 1;
        let capacity = hasher.params.width - rate;
        Self {
            hasher,
            state,
            rate,
            _capacity: capacity,
            position: 0,
            mode: SpongeMode::Absorbing,
        }
    }

    /// Absorb a slice of field elements into the sponge state.
    pub fn absorb_elements(&mut self, inputs: &[FieldElement]) {
        if inputs.is_empty() {
            return;
        }
        if self.mode == SpongeMode::Squeezing {
            self.hasher.permute_state(&mut self.state);
            self.position = 0;
            self.mode = SpongeMode::Absorbing;
        }
        for element in inputs {
            if self.position == self.rate {
                self.hasher.permute_state(&mut self.state);
                self.position = 0;
            }
            let updated = self.state[self.position]
                .add(element)
                .expect("modulus matches");
            self.state[self.position] = updated;
            self.position += 1;
        }
    }

    /// Absorb raw byte messages using field conversion.
    pub fn absorb_bytes(&mut self, inputs: &[Vec<u8>]) {
        let elements: Vec<FieldElement> = inputs
            .iter()
            .map(|bytes| FieldElement::from_bytes(bytes, self.hasher.modulus()))
            .collect();
        self.absorb_elements(&elements);
    }

    /// Finalize the absorbing phase and prepare for squeezing outputs.
    pub fn finish_absorbing(&mut self) {
        if self.mode == SpongeMode::Squeezing {
            return;
        }
        if self.position == self.rate {
            self.hasher.permute_state(&mut self.state);
            self.position = 0;
        }
        let one = FieldElement::one(self.hasher.modulus());
        let updated = self.state[self.position]
            .add(&one)
            .expect("modulus matches");
        self.state[self.position] = updated;
        self.hasher.permute_state(&mut self.state);
        self.position = 0;
        self.mode = SpongeMode::Squeezing;
    }

    /// Squeeze a single field element from the sponge.
    pub fn squeeze(&mut self) -> FieldElement {
        if self.mode == SpongeMode::Absorbing {
            self.finish_absorbing();
        }
        if self.position == self.rate {
            self.hasher.permute_state(&mut self.state);
            self.position = 0;
        }
        let result = self.state[self.position].clone();
        self.position += 1;
        result
    }

    /// Squeeze multiple field elements from the sponge.
    pub fn squeeze_many(&mut self, count: usize) -> Vec<FieldElement> {
        (0..count).map(|_| self.squeeze()).collect()
    }
}

fn matrix_is_invertible(matrix: &[Vec<FieldElement>]) -> bool {
    let size = matrix.len();
    if size == 0 {
        return false;
    }
    if size == 1 {
        return !matrix[0][0].is_zero();
    }
    if size == 2 {
        let a = &matrix[0][0];
        let b = &matrix[0][1];
        let c = &matrix[1][0];
        let d = &matrix[1][1];
        let ad = a.mul(d).expect("modulus matches");
        let bc = b.mul(c).expect("modulus matches");
        return !ad.sub(&bc).expect("modulus matches").is_zero();
    }
    if size == 3 {
        let m = matrix;
        let term1 = m[0][0]
            .mul(&m[1][1])
            .expect("modulus matches")
            .mul(&m[2][2])
            .expect("modulus matches");
        let term2 = m[0][1]
            .mul(&m[1][2])
            .expect("modulus matches")
            .mul(&m[2][0])
            .expect("modulus matches");
        let term3 = m[0][2]
            .mul(&m[1][0])
            .expect("modulus matches")
            .mul(&m[2][1])
            .expect("modulus matches");
        let term4 = m[0][2]
            .mul(&m[1][1])
            .expect("modulus matches")
            .mul(&m[2][0])
            .expect("modulus matches");
        let term5 = m[0][0]
            .mul(&m[1][2])
            .expect("modulus matches")
            .mul(&m[2][1])
            .expect("modulus matches");
        let term6 = m[0][1]
            .mul(&m[1][0])
            .expect("modulus matches")
            .mul(&m[2][2])
            .expect("modulus matches");

        let det = term1
            .add(&term2)
            .expect("modulus matches")
            .add(&term3)
            .expect("modulus matches")
            .sub(&term4)
            .expect("modulus matches")
            .sub(&term5)
            .expect("modulus matches")
            .sub(&term6)
            .expect("modulus matches");
        return !det.is_zero();
    }

    // Fallback: perform Gaussian elimination to compute determinant != 0.
    gaussian_invertible(matrix)
}

fn gaussian_invertible(matrix: &[Vec<FieldElement>]) -> bool {
    let size = matrix.len();
    let mut mat: Vec<Vec<FieldElement>> = matrix
        .iter()
        .map(|row| row.iter().cloned().collect())
        .collect();

    for pivot in 0..size {
        let mut pivot_row = pivot;
        while pivot_row < size && mat[pivot_row][pivot].is_zero() {
            pivot_row += 1;
        }
        if pivot_row == size {
            return false;
        }
        if pivot_row != pivot {
            mat.swap(pivot_row, pivot);
        }
        let pivot_value = mat[pivot][pivot].clone();
        let pivot_inv = match pivot_value.inverse() {
            Ok(inv) => inv,
            Err(_) => return false,
        };

        for col in pivot..size {
            mat[pivot][col] = mat[pivot][col].mul(&pivot_inv).expect("modulus matches");
        }

        for row in 0..size {
            if row == pivot {
                continue;
            }
            let factor = mat[row][pivot].clone();
            if factor.is_zero() {
                continue;
            }
            for col in pivot..size {
                let product = factor.mul(&mat[pivot][col]).expect("modulus matches");
                mat[row][col] = mat[row][col].sub(&product).expect("modulus matches");
            }
        }
    }

    true
}
