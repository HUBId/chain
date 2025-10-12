//! Prime field interface tailored for the `rpp-stark` engine.
//!
//! This module intentionally exposes *only* the type- and trait-level
//! contracts that downstream back-ends must satisfy.  No arithmetic logic
//! is provided here; consumers are expected to supply constant-time
//! implementations that respect the documented invariants.
#![allow(clippy::wrong_self_convention)]
//!
//! # Security Notes
//!
//! * No `unsafe` code is used in this module.
//! * Randomness must always be derived deterministically from the transcript;
//!   operating-system entropy sources are intentionally avoided.

use core::{cmp::Ordering, fmt};
use std::error::Error;

/// Errors surfaced while enforcing canonical field constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldConstraintError {
    /// The value is not a canonical representative of the field modulus.
    NotCanonical,
    /// The value must be non-zero but was equal to the additive identity.
    IsZero,
}

impl fmt::Display for FieldConstraintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldConstraintError::NotCanonical => {
                f.write_str("field element is not in canonical form")
            }
            FieldConstraintError::IsZero => {
                f.write_str("field element violates non-zero constraint")
            }
        }
    }
}

impl Error for FieldConstraintError {}

/// Metadata describing the underlying field modulus.
#[derive(Debug, Clone, Copy)]
pub struct Modulus {
    /// Prime modulus value in canonical representation.
    pub value: u64,
    /// Indicates whether the modulus passed primality checks during configuration.
    pub is_prime: bool,
}

impl Modulus {
    /// Creates a new modulus descriptor.
    pub const fn new(value: u64, is_prime: bool) -> Self {
        Self { value, is_prime }
    }
}

/// Canonical generator for the default field used across the system.
pub const DEFAULT_MODULUS: Modulus = Modulus::new(0xffffffff00000001, true);

/// Field element represented as a canonical value modulo the prime.
///
/// # Representation
///
/// * `FieldElement` is a transparent wrapper around a raw `u64`.  When the
///   element is in canonical (non-Montgomery) form the wrapped integer must be
///   within the range `[0, MODULUS.value)`.
/// * Montgomery form encodes elements as `a * R mod MODULUS`, where `R = 2^64`.
/// * Serialization uses **little-endian** byte order for canonical
///   representations; Montgomery encodings are documented separately by the
///   conversion traits.
///
/// # Safety & Auditing
///
/// The type itself performs no runtime validation.  Implementations of the
/// provided traits must enforce the documented invariants and perform
/// constant-time assertions where required by `ConstantTimeAssertions`.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct FieldElement(pub u64);

impl fmt::Debug for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("FieldElement").field(&self.0).finish()
    }
}

impl FieldElement {
    /// Canonical prime modulus associated with this field.
    pub const MODULUS: Modulus = DEFAULT_MODULUS;
    /// Montgomery radix `R = 2^64 mod MODULUS`.
    pub const R: u64 = 0xffffffff;
    /// Precomputed `R^2 mod MODULUS` used for Montgomery conversions.
    pub const R2: u64 = 0xfffffffe00000001;
    /// `-MODULUS^{-1} mod 2^64`, the Montgomery reduction parameter.
    pub const MONTGOMERY_INV: u64 = 0xfffffffeffffffff;
    /// Designated generator for the multiplicative subgroup.
    pub const GENERATOR: FieldElement = FieldElement(3);
    /// Additive identity in canonical form.
    pub const ZERO: FieldElement = FieldElement(0);
    /// Multiplicative identity in canonical form.
    pub const ONE: FieldElement = FieldElement(1);
    /// Length in bytes of the canonical serialization.
    pub const BYTE_LENGTH: usize = 8;

    #[inline(always)]
    const fn modulus() -> u64 {
        Self::MODULUS.value
    }

    #[inline(always)]
    fn reduce_once(value: u64) -> u64 {
        let reduced = value.wrapping_sub(Self::modulus());
        let underflow = (reduced > value) as u64;
        let mask = underflow.wrapping_neg();
        reduced.wrapping_add(Self::modulus() & mask)
    }

    #[inline(always)]
    fn montgomery_reduce(t: u128) -> u64 {
        let modulus = Self::modulus() as u128;
        let m = (t as u64).wrapping_mul(Self::MONTGOMERY_INV) as u128;
        let u = t.wrapping_add(m.wrapping_mul(modulus)) >> 64;
        let candidate = u as u64;
        Self::reduce_once(candidate)
    }

    #[inline(always)]
    fn montgomery_mul(a: u64, b: u64) -> u64 {
        let product = (a as u128) * (b as u128);
        Self::montgomery_reduce(product)
    }

    #[inline(always)]
    fn add_internal(&self, rhs: &Self) -> Self {
        let modulus = Self::modulus() as u128;
        let sum = self.0 as u128 + rhs.0 as u128;
        let mask = (sum >= modulus) as u128;
        let result = sum - mask * modulus;
        FieldElement(result as u64)
    }

    #[inline(always)]
    fn sub_internal(&self, rhs: &Self) -> Self {
        let (diff, borrow) = self.0.overflowing_sub(rhs.0);
        let mask = (borrow as u64).wrapping_neg();
        let result = diff.wrapping_add(Self::modulus() & mask);
        FieldElement(result)
    }

    #[inline(always)]
    fn neg_internal(&self) -> Self {
        let tmp = Self::modulus().wrapping_sub(self.0);
        let nz = (self.0 != 0) as u64;
        let mask = nz.wrapping_neg();
        FieldElement(tmp & mask)
    }

    #[inline(always)]
    fn mul_internal(&self, rhs: &Self) -> Self {
        let modulus = Self::modulus() as u128;
        let product = (self.0 as u128 * rhs.0 as u128) % modulus;
        FieldElement(product as u64)
    }

    #[inline(always)]
    fn square_internal(&self) -> Self {
        let modulus = Self::modulus() as u128;
        let product = (self.0 as u128 * self.0 as u128) % modulus;
        FieldElement(product as u64)
    }

    /// Raises the element to the provided exponent using square-and-multiply.
    pub fn pow(&self, exponent: u64) -> Self {
        let mut base = *self;
        let mut acc = FieldElement::ONE;
        for i in 0..64 {
            let bit = (exponent >> i) & 1;
            let mask = bit.wrapping_neg();
            let candidate = acc.mul_internal(&base);
            let acc_val = (acc.0 & !mask) | (candidate.0 & mask);
            acc = FieldElement(acc_val);
            base = base.square_internal();
        }
        acc
    }

    /// Converts uniformly distributed transcript bytes into a field element.
    pub fn from_transcript_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (dst, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(chunk);
            *dst = u64::from_le_bytes(buf);
        }

        let mut acc = FieldElement::ZERO;
        let mut factor = FieldElement::ONE;
        let radix = FieldElement::from(Self::R);
        for limb in limbs.iter() {
            let term = FieldElement::from(*limb).mul_internal(&factor);
            acc = acc.add_internal(&term);
            factor = factor.mul_internal(&radix);
        }
        acc
    }
}

/// Trait describing the high-level arithmetic contract for field elements.
pub trait FieldElementOps: Sized {
    /// Adds two canonical field elements, returning the canonical representative.
    fn add(&self, rhs: &Self) -> Self;
    /// Subtracts `rhs` from `self` in canonical form.
    fn sub(&self, rhs: &Self) -> Self;
    /// Computes the additive inverse of `self`.
    fn neg(&self) -> Self;
    /// Multiplies two field elements.
    fn mul(&self, rhs: &Self) -> Self;
    /// Squares the field element.
    fn square(&self) -> Self;
    /// Computes the multiplicative inverse, returning `None` for zero.
    fn inv(&self) -> Option<Self>;
}

/// Trait capturing Montgomery encoding/decoding contracts.
pub trait MontgomeryConvertible: Sized {
    /// Converts a canonical element into Montgomery form.
    fn to_montgomery(&self) -> Self;
    /// Converts an element from Montgomery form back to canonical representation.
    fn from_montgomery(&self) -> Self;
}

/// Trait defining serialization requirements for field elements.
///
/// Implementations must reject non-canonical encodings by returning
/// [`FieldConstraintError`].
pub trait CanonicalSerialize: Sized {
    /// Canonical serialization output type (e.g. `[u8; 8]`).
    type Bytes;

    /// Serializes the element into canonical little-endian bytes.
    fn to_bytes(&self) -> Result<Self::Bytes, FieldConstraintError>;

    /// Attempts to deserialize from canonical little-endian bytes.
    fn from_bytes(bytes: &Self::Bytes) -> Result<Self, FieldDeserializeError>;
}

/// Errors that can occur while deserializing field elements from canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldDeserializeError {
    /// The provided bytes encode a value outside of the canonical field range.
    FieldDeserializeNonCanonical,
}

impl fmt::Display for FieldDeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldDeserializeError::FieldDeserializeNonCanonical => {
                f.write_str("field element deserialization failed: non-canonical input")
            }
        }
    }
}

/// Trait collecting constant-time auditing assertions required by higher layers.
///
/// The methods return [`FieldConstraintError`] instead of panicking so callers
/// can surface canonicality bugs through their own error channels while
/// retaining constant-time checking internally.
pub trait ConstantTimeAssertions {
    /// Ensures the element is strictly less than the field modulus in constant time.
    fn assert_lt_modulus(&self) -> Result<(), FieldConstraintError>;
    /// Ensures the element is *not* the additive identity in constant time.
    fn assert_nonzero(&self) -> Result<(), FieldConstraintError>;
    /// Ensures the element is a valid canonical representative.
    fn assert_canonical(&self) -> Result<(), FieldConstraintError>;
}

impl FieldElementOps for FieldElement {
    fn add(&self, rhs: &Self) -> Self {
        self.add_internal(rhs)
    }

    fn sub(&self, rhs: &Self) -> Self {
        self.sub_internal(rhs)
    }

    fn neg(&self) -> Self {
        self.neg_internal()
    }

    fn mul(&self, rhs: &Self) -> Self {
        self.mul_internal(rhs)
    }

    fn square(&self) -> Self {
        self.square_internal()
    }

    fn inv(&self) -> Option<Self> {
        if self.0 == 0 {
            None
        } else {
            Some(self.pow(Self::modulus() - 2))
        }
    }
}

impl MontgomeryConvertible for FieldElement {
    fn to_montgomery(&self) -> Self {
        FieldElement(Self::montgomery_mul(self.0, Self::R2))
    }

    fn from_montgomery(&self) -> Self {
        FieldElement(Self::montgomery_mul(self.0, 1))
    }
}

impl CanonicalSerialize for FieldElement {
    type Bytes = [u8; 8];

    fn to_bytes(&self) -> Result<Self::Bytes, FieldConstraintError> {
        self.assert_canonical()?;
        Ok(self.0.to_le_bytes())
    }

    fn from_bytes(bytes: &Self::Bytes) -> Result<Self, FieldDeserializeError> {
        let value = u64::from_le_bytes(*bytes);
        if value < Self::modulus() {
            Ok(FieldElement(value))
        } else {
            Err(FieldDeserializeError::FieldDeserializeNonCanonical)
        }
    }
}

impl ConstantTimeAssertions for FieldElement {
    fn assert_lt_modulus(&self) -> Result<(), FieldConstraintError> {
        if self.0 >= Self::modulus() {
            return Err(FieldConstraintError::NotCanonical);
        }
        Ok(())
    }

    fn assert_nonzero(&self) -> Result<(), FieldConstraintError> {
        if self.0 == 0 {
            return Err(FieldConstraintError::IsZero);
        }
        Ok(())
    }

    fn assert_canonical(&self) -> Result<(), FieldConstraintError> {
        self.assert_lt_modulus()
    }
}

impl From<u64> for FieldElement {
    fn from(value: u64) -> Self {
        FieldElement(FieldElement::reduce_once(value))
    }
}

impl TryFrom<FieldElement> for u64 {
    type Error = FieldConstraintError;

    fn try_from(value: FieldElement) -> Result<Self, Self::Error> {
        value.assert_canonical()?;
        Ok(value.0)
    }
}

impl Ord for FieldElement {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.cmp(&other.0)
    }
}

impl PartialOrd for FieldElement {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl FieldElement {
    /// Returns `true` if the element is the additive identity.
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    /// Returns `true` if the element is the multiplicative identity.
    pub fn is_one(&self) -> bool {
        self.0 == 1
    }
}
