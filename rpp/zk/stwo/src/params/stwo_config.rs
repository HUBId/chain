use serde::{Deserialize, Serialize};

/// Field modulus used by the lightweight prover: 2^64 - 2^32 + 1 (a popular
/// 64-bit friendly prime).
pub const FIELD_MODULUS: u128 = 0xFFFF_FFFF_0000_0001;

/// Configuration values mirroring the upstream STWO defaults.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StwoConfig {
    pub field_modulus: u128,
    pub blowup_factor: usize,
    pub fri_repetitions: usize,
    pub proof_size_hint: usize,
}

impl Default for StwoConfig {
    fn default() -> Self {
        Self {
            field_modulus: FIELD_MODULUS,
            blowup_factor: 16,
            fri_repetitions: 5,
            proof_size_hint: 20 * 1024,
        }
    }
}

/// Minimal field element representation used across the crate.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FieldElement(u128);

impl FieldElement {
    pub fn new(value: u128) -> Self {
        Self(value % FIELD_MODULUS)
    }

    pub fn zero() -> Self {
        Self(0)
    }

    pub fn one() -> Self {
        Self(1)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut acc = 0u128;
        for byte in bytes.iter().take(16) {
            acc = (acc << 8) | (*byte as u128);
        }
        Self::new(acc)
    }

    pub fn to_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }
}

impl From<u128> for FieldElement {
    fn from(value: u128) -> Self {
        FieldElement::new(value)
    }
}

use core::ops::{Add, Mul};

impl Add for FieldElement {
    type Output = FieldElement;

    fn add(self, rhs: FieldElement) -> Self::Output {
        FieldElement::new(self.0 + rhs.0)
    }
}

impl Mul for FieldElement {
    type Output = FieldElement;

    fn mul(self, rhs: FieldElement) -> Self::Output {
        FieldElement::new(self.0 * rhs.0)
    }
}
