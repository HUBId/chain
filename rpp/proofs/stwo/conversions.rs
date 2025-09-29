//! Shared helpers for converting blueprint field elements into official STWO representations.

use super::params::FieldElement;
use stwo::stwo_official::core::fields::m31::BaseField;
use stwo::stwo_official::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};

/// Canonical 128-bit representation of a blueprint field element.
pub fn field_bytes(value: &FieldElement) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    let repr = value.to_bytes();
    let copy_len = repr.len().min(bytes.len());
    let start = bytes.len() - copy_len;
    bytes[start..].copy_from_slice(&repr[repr.len() - copy_len..]);
    bytes
}

/// Convert a blueprint field element into the official base field representation.
pub fn field_to_base(value: &FieldElement) -> BaseField {
    let bytes = field_bytes(value);
    BaseField::from(u32::from_be_bytes(
        bytes[bytes.len() - 4..]
            .try_into()
            .expect("slice length is 4"),
    ))
}

/// Convert a blueprint field element into the official secure field representation.
pub fn field_to_secure(value: &FieldElement) -> SecureField {
    let bytes = field_bytes(value);
    let mut limbs = [BaseField::from(0u32); SECURE_EXTENSION_DEGREE];
    for (idx, chunk) in bytes.chunks(4).take(SECURE_EXTENSION_DEGREE).enumerate() {
        let limb = u32::from_be_bytes(chunk.try_into().expect("slice length is 4"));
        limbs[idx] = BaseField::from(limb);
    }
    SecureField::from_m31_array(limbs)
}

/// Convert an iterator over blueprint field elements into base field values.
pub fn column_to_base<'a, I>(column: I) -> Vec<BaseField>
where
    I: IntoIterator<Item = &'a FieldElement>,
{
    column.into_iter().map(field_to_base).collect()
}

/// Convert an iterator over blueprint field elements into secure field values.
pub fn column_to_secure<'a, I>(column: I) -> Vec<SecureField>
where
    I: IntoIterator<Item = &'a FieldElement>,
{
    column.into_iter().map(field_to_secure).collect()
}
