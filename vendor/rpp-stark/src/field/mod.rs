//! Field arithmetic primitives for the `rpp-stark` proof system.
//! Contains finite field implementations and polynomial utilities.

pub mod polynomial;
pub mod prime_field;

pub use prime_field::FieldElement;

#[cfg(test)]
pub mod tests;
