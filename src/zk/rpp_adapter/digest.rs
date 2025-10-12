#![cfg(feature = "backend-rpp-stark")]

use core::fmt;
use core::str::FromStr;
use std::array::TryFromSliceError;

/// Fixed-size 32-byte digest matching the expectations of `rpp-stark`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Digest32(pub [u8; 32]);

impl Digest32 {
    /// Length in bytes for the digest.
    pub const LENGTH: usize = 32;

    /// Creates a digest from a hexadecimal string.
    pub fn from_hex(hex_str: &str) -> Result<Self, ParseDigestError> {
        let bytes = hex::decode(hex_str).map_err(ParseDigestError::InvalidHex)?;
        Self::try_from(bytes.as_slice()).map_err(ParseDigestError::InvalidLength)
    }

    /// Returns the digest as a lowercase hexadecimal string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Returns the inner byte array by reference.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the digest and returns the underlying bytes.
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest32(0x{})", self.to_hex())
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl From<[u8; 32]> for Digest32 {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

impl From<Digest32> for [u8; 32] {
    fn from(value: Digest32) -> Self {
        value.0
    }
}

impl TryFrom<&[u8]> for Digest32 {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 32]>::try_from(value).map(Self)
    }
}

impl TryFrom<Vec<u8>> for Digest32 {
    type Error = TryFromSliceError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        <[u8; 32]>::try_from(value.as_slice()).map(Self)
    }
}

impl FromStr for Digest32 {
    type Err = ParseDigestError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

/// Errors that can occur while parsing a [`Digest32`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseDigestError {
    #[error("digest hex string has invalid length: expected 64 hex chars")]
    InvalidLength(TryFromSliceError),
    #[error("invalid digest hex: {0}")]
    InvalidHex(hex::FromHexError),
}
