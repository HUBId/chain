#![cfg(feature = "backend-rpp-stark")]

use core::fmt;
use core::ops::{Deref, DerefMut};

/// Thin wrapper around the `rpp_stark` field element type.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Felt(pub rpp_stark::felt::Felt);

impl Felt {
    /// Returns a shared reference to the underlying `rpp_stark` field element.
    #[inline]
    pub const fn as_inner(&self) -> &rpp_stark::felt::Felt {
        &self.0
    }

    /// Consumes the wrapper and returns the inner field element.
    #[inline]
    pub const fn into_inner(self) -> rpp_stark::felt::Felt {
        self.0
    }
}

impl From<rpp_stark::felt::Felt> for Felt {
    #[inline]
    fn from(value: rpp_stark::felt::Felt) -> Self {
        Self(value)
    }
}

impl From<Felt> for rpp_stark::felt::Felt {
    #[inline]
    fn from(value: Felt) -> Self {
        value.0
    }
}

impl Deref for Felt {
    type Target = rpp_stark::felt::Felt;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Felt {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl fmt::Debug for Felt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for Felt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
