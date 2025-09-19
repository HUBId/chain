use std::fmt;
use std::ops::{AddAssign, SubAssign};
use std::str::FromStr;

use malachite::Natural;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::Address;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stake {
    inner: Natural,
}

impl Stake {
    pub fn zero() -> Self {
        Self {
            inner: Natural::from(0u32),
        }
    }

    pub fn from_natural(inner: Natural) -> Self {
        Self { inner }
    }

    pub fn from_u128(value: u128) -> Self {
        Self {
            inner: Natural::from(value),
        }
    }

    pub fn as_natural(&self) -> &Natural {
        &self.inner
    }

    pub fn add_assign(&mut self, other: &Stake) {
        self.inner.add_assign(other.inner.clone());
    }

    pub fn saturating_sub(&mut self, other: &Stake) {
        if self.inner >= other.inner {
            self.inner.sub_assign(other.inner.clone());
        } else {
            self.inner = Natural::from(0u32);
        }
    }

    pub fn to_string(&self) -> String {
        self.inner.to_string()
    }
}

impl Default for Stake {
    fn default() -> Self {
        Self::zero()
    }
}

impl FromStr for Stake {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Natural::from_str(s).map(Stake::from_natural)
    }
}

impl Serialize for Stake {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.inner.to_string())
    }
}

impl<'de> Deserialize<'de> for Stake {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Natural::from_str(&value)
            .map(Stake::from_natural)
            .map_err(|_| serde::de::Error::custom("invalid stake value"))
    }
}

impl fmt::Display for Stake {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    pub address: Address,
    pub balance: u128,
    pub nonce: u64,
    pub stake: Stake,
}

impl Account {
    pub fn new(address: Address, balance: u128, stake: Stake) -> Self {
        Self {
            address,
            balance,
            nonce: 0,
            stake,
        }
    }

    pub fn credit(&mut self, amount: u128) {
        self.balance = self.balance.saturating_add(amount);
    }

    pub fn debit(&mut self, amount: u128) -> bool {
        if self.balance >= amount {
            self.balance -= amount;
            true
        } else {
            false
        }
    }
}
