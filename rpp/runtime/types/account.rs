use std::fmt;
use std::ops::{AddAssign, SubAssign};
use std::str::FromStr;

use malachite::Natural;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::{address_from_public_key, public_key_from_hex};
use crate::errors::{ChainError, ChainResult};
use crate::reputation::ReputationProfile;
use hex;

use super::Address;

use stwo::core::vcs::blake2_hash::Blake2sHasher;

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct IdentityBinding {
    pub wallet_public_key: Option<String>,
    pub node_address: Option<Address>,
}

impl IdentityBinding {
    pub fn ensure_wallet_key(
        &mut self,
        account_address: &Address,
        wallet_public_key_hex: &str,
    ) -> ChainResult<String> {
        let public_key = public_key_from_hex(wallet_public_key_hex)?;
        let derived_address = address_from_public_key(&public_key);
        if &derived_address != account_address {
            return Err(ChainError::Transaction(
                "public key does not match wallet address".into(),
            ));
        }
        if let Some(existing) = &self.wallet_public_key {
            if existing != wallet_public_key_hex {
                return Err(ChainError::Transaction(
                    "wallet already bound to a different public key".into(),
                ));
            }
        } else {
            self.wallet_public_key = Some(wallet_public_key_hex.to_string());
        }
        let commitment: [u8; 32] = Blake2sHasher::hash(&public_key.to_bytes()).into();
        Ok(hex::encode(commitment))
    }

    pub fn ensure_node_binding(
        &mut self,
        account_address: &Address,
        node_address: &Address,
    ) -> ChainResult<()> {
        if node_address != account_address {
            return Err(ChainError::Config(
                "node identity must match wallet address".into(),
            ));
        }
        if let Some(existing) = &self.node_address {
            if existing != node_address {
                return Err(ChainError::Config(
                    "node already bound to a different identity".into(),
                ));
            }
            return Ok(());
        }
        self.node_address = Some(node_address.clone());
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct WalletBindingChange {
    pub previous: Option<String>,
    pub current: String,
}

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

    pub fn slash_percent(&mut self, percent: u8) {
        if percent == 0 {
            return;
        }
        if percent >= 100 {
            self.inner = Natural::from(0u32);
            return;
        }
        let hundred = Natural::from(100u32);
        let keep = hundred.clone() - Natural::from(percent as u32);
        self.inner = (self.inner.clone() * keep) / hundred;
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
    #[serde(default)]
    pub identity: IdentityBinding,
    pub reputation: ReputationProfile,
}

impl Account {
    pub fn new(address: Address, balance: u128, stake: Stake) -> Self {
        let reputation = ReputationProfile::new(address.as_str());
        Self {
            address,
            balance,
            nonce: 0,
            stake,
            identity: IdentityBinding::default(),
            reputation,
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

    pub fn ensure_wallet_binding(
        &mut self,
        wallet_public_key_hex: &str,
    ) -> ChainResult<WalletBindingChange> {
        let commitment = self
            .identity
            .ensure_wallet_key(&self.address, wallet_public_key_hex)?;
        if self.reputation.zsi.public_key_commitment == commitment {
            return Ok(WalletBindingChange {
                previous: Some(commitment.clone()),
                current: commitment,
            });
        }
        if self.reputation.zsi.validated {
            return Err(ChainError::Transaction(
                "wallet public key does not match validated identity".into(),
            ));
        }
        let previous = std::mem::replace(
            &mut self.reputation.zsi.public_key_commitment,
            commitment.clone(),
        );
        Ok(WalletBindingChange {
            previous: Some(previous),
            current: commitment,
        })
    }

    pub fn bind_node_identity(&mut self) -> ChainResult<()> {
        self.identity
            .ensure_node_binding(&self.address, &self.address)
    }
}
