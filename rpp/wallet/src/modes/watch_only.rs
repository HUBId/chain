use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::proof_backend::Blake2sHasher;

const WATCH_ONLY_SEED_DOMAIN: &[u8] = b"rpp::wallet::watch_only::seed";

fn debug_assert_zeroized(buf: &[u8]) {
    debug_assert!(
        buf.iter().all(|byte| *byte == 0),
        "watch-only seed material should be zeroized",
    );
}

/// Persisted configuration describing a watch-only wallet mode.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchOnlyRecord {
    pub external_descriptor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub internal_descriptor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_xpub: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birthday_height: Option<u64>,
}

impl WatchOnlyRecord {
    pub fn new(external_descriptor: impl Into<String>) -> Self {
        Self {
            external_descriptor: external_descriptor.into(),
            internal_descriptor: None,
            account_xpub: None,
            birthday_height: None,
        }
    }

    pub fn with_internal_descriptor(mut self, descriptor: impl Into<String>) -> Self {
        self.internal_descriptor = Some(descriptor.into());
        self
    }

    pub fn with_account_xpub(mut self, xpub: impl Into<String>) -> Self {
        self.account_xpub = Some(xpub.into());
        self
    }

    pub fn with_birthday_height(mut self, height: Option<u64>) -> Self {
        self.birthday_height = height;
        self
    }

    /// Deterministically derive a seed used by the wallet engine for address
    /// tracking when running in watch-only mode.
    pub fn derive_seed(&self) -> [u8; 32] {
        let mut material = Zeroizing::new(Vec::new());
        material.extend_from_slice(WATCH_ONLY_SEED_DOMAIN);
        material.extend_from_slice(self.external_descriptor.as_bytes());
        if let Some(internal) = &self.internal_descriptor {
            material.extend_from_slice(b"::internal::");
            material.extend_from_slice(internal.as_bytes());
        }
        if let Some(xpub) = &self.account_xpub {
            material.extend_from_slice(b"::account::");
            material.extend_from_slice(xpub.as_bytes());
        }
        if let Some(height) = self.birthday_height {
            material.extend_from_slice(b"::birthday::");
            material.extend_from_slice(&height.to_be_bytes());
        }
        let seed = Blake2sHasher::hash(material.as_slice()).into();
        material.zeroize();
        debug_assert_zeroized(material.as_slice());
        seed
    }
}

/// Snapshot describing the current watch-only status of the wallet.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WatchOnlyStatus {
    pub enabled: bool,
    pub external_descriptor: Option<String>,
    pub internal_descriptor: Option<String>,
    pub account_xpub: Option<String>,
    pub birthday_height: Option<u64>,
}

impl From<Option<WatchOnlyRecord>> for WatchOnlyStatus {
    fn from(record: Option<WatchOnlyRecord>) -> Self {
        match record {
            Some(record) => Self {
                enabled: true,
                external_descriptor: Some(record.external_descriptor),
                internal_descriptor: record.internal_descriptor,
                account_xpub: record.account_xpub,
                birthday_height: record.birthday_height,
            },
            None => Self::default(),
        }
    }
}
