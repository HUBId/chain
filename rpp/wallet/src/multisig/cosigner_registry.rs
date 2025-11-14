use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cosigner {
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default)]
    pub endpoint: Option<String>,
}

impl Cosigner {
    pub fn new(
        fingerprint: impl Into<String>,
        endpoint: Option<impl Into<String>>,
    ) -> Result<Self, CosignerRegistryError> {
        let fingerprint = fingerprint.into();
        validate_fingerprint(&fingerprint)?;
        let endpoint = endpoint.map(Into::into);
        if let Some(url) = endpoint.as_ref() {
            if url.trim().is_empty() {
                return Err(CosignerRegistryError::InvalidEndpoint);
            }
        }
        Ok(Self {
            fingerprint,
            endpoint,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CosignerRegistry {
    entries: Vec<Cosigner>,
}

impl CosignerRegistry {
    pub fn new(entries: Vec<Cosigner>) -> Result<Self, CosignerRegistryError> {
        if entries.is_empty() {
            return Err(CosignerRegistryError::Empty);
        }
        let mut map = BTreeMap::new();
        for entry in entries {
            if map.insert(entry.fingerprint.clone(), entry).is_some() {
                return Err(CosignerRegistryError::DuplicateFingerprint);
            }
        }
        Ok(Self {
            entries: map.into_values().collect(),
        })
    }

    pub fn entries(&self) -> &[Cosigner] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn to_vec(&self) -> Vec<Cosigner> {
        self.entries.clone()
    }
}

fn validate_fingerprint(fingerprint: &str) -> Result<(), CosignerRegistryError> {
    if fingerprint.len() != 32 && fingerprint.len() != 64 {
        return Err(CosignerRegistryError::InvalidFingerprint);
    }
    if !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(CosignerRegistryError::InvalidFingerprint);
    }
    Ok(())
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CosignerRegistryError {
    #[error("cosigner registry must contain at least one entry")]
    Empty,
    #[error("duplicate cosigner fingerprint")]
    DuplicateFingerprint,
    #[error("invalid cosigner fingerprint")]
    InvalidFingerprint,
    #[error("invalid cosigner endpoint")]
    InvalidEndpoint,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(prefix: &str) -> String {
        let mut fp = prefix.to_owned();
        while fp.len() < 64 {
            fp.push('a');
        }
        fp.truncate(64);
        fp
    }

    #[test]
    fn registry_requires_non_empty_entries() {
        assert!(matches!(
            CosignerRegistry::new(Vec::new()),
            Err(CosignerRegistryError::Empty)
        ));
    }

    #[test]
    fn registry_rejects_duplicates() {
        let entry = Cosigner::new(fingerprint("aa"), None).expect("entry");
        assert!(matches!(
            CosignerRegistry::new(vec![entry.clone(), entry]),
            Err(CosignerRegistryError::DuplicateFingerprint)
        ));
    }

    #[test]
    fn fingerprint_validation_enforces_hex_length() {
        let invalid = fingerprint("zz");
        assert!(matches!(
            Cosigner::new(invalid, None),
            Err(CosignerRegistryError::InvalidFingerprint)
        ));
        assert!(matches!(
            Cosigner::new("aa", None),
            Err(CosignerRegistryError::InvalidFingerprint)
        ));
    }

    #[test]
    fn registry_sorts_entries() {
        let a = Cosigner::new(fingerprint("aa"), None).expect("a");
        let b = Cosigner::new(fingerprint("bb"), Some("https://b")).expect("b");
        let registry = CosignerRegistry::new(vec![b.clone(), a.clone()]).expect("registry");
        assert_eq!(registry.entries(), &[a, b]);
    }
}
