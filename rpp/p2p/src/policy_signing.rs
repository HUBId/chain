use std::collections::HashMap;
use std::convert::TryInto;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const SIGNATURE_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum PolicySigningError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("signing key mismatch for active key {key_id}")]
    SigningKeyMismatch { key_id: String },
    #[error("unknown signing key id {0}")]
    UnknownKey(String),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicySignature {
    pub version: u32,
    pub key_id: String,
    pub value: String,
}

impl PolicySignature {
    pub fn new(key_id: String, value: String) -> Self {
        Self {
            version: SIGNATURE_VERSION,
            key_id,
            value,
        }
    }

    pub fn signature(&self) -> Result<Signature, PolicySigningError> {
        let bytes = hex::decode(&self.value).map_err(|err| {
            PolicySigningError::Encoding(format!("invalid signature encoding: {err}"))
        })?;
        Signature::from_bytes(&bytes)
            .map_err(|err| PolicySigningError::Encoding(format!("invalid signature bytes: {err}")))
    }
}

#[derive(Clone)]
pub struct PolicyTrustStore {
    keys: Arc<HashMap<String, VerifyingKey>>,
}

impl PolicyTrustStore {
    pub fn from_hex(keys: HashMap<String, String>) -> Result<Self, PolicySigningError> {
        let mut parsed = HashMap::with_capacity(keys.len());
        for (key_id, value) in keys {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(PolicySigningError::Encoding(format!(
                    "signing trust store entry `{key_id}` must not be empty"
                )));
            }
            let bytes = hex::decode(trimmed).map_err(|err| {
                PolicySigningError::Encoding(format!(
                    "invalid signing public key encoding for `{key_id}`: {err}"
                ))
            })?;
            let verifying = VerifyingKey::from_bytes(&bytes.try_into().map_err(|_| {
                PolicySigningError::Encoding(format!(
                    "signing public key `{key_id}` must encode 32 bytes"
                ))
            })?)
            .map_err(|err| {
                PolicySigningError::Encoding(format!(
                    "invalid signing public key bytes for `{key_id}`: {err}"
                ))
            })?;
            parsed.insert(key_id, verifying);
        }
        Ok(Self {
            keys: Arc::new(parsed),
        })
    }

    pub fn verifying_key(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(key_id)
    }

    pub fn contains(&self, key_id: &str) -> bool {
        self.keys.contains_key(key_id)
    }
}

#[derive(Clone)]
pub struct PolicySignatureVerifier {
    trust: PolicyTrustStore,
}

impl PolicySignatureVerifier {
    pub fn new(trust: PolicyTrustStore) -> Self {
        Self { trust }
    }

    pub fn verify(
        &self,
        signature: &PolicySignature,
        message: &[u8],
    ) -> Result<(), PolicySigningError> {
        let verifying = self
            .trust
            .verifying_key(&signature.key_id)
            .ok_or_else(|| PolicySigningError::UnknownKey(signature.key_id.clone()))?;
        verifying
            .verify(message, &signature.signature()?)
            .map_err(|err| PolicySigningError::InvalidSignature(err.to_string()))
    }

    pub fn trust_store(&self) -> &PolicyTrustStore {
        &self.trust
    }
}

#[derive(Clone)]
pub struct PolicySigner {
    active_key: String,
    key_source: PolicyKeySource,
    verifier: PolicySignatureVerifier,
}

#[derive(Clone)]
enum PolicyKeySource {
    File(PathBuf),
}

impl PolicySigner {
    pub fn with_filesystem_key(
        active_key: String,
        key_path: PathBuf,
        trust: PolicyTrustStore,
    ) -> Result<Self, PolicySigningError> {
        let verifier = PolicySignatureVerifier::new(trust);
        if !verifier.trust_store().contains(&active_key) {
            return Err(PolicySigningError::UnknownKey(active_key));
        }
        Ok(Self {
            active_key,
            key_source: PolicyKeySource::File(key_path),
            verifier,
        })
    }

    pub fn verifier(&self) -> &PolicySignatureVerifier {
        &self.verifier
    }

    pub fn active_key(&self) -> &str {
        &self.active_key
    }

    pub fn sign(&self, message: &[u8]) -> Result<PolicySignature, PolicySigningError> {
        let signing_key = self.load_signing_key()?;
        let signature = signing_key.sign(message);
        let verifying = signing_key.verifying_key();
        let trusted = self
            .verifier
            .trust_store()
            .verifying_key(&self.active_key)
            .ok_or_else(|| PolicySigningError::UnknownKey(self.active_key.clone()))?;
        if verifying != *trusted {
            return Err(PolicySigningError::SigningKeyMismatch {
                key_id: self.active_key.clone(),
            });
        }
        Ok(PolicySignature::new(
            self.active_key.clone(),
            hex::encode(signature.to_bytes()),
        ))
    }

    pub fn verify(
        &self,
        signature: &PolicySignature,
        message: &[u8],
    ) -> Result<(), PolicySigningError> {
        self.verifier.verify(signature, message)
    }

    fn load_signing_key(&self) -> Result<SigningKey, PolicySigningError> {
        match &self.key_source {
            PolicyKeySource::File(path) => load_signing_key(path),
        }
    }
}

fn load_signing_key(path: &Path) -> Result<SigningKey, PolicySigningError> {
    let raw = fs::read_to_string(path)?;
    let stored: StoredSigningKey = toml::from_str(&raw).map_err(|err| {
        PolicySigningError::Encoding(format!("failed to decode signing key: {err}"))
    })?;
    let secret_bytes = hex::decode(&stored.secret_key).map_err(|err| {
        PolicySigningError::Encoding(format!("invalid signing key encoding: {err}"))
    })?;
    let secret: [u8; 32] = secret_bytes
        .try_into()
        .map_err(|_| PolicySigningError::Encoding("signing key must be 32 bytes".into()))?;
    let signing = SigningKey::from_bytes(&secret)
        .map_err(|err| PolicySigningError::Encoding(format!("invalid signing key bytes: {err}")))?;
    if let Some(public_hex) = stored.public_key.as_deref() {
        let public_bytes = hex::decode(public_hex).map_err(|err| {
            PolicySigningError::Encoding(format!("invalid signing public key encoding: {err}"))
        })?;
        let public: [u8; 32] = public_bytes
            .try_into()
            .map_err(|_| PolicySigningError::Encoding("public key must be 32 bytes".into()))?;
        let expected = VerifyingKey::from_bytes(&public).map_err(|err| {
            PolicySigningError::Encoding(format!("invalid signing public key bytes: {err}"))
        })?;
        if expected != signing.verifying_key() {
            return Err(PolicySigningError::Encoding(
                "signing keypair mismatch between secret and public key".into(),
            ));
        }
    }
    Ok(signing)
}

#[derive(Debug, Deserialize)]
struct StoredSigningKey {
    pub secret_key: String,
    #[allow(dead_code)]
    pub public_key: Option<String>,
}
