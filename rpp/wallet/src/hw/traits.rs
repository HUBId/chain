use crate::engine::DerivationPath;
use zeroize::Zeroize;

/// Metadata describing a hardware signing device discovered by the wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardwareDevice {
    pub fingerprint: String,
    pub model: String,
    pub label: Option<String>,
}

impl HardwareDevice {
    pub fn new(fingerprint: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            fingerprint: fingerprint.into(),
            model: model.into(),
            label: None,
        }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

/// Public key material returned by a hardware device for a derivation path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardwarePublicKey {
    pub fingerprint: String,
    pub path: DerivationPath,
    pub public_key: Vec<u8>,
}

impl HardwarePublicKey {
    pub fn new(
        fingerprint: impl Into<String>,
        path: DerivationPath,
        public_key: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            fingerprint: fingerprint.into(),
            path,
            public_key: public_key.into(),
        }
    }
}

/// Signing intent submitted to a hardware device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardwareSignRequest {
    pub fingerprint: String,
    pub path: DerivationPath,
    pub payload: Vec<u8>,
}

impl Zeroize for HardwareSignRequest {
    fn zeroize(&mut self) {
        self.payload.zeroize();
    }
}

impl Drop for HardwareSignRequest {
    fn drop(&mut self) {
        self.zeroize();
        debug_assert!(
            self.payload.iter().all(|byte| *byte == 0),
            "hardware signing payload should be zeroized",
        );
    }
}

impl HardwareSignRequest {
    pub fn new(
        fingerprint: impl Into<String>,
        path: DerivationPath,
        payload: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            fingerprint: fingerprint.into(),
            path,
            payload: payload.into(),
        }
    }
}

/// Signature returned by a hardware device together with supporting metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardwareSignature {
    pub fingerprint: String,
    pub path: DerivationPath,
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl HardwareSignature {
    pub fn new(
        fingerprint: impl Into<String>,
        path: DerivationPath,
        signature: impl Into<Vec<u8>>,
        public_key: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            fingerprint: fingerprint.into(),
            path,
            signature: signature.into(),
            public_key: public_key.into(),
        }
    }
}

/// Errors surfaced by hardware signing backends.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum HardwareSignerError {
    #[error("hardware device `{fingerprint}` not found")]
    DeviceNotFound { fingerprint: String },
    #[error("hardware device `{fingerprint}` does not support derivation path {path}")]
    PathUnsupported {
        fingerprint: String,
        path: DerivationPath,
    },
    #[error("hardware device rejected request: {reason}")]
    Rejected { reason: String },
    #[error("hardware communication error: {0}")]
    Communication(String),
    #[error("hardware operation unsupported: {0}")]
    Unsupported(String),
}

impl HardwareSignerError {
    pub fn rejected(reason: impl Into<String>) -> Self {
        let reason = reason.into();
        let reason = if reason.is_empty() {
            "rejected by user".to_string()
        } else {
            reason
        };
        Self::Rejected { reason }
    }
}

/// Trait implemented by hardware signing backends.
pub trait HardwareSigner: Send + Sync {
    fn enumerate(&self) -> Result<Vec<HardwareDevice>, HardwareSignerError>;
    fn get_public_key(
        &self,
        fingerprint: &str,
        path: &DerivationPath,
    ) -> Result<HardwarePublicKey, HardwareSignerError>;
    fn sign(&self, request: &HardwareSignRequest)
        -> Result<HardwareSignature, HardwareSignerError>;
}
