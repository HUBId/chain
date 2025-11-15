use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use super::{
    HardwareDevice, HardwarePublicKey, HardwareSignRequest, HardwareSignature, HardwareSigner,
    HardwareSignerError,
};
use crate::engine::DerivationPath;

#[derive(Clone, Default)]
pub struct MockHardwareSigner {
    devices: Arc<Mutex<Vec<HardwareDevice>>>,
    pubkey_responses: Arc<Mutex<VecDeque<Result<HardwarePublicKey, HardwareSignerError>>>>,
    sign_responses: Arc<Mutex<VecDeque<Result<HardwareSignature, HardwareSignerError>>>>,
    last_pubkey_request: Arc<Mutex<Option<(String, DerivationPath)>>>,
    last_sign_request: Arc<Mutex<Option<HardwareSignRequest>>>,
}

impl MockHardwareSigner {
    pub fn new(devices: Vec<HardwareDevice>) -> Self {
        Self {
            devices: Arc::new(Mutex::new(devices)),
            ..Self::default()
        }
    }

    pub fn set_devices(&self, devices: Vec<HardwareDevice>) {
        if let Ok(mut slot) = self.devices.lock() {
            *slot = devices;
        }
    }

    pub fn push_public_key_response(
        &self,
        response: Result<HardwarePublicKey, HardwareSignerError>,
    ) {
        if let Ok(mut queue) = self.pubkey_responses.lock() {
            queue.push_back(response);
        }
    }

    pub fn push_sign_response(&self, response: Result<HardwareSignature, HardwareSignerError>) {
        if let Ok(mut queue) = self.sign_responses.lock() {
            queue.push_back(response);
        }
    }

    pub fn last_public_key_request(&self) -> Option<(String, DerivationPath)> {
        self.last_pubkey_request
            .lock()
            .ok()
            .and_then(|value| value.clone())
    }

    pub fn last_sign_request(&self) -> Option<HardwareSignRequest> {
        self.last_sign_request
            .lock()
            .ok()
            .and_then(|value| value.clone())
    }

    fn take_public_key_response(&self) -> Result<HardwarePublicKey, HardwareSignerError> {
        self.pubkey_responses
            .lock()
            .ok()
            .and_then(|mut queue| queue.pop_front())
            .unwrap_or_else(|| {
                Err(HardwareSignerError::Unsupported(
                    "mock public key response not configured".into(),
                ))
            })
    }

    fn take_sign_response(&self) -> Result<HardwareSignature, HardwareSignerError> {
        self.sign_responses
            .lock()
            .ok()
            .and_then(|mut queue| queue.pop_front())
            .unwrap_or_else(|| {
                Err(HardwareSignerError::Unsupported(
                    "mock signature response not configured".into(),
                ))
            })
    }
}

impl HardwareSigner for MockHardwareSigner {
    fn enumerate(&self) -> Result<Vec<HardwareDevice>, HardwareSignerError> {
        self.devices
            .lock()
            .map(|devices| devices.clone())
            .map_err(|_| HardwareSignerError::Communication("mock poisoned".into()))
    }

    fn get_public_key(
        &self,
        fingerprint: &str,
        path: &DerivationPath,
    ) -> Result<HardwarePublicKey, HardwareSignerError> {
        if let Ok(mut slot) = self.last_pubkey_request.lock() {
            *slot = Some((fingerprint.to_string(), path.clone()));
        }
        self.take_public_key_response()
    }

    fn sign(
        &self,
        request: &HardwareSignRequest,
    ) -> Result<HardwareSignature, HardwareSignerError> {
        if let Ok(mut slot) = self.last_sign_request.lock() {
            *slot = Some(request.clone());
        }
        self.take_sign_response()
    }
}
