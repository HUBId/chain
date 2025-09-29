use std::convert::TryFrom;
use std::fs;
use std::path::Path;

use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use schnorrkel::SignatureError as VrfSignatureError;
use schnorrkel::keys::{
    ExpansionMode, Keypair as VrfKeypairInner, MiniSecretKey, PublicKey as SrPublicKey,
};
use serde::{Deserialize, Serialize};
use crate::proof_backend::Blake2sHasher;

use crate::errors::{ChainError, ChainResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKeypair {
    pub public_key: String,
    pub secret_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredVrfKeypair {
    pub public_key: String,
    pub secret_key: String,
}

#[derive(Debug, Clone)]
pub struct VrfSecretKey {
    inner: MiniSecretKey,
}

impl VrfSecretKey {
    pub fn new(inner: MiniSecretKey) -> Self {
        Self { inner }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub fn as_mini_secret(&self) -> &MiniSecretKey {
        &self.inner
    }

    pub fn expand_to_keypair(&self) -> VrfKeypairInner {
        self.inner.expand_to_keypair(ExpansionMode::Uniform)
    }

    pub fn derive_public(&self) -> VrfPublicKey {
        VrfPublicKey {
            inner: self.expand_to_keypair().public,
        }
    }
}

impl TryFrom<[u8; 32]> for VrfSecretKey {
    type Error = VrfSignatureError;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        MiniSecretKey::from_bytes(&bytes).map(VrfSecretKey::new)
    }
}

#[derive(Debug, Clone)]
pub struct VrfPublicKey {
    inner: SrPublicKey,
}

impl VrfPublicKey {
    pub fn new(inner: SrPublicKey) -> Self {
        Self { inner }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub fn as_public_key(&self) -> &SrPublicKey {
        &self.inner
    }
}

impl TryFrom<[u8; 32]> for VrfPublicKey {
    type Error = VrfSignatureError;

    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        SrPublicKey::from_bytes(&bytes).map(VrfPublicKey::new)
    }
}

#[derive(Debug, Clone)]
pub struct VrfKeypair {
    pub public: VrfPublicKey,
    pub secret: VrfSecretKey,
}

pub fn generate_keypair() -> Keypair {
    Keypair::generate(&mut OsRng)
}

pub fn load_or_generate_keypair(path: &Path) -> ChainResult<Keypair> {
    if path.exists() {
        load_keypair(path)
    } else {
        let keypair = generate_keypair();
        save_keypair(path, &keypair)?;
        Ok(keypair)
    }
}

pub fn save_keypair(path: &Path, keypair: &Keypair) -> ChainResult<()> {
    let stored = StoredKeypair {
        public_key: hex::encode(keypair.public.to_bytes()),
        secret_key: hex::encode(keypair.secret.to_bytes()),
    };
    let encoded = toml::to_string_pretty(&stored)
        .map_err(|err| ChainError::Config(format!("failed to encode keypair: {err}")))?;
    fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")))?;
    fs::write(path, encoded)?;
    Ok(())
}

pub fn load_keypair(path: &Path) -> ChainResult<Keypair> {
    let raw = fs::read_to_string(path)?;
    let stored: StoredKeypair = toml::from_str(&raw)
        .map_err(|err| ChainError::Config(format!("failed to decode keypair: {err}")))?;
    let secret_bytes = hex::decode(stored.secret_key)
        .map_err(|err| ChainError::Config(format!("invalid secret key encoding: {err}")))?;
    let public_bytes = hex::decode(stored.public_key)
        .map_err(|err| ChainError::Config(format!("invalid public key encoding: {err}")))?;
    let secret = SecretKey::from_bytes(&secret_bytes)
        .map_err(|err| ChainError::Config(format!("invalid secret key bytes: {err}")))?;
    let public = PublicKey::from_bytes(&public_bytes)
        .map_err(|err| ChainError::Config(format!("invalid public key bytes: {err}")))?;
    Ok(Keypair { secret, public })
}

pub fn sign_message(keypair: &Keypair, message: &[u8]) -> Signature {
    keypair.sign(message)
}

pub fn verify_signature(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> ChainResult<()> {
    public_key
        .verify(message, signature)
        .map_err(|err| ChainError::Crypto(format!("signature verification failed: {err}")))
}

pub fn address_from_public_key(public_key: &PublicKey) -> String {
    let hash = Blake2sHasher::hash(public_key.as_bytes());
    hex::encode::<[u8; 32]>(hash.into())
}

pub fn public_key_from_hex(data: &str) -> ChainResult<PublicKey> {
    let bytes = hex::decode(data)
        .map_err(|err| ChainError::Config(format!("invalid public key encoding: {err}")))?;
    PublicKey::from_bytes(&bytes)
        .map_err(|err| ChainError::Config(format!("invalid public key bytes: {err}")))
}

pub fn signature_from_hex(data: &str) -> ChainResult<Signature> {
    let bytes = hex::decode(data)
        .map_err(|err| ChainError::Config(format!("invalid signature encoding: {err}")))?;
    Signature::from_bytes(&bytes)
        .map_err(|err| ChainError::Config(format!("invalid signature bytes: {err}")))
}

pub fn signature_to_hex(signature: &Signature) -> String {
    hex::encode(signature.to_bytes())
}

fn derive_vrf_public(secret: &VrfSecretKey) -> VrfPublicKey {
    secret.derive_public()
}

pub fn generate_vrf_keypair() -> ChainResult<VrfKeypair> {
    let secret = MiniSecretKey::generate();
    let secret = VrfSecretKey::new(secret);
    let public = derive_vrf_public(&secret);
    Ok(VrfKeypair { public, secret })
}

pub fn load_or_generate_vrf_keypair(path: &Path) -> ChainResult<VrfKeypair> {
    if path.exists() {
        load_vrf_keypair(path)
    } else {
        let keypair = generate_vrf_keypair()?;
        save_vrf_keypair(path, &keypair)?;
        Ok(keypair)
    }
}

pub fn save_vrf_keypair(path: &Path, keypair: &VrfKeypair) -> ChainResult<()> {
    let stored = StoredVrfKeypair {
        public_key: hex::encode(keypair.public.to_bytes()),
        secret_key: hex::encode(keypair.secret.to_bytes()),
    };
    let encoded = toml::to_string_pretty(&stored)
        .map_err(|err| ChainError::Config(format!("failed to encode VRF keypair: {err}")))?;
    fs::create_dir_all(path.parent().unwrap_or_else(|| Path::new(".")))?;
    fs::write(path, encoded)?;
    Ok(())
}

pub fn load_vrf_keypair(path: &Path) -> ChainResult<VrfKeypair> {
    let raw = fs::read_to_string(path)?;
    let stored: StoredVrfKeypair = toml::from_str(&raw)
        .map_err(|err| ChainError::Config(format!("failed to decode VRF keypair: {err}")))?;
    let secret_vec = hex::decode(stored.secret_key)
        .map_err(|err| ChainError::Config(format!("invalid VRF secret key encoding: {err}")))?;
    let public_vec = hex::decode(stored.public_key)
        .map_err(|err| ChainError::Config(format!("invalid VRF public key encoding: {err}")))?;
    let secret_bytes: [u8; 32] = secret_vec
        .try_into()
        .map_err(|_| ChainError::Config("invalid VRF secret key length".to_string()))?;
    let public_bytes: [u8; 32] = public_vec
        .try_into()
        .map_err(|_| ChainError::Config("invalid VRF public key length".to_string()))?;
    let secret = VrfSecretKey::try_from(secret_bytes)
        .map_err(|err| ChainError::Config(format!("invalid VRF secret key bytes: {err}")))?;
    let public = match VrfPublicKey::try_from(public_bytes) {
        Ok(key) => key,
        Err(_) => {
            return Err(ChainError::Config(
                "VRF public key mismatch; regenerate the VRF keypair".to_string(),
            ));
        }
    };
    let derived_public = derive_vrf_public(&secret);
    if derived_public.to_bytes() != public.to_bytes() {
        return Err(ChainError::Config(
            "VRF public key mismatch; regenerate the VRF keypair".to_string(),
        ));
    }
    Ok(VrfKeypair { public, secret })
}

pub fn vrf_public_key_from_hex(data: &str) -> ChainResult<VrfPublicKey> {
    let bytes = hex::decode(data)
        .map_err(|err| ChainError::Config(format!("invalid VRF public key encoding: {err}")))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ChainError::Config("invalid VRF public key length".to_string()))?;
    VrfPublicKey::try_from(bytes)
        .map_err(|err| ChainError::Config(format!("invalid VRF public key bytes: {err}")))
}

pub fn vrf_secret_key_from_hex(data: &str) -> ChainResult<VrfSecretKey> {
    let bytes = hex::decode(data)
        .map_err(|err| ChainError::Config(format!("invalid VRF secret key encoding: {err}")))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ChainError::Config("invalid VRF secret key length".to_string()))?;
    VrfSecretKey::try_from(bytes)
        .map_err(|err| ChainError::Config(format!("invalid VRF secret key bytes: {err}")))
}

pub fn vrf_public_key_to_hex(key: &VrfPublicKey) -> String {
    hex::encode(key.to_bytes())
}

pub fn vrf_secret_key_to_hex(key: &VrfSecretKey) -> String {
    hex::encode(key.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    use tempfile::tempdir;

    fn read_stored_keypair(path: &Path) -> StoredVrfKeypair {
        let raw = fs::read_to_string(path).expect("read vrf keypair file");
        toml::from_str(&raw).expect("decode vrf keypair")
    }

    fn write_stored_keypair(path: &Path, stored: &StoredVrfKeypair) {
        let encoded = toml::to_string_pretty(stored).expect("encode vrf keypair");
        fs::write(path, encoded).expect("write vrf keypair");
    }

    #[test]
    fn vrf_keypair_can_be_persisted_and_reloaded() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("vrf.toml");

        let original = generate_vrf_keypair().expect("generate vrf keypair");
        save_vrf_keypair(&path, &original).expect("save vrf keypair");

        let loaded = load_vrf_keypair(&path).expect("load vrf keypair");
        assert_eq!(original.public.to_bytes(), loaded.public.to_bytes());
        assert_eq!(original.secret.to_bytes(), loaded.secret.to_bytes());
    }

    #[test]
    fn load_vrf_keypair_detects_public_secret_mismatch() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("vrf.toml");

        let keypair = generate_vrf_keypair().expect("generate vrf keypair");
        save_vrf_keypair(&path, &keypair).expect("save vrf keypair");

        let mut stored = read_stored_keypair(&path);
        let mut corrupted_public = keypair.public.to_bytes();
        corrupted_public[0] ^= 0xFF;
        stored.public_key = hex::encode(corrupted_public);
        write_stored_keypair(&path, &stored);

        let err = load_vrf_keypair(&path).expect_err("mismatched keypair should fail");
        match err {
            ChainError::Config(message) => {
                assert!(message.contains("VRF public key mismatch"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn load_or_generate_vrf_keypair_reuses_existing_material() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("vrf.toml");

        let first = load_or_generate_vrf_keypair(&path).expect("initial vrf keypair");
        let second = load_or_generate_vrf_keypair(&path).expect("reused vrf keypair");

        assert_eq!(first.public.to_bytes(), second.public.to_bytes());
        assert_eq!(first.secret.to_bytes(), second.secret.to_bytes());
    }

    #[test]
    fn vrf_hex_helpers_roundtrip() {
        let keypair = generate_vrf_keypair().expect("generate vrf keypair");

        let public_hex = vrf_public_key_to_hex(&keypair.public);
        let parsed_public = vrf_public_key_from_hex(&public_hex).expect("parse public hex");
        assert_eq!(parsed_public.to_bytes(), keypair.public.to_bytes());

        let secret_hex = vrf_secret_key_to_hex(&keypair.secret);
        let parsed_secret = vrf_secret_key_from_hex(&secret_hex).expect("parse secret hex");
        assert_eq!(parsed_secret.to_bytes(), keypair.secret.to_bytes());
    }
}
