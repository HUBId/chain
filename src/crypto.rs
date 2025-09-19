use std::fs;
use std::path::Path;

use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use stwo::core::vcs::blake2_hash::Blake2sHasher;

use crate::errors::{ChainError, ChainResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKeypair {
    pub public_key: String,
    pub secret_key: String,
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
