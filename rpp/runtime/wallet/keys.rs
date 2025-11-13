use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use argon2::{Algorithm, Argon2, Params, ParamsBuilder, PasswordHasher, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, Key, KeyInit, Nonce};
use ed25519_dalek::{Keypair, PublicKey, SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{generate_keypair, load_keypair, save_keypair};
use crate::errors::{ChainError, ChainResult};

const KEYSTORE_VERSION: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SYMMETRIC_KEY_LEN: usize = 32;
const ARGON2_MEMORY_COST_KIB: u32 = 64 * 1024;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const CIPHER_ALGORITHM: &str = "chacha20poly1305";
const KDF_ALGORITHM: &str = "argon2id";

fn assert_zeroized(buf: &[u8]) {
    debug_assert!(buf.iter().all(|byte| *byte == 0));
}

/// Abstraction over key management for the wallet runtime.
pub trait WalletKeyProvider: Send + Sync {
    /// Loads a keypair or generates a fresh one if it does not exist.
    fn load_or_generate(&self) -> ChainResult<Keypair>;

    /// Persists a newly generated keypair if supported by the backend.
    fn persist(&self, keypair: &Keypair) -> ChainResult<()> {
        let _ = keypair;
        Ok(())
    }
}

type PassphraseCallback = dyn Fn() -> ChainResult<Zeroizing<Vec<u8>>> + Send + Sync;

#[derive(Clone)]
enum PassphraseSource {
    None,
    Static(Arc<Zeroizing<Vec<u8>>>),
    Callback(Arc<PassphraseCallback>),
}

impl std::fmt::Debug for PassphraseSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PassphraseSource::None => f.write_str("None"),
            PassphraseSource::Static(_) => f.write_str("Static"),
            PassphraseSource::Callback(_) => f.write_str("Callback"),
        }
    }
}

/// File-backed wallet key provider.
#[derive(Clone)]
pub struct FileWalletKeyProvider {
    path: PathBuf,
    passphrase: PassphraseSource,
}

impl std::fmt::Debug for FileWalletKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileWalletKeyProvider")
            .field("path", &self.path)
            .finish()
    }
}

impl FileWalletKeyProvider {
    /// Creates a new provider rooted at the supplied filesystem path.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            passphrase: PassphraseSource::None,
        }
    }

    /// Configures the provider with a static passphrase supplied directly by the caller.
    pub fn with_passphrase_bytes(mut self, passphrase: Zeroizing<Vec<u8>>) -> Self {
        self.passphrase = PassphraseSource::Static(Arc::new(passphrase));
        self
    }

    /// Configures the provider with a static UTF-8 passphrase supplied directly by the caller.
    pub fn with_passphrase(mut self, passphrase: impl Into<String>) -> Self {
        let bytes = Zeroizing::new(passphrase.into().into_bytes());
        self.passphrase = PassphraseSource::Static(Arc::new(bytes));
        self
    }

    /// Configures the provider to acquire the passphrase from the specified environment variable.
    pub fn with_passphrase_from_env(mut self, var: impl Into<String>) -> Self {
        let var = Arc::new(var.into());
        self.passphrase = PassphraseSource::Callback(Arc::new(move || {
            let value = std::env::var(var.as_str()).map_err(|err| {
                ChainError::Config(format!(
                    "failed to read passphrase from environment variable {}: {err}",
                    var
                ))
            })?;
            Ok(Zeroizing::new(value.into_bytes()))
        }));
        self
    }

    /// Configures the provider to acquire the passphrase using the supplied callback.
    pub fn with_passphrase_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn() -> ChainResult<Zeroizing<Vec<u8>>> + Send + Sync + 'static,
    {
        self.passphrase = PassphraseSource::Callback(Arc::new(callback));
        self
    }

    /// Returns the path backing this provider.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn acquire_passphrase(&self) -> ChainResult<Option<Zeroizing<Vec<u8>>>> {
        match &self.passphrase {
            PassphraseSource::None => Ok(None),
            PassphraseSource::Static(value) => {
                let clone = Zeroizing::new((**value).clone());
                Ok(Some(clone))
            }
            PassphraseSource::Callback(callback) => callback().map(Some),
        }
    }
}

impl WalletKeyProvider for FileWalletKeyProvider {
    fn load_or_generate(&self) -> ChainResult<Keypair> {
        if self.path.exists() {
            let passphrase = self.acquire_passphrase()?;
            match load_keypair_from_disk(&self.path, passphrase.as_ref())? {
                LoadOutcome::Encrypted(keypair) => Ok(keypair),
                LoadOutcome::Plaintext(keypair) => {
                    if let Some(passphrase) = passphrase.as_ref() {
                        persist_encrypted_keypair(&self.path, &keypair, passphrase)?;
                    }
                    Ok(keypair)
                }
            }
        } else {
            let keypair = generate_keypair();
            let passphrase = self.acquire_passphrase()?;
            if let Some(passphrase) = passphrase.as_ref() {
                persist_encrypted_keypair(&self.path, &keypair, passphrase)?;
            } else {
                persist_plaintext_keypair(&self.path, &keypair)?;
            }
            Ok(keypair)
        }
    }

    fn persist(&self, keypair: &Keypair) -> ChainResult<()> {
        let passphrase = self.acquire_passphrase()?;
        if let Some(passphrase) = passphrase.as_ref() {
            persist_encrypted_keypair(&self.path, keypair, passphrase)
        } else {
            persist_plaintext_keypair(&self.path, keypair)
        }
    }
}

fn persist_plaintext_keypair(path: &Path, keypair: &Keypair) -> ChainResult<()> {
    save_keypair(path, keypair)
}

fn persist_encrypted_keypair(
    path: &Path,
    keypair: &Keypair,
    passphrase: &Zeroizing<Vec<u8>>,
) -> ChainResult<()> {
    let keystore = encrypt_keypair(keypair, passphrase)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let encoded = toml::to_string_pretty(&keystore)
        .map_err(|err| ChainError::Config(format!("failed to encode encrypted keypair: {err}")))?;
    fs::write(path, encoded)?;
    Ok(())
}

fn load_keypair_from_disk(
    path: &Path,
    passphrase: Option<&Zeroizing<Vec<u8>>>,
) -> ChainResult<LoadOutcome> {
    let raw = fs::read_to_string(path)?;
    if let Ok(keystore) = toml::from_str::<EncryptedKeystore>(&raw) {
        if passphrase.is_none() {
            return Err(ChainError::Config(
                "wallet keystore is encrypted but no passphrase was supplied".to_string(),
            ));
        }
        let passphrase = passphrase.expect("passphrase checked above");
        let keypair = decrypt_keypair(&keystore, passphrase)?;
        return Ok(LoadOutcome::Encrypted(keypair));
    }

    let keypair = load_keypair(path)?;
    Ok(LoadOutcome::Plaintext(keypair))
}

enum LoadOutcome {
    Encrypted(Keypair),
    Plaintext(Keypair),
}

fn encrypt_keypair(
    keypair: &Keypair,
    passphrase: &Zeroizing<Vec<u8>>,
) -> ChainResult<EncryptedKeystore> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let params = build_argon2_params()?;
    let mut key = Zeroizing::new([0u8; SYMMETRIC_KEY_LEN]);
    derive_symmetric_key(passphrase, &salt, &params, &mut key)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
    let stored = StoredKeypair {
        public_key: hex::encode(keypair.public.to_bytes()),
        secret_key: hex::encode(keypair.secret.to_bytes()),
    };
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&stored)
            .map_err(|err| ChainError::Config(format!("failed to encode keypair: {err}")))?,
    );
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|err| ChainError::Crypto(format!("failed to encrypt wallet keypair: {err}")))?;

    let mut key = key;
    key.zeroize();
    assert_zeroized(&*key);

    let mut plaintext = plaintext;
    plaintext.zeroize();
    assert_zeroized(plaintext.as_ref());

    Ok(EncryptedKeystore {
        version: KEYSTORE_VERSION,
        cipher: CipherMetadata {
            algorithm: CIPHER_ALGORITHM.to_string(),
            nonce: BASE64.encode(nonce),
        },
        kdf: KdfMetadata {
            algorithm: KDF_ALGORITHM.to_string(),
            memory_kib: ARGON2_MEMORY_COST_KIB,
            iterations: ARGON2_TIME_COST,
            parallelism: ARGON2_PARALLELISM,
            salt: BASE64.encode(salt),
        },
        ciphertext: BASE64.encode(ciphertext),
    })
}

fn decrypt_keypair(
    keystore: &EncryptedKeystore,
    passphrase: &Zeroizing<Vec<u8>>,
) -> ChainResult<Keypair> {
    if keystore.version != KEYSTORE_VERSION {
        return Err(ChainError::Config(format!(
            "unsupported wallet keystore version {}",
            keystore.version
        )));
    }
    if keystore.cipher.algorithm != CIPHER_ALGORITHM {
        return Err(ChainError::Config(format!(
            "unsupported wallet cipher {}",
            keystore.cipher.algorithm
        )));
    }
    if keystore.kdf.algorithm != KDF_ALGORITHM {
        return Err(ChainError::Config(format!(
            "unsupported wallet kdf {}",
            keystore.kdf.algorithm
        )));
    }

    let salt = BASE64
        .decode(&keystore.kdf.salt)
        .map_err(|err| ChainError::Config(format!("invalid keystore salt: {err}")))?;
    if salt.len() != SALT_LEN {
        return Err(ChainError::Config(format!(
            "invalid keystore salt length: expected {SALT_LEN}, found {}",
            salt.len()
        )));
    }
    let nonce = BASE64
        .decode(&keystore.cipher.nonce)
        .map_err(|err| ChainError::Config(format!("invalid keystore nonce: {err}")))?;
    if nonce.len() != NONCE_LEN {
        return Err(ChainError::Config(format!(
            "invalid keystore nonce length: expected {NONCE_LEN}, found {}",
            nonce.len()
        )));
    }
    let ciphertext = BASE64
        .decode(&keystore.ciphertext)
        .map_err(|err| ChainError::Config(format!("invalid keystore ciphertext: {err}")))?;

    let params = ParamsBuilder::new()
        .m_cost(keystore.kdf.memory_kib)
        .t_cost(keystore.kdf.iterations)
        .p_cost(keystore.kdf.parallelism)
        .output_len(SYMMETRIC_KEY_LEN)
        .map_err(|err| ChainError::Config(format!("invalid keystore parameters: {err}")))?
        .build()
        .map_err(|err| ChainError::Config(format!("invalid keystore parameters: {err}")))?;

    let mut key = Zeroizing::new([0u8; SYMMETRIC_KEY_LEN]);
    derive_symmetric_key(passphrase, &salt, &params, &mut key)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&*key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| ChainError::Crypto("wallet keystore authentication failed".to_string()))?;

    let mut key = key;
    key.zeroize();
    assert_zeroized(&*key);

    let mut plaintext = Zeroizing::new(plaintext);
    let stored: StoredKeypair = serde_json::from_slice(plaintext.as_ref()).map_err(|err| {
        ChainError::Config(format!("failed to decode decrypted wallet keypair: {err}"))
    })?;

    let mut secret_bytes = Zeroizing::new(
        hex::decode(stored.secret_key)
            .map_err(|err| ChainError::Config(format!("invalid secret key encoding: {err}")))?,
    );
    let public_bytes = hex::decode(stored.public_key)
        .map_err(|err| ChainError::Config(format!("invalid public key encoding: {err}")))?;
    let secret = SecretKey::from_bytes(secret_bytes.as_ref())
        .map_err(|err| ChainError::Config(format!("invalid secret key bytes: {err}")))?;
    let public = PublicKey::from_bytes(&public_bytes)
        .map_err(|err| ChainError::Config(format!("invalid public key bytes: {err}")))?;

    secret_bytes.zeroize();
    assert_zeroized(secret_bytes.as_ref());

    plaintext.zeroize();
    assert_zeroized(plaintext.as_ref());

    Ok(Keypair { secret, public })
}

fn derive_symmetric_key(
    passphrase: &Zeroizing<Vec<u8>>,
    salt: &[u8],
    params: &Params,
    out: &mut [u8; SYMMETRIC_KEY_LEN],
) -> ChainResult<()> {
    let argon2 = Argon2::new_with_secret(&[], Algorithm::Argon2id, Version::V0x13, params.clone())
        .map_err(|err| ChainError::Crypto(format!("failed to initialise argon2: {err}")))?;
    argon2
        .hash_password_into(passphrase.as_ref(), salt, out)
        .map_err(|err| {
            ChainError::Crypto(format!("failed to derive wallet keystore key: {err}"))
        })?;
    Ok(())
}

fn build_argon2_params() -> ChainResult<Params> {
    ParamsBuilder::new()
        .m_cost(ARGON2_MEMORY_COST_KIB)
        .t_cost(ARGON2_TIME_COST)
        .p_cost(ARGON2_PARALLELISM)
        .output_len(SYMMETRIC_KEY_LEN)
        .map_err(|err| ChainError::Crypto(format!("invalid argon2 parameters: {err}")))?
        .build()
        .map_err(|err| ChainError::Crypto(format!("invalid argon2 parameters: {err}")))
}

#[derive(Debug, Serialize, Deserialize)]
struct CipherMetadata {
    algorithm: String,
    nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct KdfMetadata {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedKeystore {
    version: u32,
    cipher: CipherMetadata,
    kdf: KdfMetadata,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct StoredKeypair {
    public_key: String,
    secret_key: String,
}

/// In-memory provider primarily used for tests.
#[derive(Clone, Debug)]
pub struct InMemoryWalletKeyProvider {
    keypair: Keypair,
}

impl InMemoryWalletKeyProvider {
    /// Constructs a provider with a randomly generated keypair.
    pub fn random() -> ChainResult<Self> {
        Ok(Self {
            keypair: generate_keypair(),
        })
    }

    /// Constructs a provider from a fixed keypair.
    pub fn from_keypair(keypair: Keypair) -> Self {
        Self { keypair }
    }
}

impl WalletKeyProvider for InMemoryWalletKeyProvider {
    fn load_or_generate(&self) -> ChainResult<Keypair> {
        Ok(self.keypair.clone())
    }
}

impl From<FileWalletKeyProvider> for InMemoryWalletKeyProvider {
    fn from(value: FileWalletKeyProvider) -> Self {
        let keypair = value
            .load_or_generate()
            .unwrap_or_else(|_| generate_keypair());
        Self { keypair }
    }
}

/// Helper for eagerly loading a keypair from a provider.
pub fn load_wallet_keypair(provider: &dyn WalletKeyProvider) -> ChainResult<Keypair> {
    provider.load_or_generate()
}

/// Persists the provided keypair using the supplied provider.
pub fn persist_wallet_keypair(
    provider: &dyn WalletKeyProvider,
    keypair: &Keypair,
) -> ChainResult<()> {
    provider
        .persist(keypair)
        .map_err(|err| ChainError::Config(format!("failed to persist wallet keypair: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    fn read_file(path: &Path) -> String {
        fs::read_to_string(path).expect("read file")
    }

    #[test]
    fn round_trip_encrypted_keypair() {
        let file = NamedTempFile::new().expect("temp file");
        let provider =
            FileWalletKeyProvider::new(file.path()).with_passphrase("correct horse battery staple");
        let keypair = provider.load_or_generate().expect("load or generate");
        let reloaded = provider.load_or_generate().expect("reload");
        assert_eq!(keypair.public, reloaded.public);
        assert_eq!(keypair.secret, reloaded.secret);

        let raw = read_file(file.path());
        assert!(raw.contains("ciphertext"));
        assert!(raw.contains("argon2id"));
    }

    #[test]
    fn rejects_invalid_passphrase() {
        let file = NamedTempFile::new().expect("temp file");
        let provider = FileWalletKeyProvider::new(file.path()).with_passphrase("hunter2");
        let keypair = provider.load_or_generate().expect("generate");
        provider.persist(&keypair).expect("persist");

        let bad_provider =
            FileWalletKeyProvider::new(file.path()).with_passphrase("wrong passphrase");
        let error = bad_provider.load_or_generate().expect_err("should error");
        assert!(matches!(error, ChainError::Crypto(_)));
    }

    #[test]
    fn migrates_plaintext_store() {
        let file = NamedTempFile::new().expect("temp file");
        let keypair = generate_keypair();
        persist_plaintext_keypair(file.path(), &keypair).expect("persist plain");

        let provider = FileWalletKeyProvider::new(file.path()).with_passphrase("s3cret");
        let loaded = provider.load_or_generate().expect("load");
        assert_eq!(keypair.public, loaded.public);
        assert_eq!(keypair.secret, loaded.secret);

        let raw = read_file(file.path());
        assert!(raw.contains("ciphertext"));
    }

    #[test]
    fn plaintext_round_trip_without_passphrase() {
        let file = NamedTempFile::new().expect("temp file");
        let provider = FileWalletKeyProvider::new(file.path());
        let keypair = provider.load_or_generate().expect("generate");
        let raw = read_file(file.path());
        assert!(raw.contains("public_key"));
        assert!(raw.contains("secret_key"));

        let loaded = provider.load_or_generate().expect("reload");
        assert_eq!(keypair.public, loaded.public);
        assert_eq!(keypair.secret, loaded.secret);
    }
}
