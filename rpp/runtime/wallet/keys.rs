use std::path::{Path, PathBuf};

use crate::crypto::{generate_keypair, load_or_generate_keypair, save_keypair};
use crate::errors::{ChainError, ChainResult};

/// Abstraction over key management for the wallet runtime.
pub trait WalletKeyProvider: Send + Sync {
    /// Loads a keypair or generates a fresh one if it does not exist.
    fn load_or_generate(&self) -> ChainResult<ed25519_dalek::Keypair>;

    /// Persists a newly generated keypair if supported by the backend.
    fn persist(&self, keypair: &ed25519_dalek::Keypair) -> ChainResult<()> {
        let _ = keypair;
        Ok(())
    }
}

/// File-backed wallet key provider.
#[derive(Clone, Debug)]
pub struct FileWalletKeyProvider {
    path: PathBuf,
}

impl FileWalletKeyProvider {
    /// Creates a new provider rooted at the supplied filesystem path.
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Returns the path backing this provider.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl WalletKeyProvider for FileWalletKeyProvider {
    fn load_or_generate(&self) -> ChainResult<ed25519_dalek::Keypair> {
        load_or_generate_keypair(&self.path)
    }

    fn persist(&self, keypair: &ed25519_dalek::Keypair) -> ChainResult<()> {
        save_keypair(&self.path, keypair)
    }
}

/// In-memory provider primarily used for tests.
#[derive(Clone, Debug)]
pub struct InMemoryWalletKeyProvider {
    keypair: ed25519_dalek::Keypair,
}

impl InMemoryWalletKeyProvider {
    /// Constructs a provider with a randomly generated keypair.
    pub fn random() -> ChainResult<Self> {
        Ok(Self {
            keypair: generate_keypair(),
        })
    }

    /// Constructs a provider from a fixed keypair.
    pub fn from_keypair(keypair: ed25519_dalek::Keypair) -> Self {
        Self { keypair }
    }
}

impl WalletKeyProvider for InMemoryWalletKeyProvider {
    fn load_or_generate(&self) -> ChainResult<ed25519_dalek::Keypair> {
        Ok(self.keypair.clone())
    }
}

impl From<FileWalletKeyProvider> for InMemoryWalletKeyProvider {
    fn from(value: FileWalletKeyProvider) -> Self {
        let keypair = load_or_generate_keypair(value.path()).unwrap_or_else(|_| generate_keypair());
        Self { keypair }
    }
}

/// Helper for eagerly loading a keypair from a provider.
pub fn load_wallet_keypair(
    provider: &dyn WalletKeyProvider,
) -> ChainResult<ed25519_dalek::Keypair> {
    provider.load_or_generate()
}

/// Persists the provided keypair using the supplied provider.
pub fn persist_wallet_keypair(
    provider: &dyn WalletKeyProvider,
    keypair: &ed25519_dalek::Keypair,
) -> ChainResult<()> {
    provider
        .persist(keypair)
        .map_err(|err| ChainError::Config(format!("failed to persist wallet keypair: {err}")))
}
