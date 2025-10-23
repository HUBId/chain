use std::convert::TryInto;
use std::env;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::proof_backend::Blake2sHasher;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand::rngs::OsRng;
use reqwest::blocking::Client;
use reqwest::{Certificate, Identity, StatusCode};
use rpp_crypto_vrf::{self};
pub use rpp_crypto_vrf::{
    Tier, VrfKeypair, VrfPublicKey, VrfSecretKey, vrf_public_key_to_hex, vrf_secret_key_to_hex,
};
use serde::{Deserialize, Serialize};

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

fn encode_stored_vrf_keypair(keypair: &VrfKeypair) -> StoredVrfKeypair {
    StoredVrfKeypair {
        public_key: hex::encode(keypair.public.to_bytes()),
        secret_key: hex::encode(keypair.secret.to_bytes()),
    }
}

fn decode_stored_vrf_keypair(stored: &StoredVrfKeypair) -> ChainResult<VrfKeypair> {
    let secret_vec = hex::decode(&stored.secret_key)
        .map_err(|err| ChainError::Config(format!("invalid VRF secret key encoding: {err}")))?;
    let public_vec = hex::decode(&stored.public_key)
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct FilesystemKeystoreConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<PathBuf>,
}

impl Default for FilesystemKeystoreConfig {
    fn default() -> Self {
        Self { root: None }
    }
}

impl FilesystemKeystoreConfig {
    pub fn resolve(&self, configured: &Path) -> PathBuf {
        if configured.is_absolute() {
            configured.to_path_buf()
        } else if let Some(root) = &self.root {
            root.join(configured)
        } else {
            configured.to_path_buf()
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct VaultTlsConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_cert: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<PathBuf>,
    pub insecure_skip_verify: bool,
}

impl Default for VaultTlsConfig {
    fn default() -> Self {
        Self {
            ca_cert: None,
            identity: None,
            insecure_skip_verify: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultKeystoreConfig {
    pub address: String,
    #[serde(default = "VaultKeystoreConfig::default_mount")]
    pub mount: String,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_file: Option<PathBuf>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_env: Option<String>,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<VaultTlsConfig>,
    #[serde(default = "VaultKeystoreConfig::default_timeout_secs")]
    pub request_timeout_secs: u64,
}

impl VaultKeystoreConfig {
    fn default_mount() -> String {
        "kv".to_string()
    }

    fn default_timeout_secs() -> u64 {
        10
    }

    fn sanitize_address(address: &str) -> ChainResult<String> {
        let trimmed = address.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            return Err(ChainError::Config(
                "vault secrets backend requires a non-empty address".into(),
            ));
        }
        Ok(trimmed.to_string())
    }

    fn sanitize_mount(mount: &str) -> ChainResult<String> {
        let trimmed = mount.trim_matches('/');
        if trimmed.is_empty() {
            return Err(ChainError::Config(
                "vault secrets backend requires a non-empty mount path".into(),
            ));
        }
        Ok(trimmed.to_string())
    }

    fn resolve_token(&self) -> ChainResult<String> {
        if let Some(token) = &self.token {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                return Err(ChainError::Config(
                    "vault secrets backend token must not be empty".into(),
                ));
            }
            return Ok(trimmed.to_string());
        }
        if let Some(path) = &self.token_file {
            let raw = fs::read_to_string(path)?;
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(ChainError::Config(format!(
                    "vault secrets backend token file {} is empty",
                    path.display()
                )));
            }
            return Ok(trimmed.to_string());
        }
        if let Some(var) = &self.token_env {
            let value = env::var(var).map_err(|_| {
                ChainError::Config(format!(
                    "vault secrets backend token env `{}` is not set",
                    var
                ))
            })?;
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(ChainError::Config(format!(
                    "vault secrets backend token env `{}` contains an empty value",
                    var
                )));
            }
            return Ok(trimmed.to_string());
        }
        Err(ChainError::Config(
            "vault secrets backend requires `token`, `token_file`, or `token_env`".into(),
        ))
    }

    pub fn validate(&self) -> ChainResult<()> {
        self.resolve_token().map(|_| ())?;
        if self.request_timeout_secs == 0 {
            return Err(ChainError::Config(
                "vault secrets backend request_timeout_secs must be greater than 0".into(),
            ));
        }
        Self::sanitize_address(&self.address)?;
        Self::sanitize_mount(&self.mount)?;
        Ok(())
    }

    fn build_client(&self) -> ChainResult<Client> {
        let mut builder = Client::builder().timeout(Duration::from_secs(self.request_timeout_secs));
        if let Some(tls) = &self.tls {
            if let Some(path) = &tls.ca_cert {
                let pem = fs::read(path)?;
                let cert = Certificate::from_pem(&pem).map_err(|err| {
                    ChainError::Config(format!("invalid vault TLS CA certificate: {err}"))
                })?;
                builder = builder.add_root_certificate(cert);
            }
            if let Some(identity_path) = &tls.identity {
                let pem = fs::read(identity_path)?;
                let identity = Identity::from_pem(&pem).map_err(|err| {
                    ChainError::Config(format!("invalid vault TLS identity: {err}"))
                })?;
                builder = builder.identity(identity);
            }
            if tls.insecure_skip_verify {
                builder = builder.danger_accept_invalid_certs(true);
            }
        }
        builder
            .build()
            .map_err(|err| ChainError::Config(format!("failed to build vault client: {err}")))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HsmKeystoreConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

#[derive(Clone, Debug)]
pub enum VrfKeyIdentifier {
    Filesystem(PathBuf),
    Remote(String),
}

impl VrfKeyIdentifier {
    pub fn filesystem(path: PathBuf) -> Self {
        Self::Filesystem(path)
    }

    pub fn remote<S: Into<String>>(key: S) -> Self {
        Self::Remote(key.into())
    }
}

pub type DynVrfKeyStore = Arc<dyn VrfKeyStore>;

pub trait VrfKeyStore: Send + Sync {
    fn load(&self, identifier: &VrfKeyIdentifier) -> ChainResult<Option<VrfKeypair>>;
    fn store(&self, identifier: &VrfKeyIdentifier, keypair: &VrfKeypair) -> ChainResult<()>;

    fn load_or_generate(&self, identifier: &VrfKeyIdentifier) -> ChainResult<VrfKeypair> {
        if let Some(existing) = self.load(identifier)? {
            return Ok(existing);
        }
        let generated = generate_vrf_keypair()?;
        self.store(identifier, &generated)?;
        Ok(generated)
    }
}

#[derive(Clone, Debug)]
pub struct FilesystemVrfKeyStore {
    config: FilesystemKeystoreConfig,
}

impl FilesystemVrfKeyStore {
    pub fn new(config: FilesystemKeystoreConfig) -> Self {
        Self { config }
    }

    fn resolve_path(&self, identifier: &VrfKeyIdentifier) -> ChainResult<PathBuf> {
        match identifier {
            VrfKeyIdentifier::Filesystem(path) => Ok(self.config.resolve(path)),
            other => Err(ChainError::Config(format!(
                "filesystem VRF keystore received incompatible identifier: {other:?}"
            ))),
        }
    }
}

impl Default for FilesystemVrfKeyStore {
    fn default() -> Self {
        Self::new(FilesystemKeystoreConfig::default())
    }
}

impl VrfKeyStore for FilesystemVrfKeyStore {
    fn load(&self, identifier: &VrfKeyIdentifier) -> ChainResult<Option<VrfKeypair>> {
        let path = self.resolve_path(identifier)?;
        match fs::read_to_string(&path) {
            Ok(raw) => {
                let stored: StoredVrfKeypair = toml::from_str(&raw).map_err(|err| {
                    ChainError::Config(format!("failed to decode VRF keypair: {err}"))
                })?;
                decode_stored_vrf_keypair(&stored).map(Some)
            }
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    fn store(&self, identifier: &VrfKeyIdentifier, keypair: &VrfKeypair) -> ChainResult<()> {
        let path = self.resolve_path(identifier)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let stored = encode_stored_vrf_keypair(keypair);
        let encoded = toml::to_string_pretty(&stored)
            .map_err(|err| ChainError::Config(format!("failed to encode VRF keypair: {err}")))?;
        fs::write(path, encoded)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct VaultVrfKeyStore {
    client: Client,
    address: String,
    mount: String,
    namespace: Option<String>,
    token: String,
}

impl VaultVrfKeyStore {
    pub fn new(config: VaultKeystoreConfig) -> ChainResult<Self> {
        config.validate()?;
        let client = config.build_client()?;
        let address = VaultKeystoreConfig::sanitize_address(&config.address)?;
        let mount = VaultKeystoreConfig::sanitize_mount(&config.mount)?;
        let token = config.resolve_token()?;
        Ok(Self {
            client,
            address,
            mount,
            namespace: config.namespace,
            token,
        })
    }

    fn require_identifier<'a>(&self, identifier: &'a VrfKeyIdentifier) -> ChainResult<&'a str> {
        match identifier {
            VrfKeyIdentifier::Remote(key) => {
                let trimmed = key.trim_matches('/');
                if trimmed.is_empty() {
                    Err(ChainError::Config(
                        "vault secrets backend requires a non-empty remote key identifier".into(),
                    ))
                } else {
                    Ok(trimmed)
                }
            }
            _ => Err(ChainError::Config(
                "vault secrets backend must be used with remote key identifiers".into(),
            )),
        }
    }

    fn data_url(&self, key: &str) -> String {
        format!("{}/v1/{}/data/{}", self.address, self.mount, key)
    }

    fn apply_headers(
        &self,
        request: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        let request = request.header("X-Vault-Token", &self.token);
        if let Some(namespace) = &self.namespace {
            request.header("X-Vault-Namespace", namespace)
        } else {
            request
        }
    }
}

#[derive(Deserialize)]
struct VaultReadResponse {
    data: VaultReadInner,
}

#[derive(Deserialize)]
struct VaultReadInner {
    data: StoredVrfKeypair,
}

#[derive(Serialize)]
struct VaultWriteRequest<'a> {
    data: &'a StoredVrfKeypair,
}

impl VrfKeyStore for VaultVrfKeyStore {
    fn load(&self, identifier: &VrfKeyIdentifier) -> ChainResult<Option<VrfKeypair>> {
        let key = self.require_identifier(identifier)?;
        let request = self.client.get(self.data_url(key));
        let response = self
            .apply_headers(request)
            .send()
            .map_err(|err| ChainError::Crypto(format!("vault read request failed: {err}")))?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(ChainError::Crypto(format!(
                "vault read request returned status {}",
                response.status()
            )));
        }
        let payload: VaultReadResponse = response.json().map_err(|err| {
            ChainError::Crypto(format!("vault read response decode failed: {err}"))
        })?;
        decode_stored_vrf_keypair(&payload.data.data).map(Some)
    }

    fn store(&self, identifier: &VrfKeyIdentifier, keypair: &VrfKeypair) -> ChainResult<()> {
        let key = self.require_identifier(identifier)?;
        let stored = encode_stored_vrf_keypair(keypair);
        let request = self
            .apply_headers(self.client.post(self.data_url(key)))
            .json(&VaultWriteRequest { data: &stored });
        let response = request
            .send()
            .map_err(|err| ChainError::Crypto(format!("vault write request failed: {err}")))?;
        if !response.status().is_success() {
            return Err(ChainError::Crypto(format!(
                "vault write request returned status {}",
                response.status()
            )));
        }
        Ok(())
    }
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
    Ok(rpp_crypto_vrf::generate_vrf_keypair())
}

pub fn load_or_generate_vrf_keypair(path: &Path) -> ChainResult<VrfKeypair> {
    FilesystemVrfKeyStore::default()
        .load_or_generate(&VrfKeyIdentifier::filesystem(path.to_path_buf()))
}

pub fn save_vrf_keypair(path: &Path, keypair: &VrfKeypair) -> ChainResult<()> {
    FilesystemVrfKeyStore::default()
        .store(&VrfKeyIdentifier::filesystem(path.to_path_buf()), keypair)
}

pub fn load_vrf_keypair(path: &Path) -> ChainResult<VrfKeypair> {
    FilesystemVrfKeyStore::default()
        .load(&VrfKeyIdentifier::filesystem(path.to_path_buf()))?
        .ok_or_else(|| ChainError::Config(format!("VRF keypair not found at {}", path.display())))
}

pub fn vrf_public_key_from_hex(data: &str) -> ChainResult<VrfPublicKey> {
    rpp_crypto_vrf::vrf_public_key_from_hex(data)
        .map_err(|err| ChainError::Config(format!("invalid VRF public key encoding: {err}")))
}

pub fn vrf_secret_key_from_hex(data: &str) -> ChainResult<VrfSecretKey> {
    rpp_crypto_vrf::vrf_secret_key_from_hex(data)
        .map_err(|err| ChainError::Config(format!("invalid VRF secret key encoding: {err}")))
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
