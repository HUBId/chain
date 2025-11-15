use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params, ParamsBuilder, PasswordHasher, Version};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bincode::Options as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::db::schema;
use crate::db::{
    PolicySnapshot, StoredZsiArtifact, WalletStore, WalletStoreBatch, WalletStoreError,
};

mod export;
mod import;

pub use export::{backup_export, BackupExportOptions, BackupExportResult};
pub use import::{
    backup_import, backup_validate, BackupImportOutcome, BackupValidation, BackupValidationMode,
};

const BACKUP_VERSION: u32 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const SYMMETRIC_KEY_LEN: usize = 32;
const CIPHER_ALGORITHM: &str = "chacha20poly1305";
const KDF_ALGORITHM: &str = "argon2id";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupMetadata {
    pub version: u32,
    pub schema_checksum: String,
    pub created_at_ms: u64,
    pub has_keystore: bool,
    pub policy_entries: usize,
    pub meta_entries: usize,
    pub include_checksums: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupPayload {
    pub keystore: Option<Vec<u8>>,
    pub meta: Vec<MetaEntry>,
    pub policies: Vec<(String, PolicySnapshot)>,
    pub zsi_artifacts: Vec<StoredZsiArtifact<'static>>,
    pub checksums: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetaEntry {
    pub key: String,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct BackupEnvelope {
    pub metadata: BackupMetadata,
    pub cipher: CipherMetadata,
    pub kdf: KdfMetadata,
    pub ciphertext: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct CipherMetadata {
    pub algorithm: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct KdfMetadata {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: String,
}

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("wallet store error: {0}")]
    Store(#[from] WalletStoreError),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("encryption error: {0}")]
    Encryption(String),
    #[error("invalid backup: {0}")]
    Invalid(String),
    #[error("passphrase confirmation mismatch")]
    PassphraseMismatch,
    #[error("wallet keystore not found at {0}")]
    KeystoreMissing(String),
    #[error("checksum mismatch for component `{component}`")]
    ChecksumMismatch { component: String },
    #[error("unsupported backup version {found} (expected {expected})")]
    UnsupportedVersion { found: u32, expected: u32 },
    #[error("schema checksum mismatch (backup {backup}, local {local})")]
    SchemaMismatch { backup: String, local: String },
}

impl From<bincode::Error> for BackupError {
    fn from(error: bincode::Error) -> Self {
        BackupError::Serialization(error.to_string())
    }
}

impl From<argon2::Error> for BackupError {
    fn from(error: argon2::Error) -> Self {
        BackupError::Encryption(error.to_string())
    }
}

fn encode_metadata(metadata: &BackupMetadata) -> Result<Vec<u8>, BackupError> {
    Ok(bincode::DefaultOptions::new().serialize(metadata)?)
}

pub(super) fn encode_payload(payload: &BackupPayload) -> Result<Vec<u8>, BackupError> {
    Ok(bincode::DefaultOptions::new().serialize(payload)?)
}

pub(super) fn decode_payload(bytes: &[u8]) -> Result<BackupPayload, BackupError> {
    Ok(bincode::DefaultOptions::new().deserialize(bytes)?)
}

pub(super) fn derive_symmetric_key(
    passphrase: &Zeroizing<Vec<u8>>,
    salt: &[u8; SALT_LEN],
    params: &Params,
    out: &mut Zeroizing<[u8; SYMMETRIC_KEY_LEN]>,
) -> Result<(), BackupError> {
    let argon2 = Argon2::new_with_secret(&[], Algorithm::Argon2id, Version::V0x13, params.clone())?;
    argon2.hash_password_into(passphrase.as_ref(), salt, out.as_mut())?;
    Ok(())
}

pub(super) fn build_argon2_params() -> Result<Params, BackupError> {
    Ok(ParamsBuilder::new()
        .m_cost(64 * 1024)
        .t_cost(3)
        .p_cost(1)
        .output_len(SYMMETRIC_KEY_LEN)
        .build()
        .map_err(BackupError::from)?)
}

pub(super) fn compute_schema_checksum() -> String {
    let mut hasher = Sha256::new();
    hasher.update(schema::META_NAMESPACE);
    hasher.update(schema::KEYS_NAMESPACE);
    hasher.update(schema::ADDR_EXTERNAL_NAMESPACE);
    hasher.update(schema::ADDR_INTERNAL_NAMESPACE);
    hasher.update(schema::UTXOS_NAMESPACE);
    hasher.update(schema::PENDING_LOCKS_NAMESPACE);
    hasher.update(schema::TX_CACHE_NAMESPACE);
    hasher.update(schema::POLICIES_NAMESPACE);
    hasher.update(schema::CHECKPOINTS_NAMESPACE);
    hasher.update(schema::EXTENSION_PENDING_LOCKS.as_bytes());
    hasher.update(schema::EXTENSION_PROVER_META.as_bytes());
    hasher.update(schema::EXTENSION_CHECKPOINTS.as_bytes());
    hasher.update(schema::ZSI_NAMESPACE);
    hasher.update(schema::META_LAST_RESCAN_TS_KEY.as_bytes());
    hasher.update(schema::META_FEE_CACHE_FETCHED_TS_KEY.as_bytes());
    hasher.update(schema::META_FEE_CACHE_EXPIRES_TS_KEY.as_bytes());
    hasher.update(schema::SCHEMA_VERSION_LATEST.to_le_bytes());
    hex::encode(hasher.finalize())
}

pub(super) fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

pub(super) fn build_metadata(include_checksums: bool, payload: &BackupPayload) -> BackupMetadata {
    BackupMetadata {
        version: BACKUP_VERSION,
        schema_checksum: compute_schema_checksum(),
        created_at_ms: current_timestamp_ms(),
        has_keystore: payload.keystore.is_some(),
        policy_entries: payload.policies.len(),
        meta_entries: payload.meta.len(),
        include_checksums,
    }
}

pub(super) fn prepare_envelope(
    payload: &BackupPayload,
    include_checksums: bool,
    passphrase: &Zeroizing<Vec<u8>>,
) -> Result<(BackupEnvelope, Zeroizing<Vec<u8>>), BackupError> {
    let metadata = build_metadata(include_checksums, payload);
    let metadata_bytes = encode_metadata(&metadata)?;
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    let params = build_argon2_params()?;
    let mut key = Zeroizing::new([0u8; SYMMETRIC_KEY_LEN]);
    derive_symmetric_key(passphrase, &salt, &params, &mut key)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let payload_bytes = encode_payload(payload)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &payload_bytes,
                aad: &metadata_bytes,
            },
        )
        .map_err(|err| BackupError::Encryption(err.to_string()))?;

    let mut key = key;
    key.zeroize();

    let envelope = BackupEnvelope {
        metadata,
        cipher: CipherMetadata {
            algorithm: CIPHER_ALGORITHM.to_string(),
            nonce: BASE64.encode(nonce),
        },
        kdf: KdfMetadata {
            algorithm: KDF_ALGORITHM.to_string(),
            memory_kib: params.m_cost(),
            iterations: params.t_cost(),
            parallelism: params.p_cost(),
            salt: BASE64.encode(salt),
        },
        ciphertext: BASE64.encode(ciphertext),
    };

    Ok((envelope, Zeroizing::new(payload_bytes)))
}

pub(super) fn decrypt_envelope(
    envelope: &BackupEnvelope,
    passphrase: &Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, BackupError> {
    if envelope.cipher.algorithm != CIPHER_ALGORITHM {
        return Err(BackupError::Invalid(format!(
            "unsupported cipher {}",
            envelope.cipher.algorithm
        )));
    }
    if envelope.kdf.algorithm != KDF_ALGORITHM {
        return Err(BackupError::Invalid(format!(
            "unsupported kdf {}",
            envelope.kdf.algorithm
        )));
    }
    if envelope.metadata.version != BACKUP_VERSION {
        return Err(BackupError::UnsupportedVersion {
            found: envelope.metadata.version,
            expected: BACKUP_VERSION,
        });
    }

    let salt_vec = BASE64
        .decode(&envelope.kdf.salt)
        .map_err(|err| BackupError::Invalid(format!("invalid salt encoding: {err}")))?;
    if salt_vec.len() != SALT_LEN {
        return Err(BackupError::Invalid(format!(
            "invalid salt length: expected {SALT_LEN}, found {}",
            salt_vec.len()
        )));
    }
    let nonce_vec = BASE64
        .decode(&envelope.cipher.nonce)
        .map_err(|err| BackupError::Invalid(format!("invalid nonce encoding: {err}")))?;
    if nonce_vec.len() != NONCE_LEN {
        return Err(BackupError::Invalid(format!(
            "invalid nonce length: expected {NONCE_LEN}, found {}",
            nonce_vec.len()
        )));
    }
    let ciphertext = BASE64
        .decode(&envelope.cipher.ciphertext)
        .map_err(|err| BackupError::Invalid(format!("invalid ciphertext encoding: {err}")))?;

    let params = ParamsBuilder::new()
        .m_cost(envelope.kdf.memory_kib)
        .t_cost(envelope.kdf.iterations)
        .p_cost(envelope.kdf.parallelism)
        .output_len(SYMMETRIC_KEY_LEN)
        .build()
        .map_err(BackupError::from)?;

    let mut key = Zeroizing::new([0u8; SYMMETRIC_KEY_LEN]);
    let salt: [u8; SALT_LEN] = salt_vec
        .as_slice()
        .try_into()
        .map_err(|_| BackupError::Invalid("invalid salt length".into()))?;
    derive_symmetric_key(passphrase, &salt, &params, &mut key)?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let metadata_bytes = encode_metadata(&envelope.metadata)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_vec),
            Payload {
                msg: ciphertext.as_ref(),
                aad: &metadata_bytes,
            },
        )
        .map_err(|_| BackupError::Encryption("backup authentication failed".into()))?;

    let mut key = key;
    key.zeroize();

    Ok(Zeroizing::new(plaintext))
}

pub(super) fn verify_schema_checksum(metadata: &BackupMetadata) -> Result<(), BackupError> {
    let local = compute_schema_checksum();
    if metadata.schema_checksum != local {
        return Err(BackupError::SchemaMismatch {
            backup: metadata.schema_checksum.clone(),
            local,
        });
    }
    Ok(())
}

pub(super) fn ensure_backup_dir(dir: &Path) -> Result<(), BackupError> {
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::create_dir_all(dir)?;
    Ok(())
}

pub(super) fn collect_meta(store: &WalletStore) -> Result<Vec<MetaEntry>, BackupError> {
    let entries = store
        .iter_meta()?
        .into_iter()
        .map(|(key, value)| MetaEntry { key, value })
        .collect();
    Ok(entries)
}

pub(super) fn collect_policies(
    store: &WalletStore,
) -> Result<Vec<(String, PolicySnapshot)>, BackupError> {
    Ok(store.iter_policy_snapshots()?)
}

pub(super) fn collect_zsi_artifacts(
    store: &WalletStore,
) -> Result<Vec<StoredZsiArtifact<'static>>, BackupError> {
    Ok(store.iter_zsi_artifacts()?)
}

pub(super) fn apply_meta(batch: &mut WalletStoreBatch<'_>, meta: &[MetaEntry]) {
    for entry in meta {
        batch.put_meta(&entry.key, &entry.value);
    }
}

pub(super) use collect_meta as gather_meta;
pub(super) use collect_policies as gather_policies;
pub(super) use collect_zsi_artifacts as gather_zsi_artifacts;

pub fn resolve_backup_path(dir: &Path, name: &str) -> Result<PathBuf, BackupError> {
    if name.contains('/') || name.contains('\\') {
        return Err(BackupError::Invalid(
            "backup file name must not contain path separators".into(),
        ));
    }
    let candidate = dir.join(name);
    let canonical = candidate
        .canonicalize()
        .unwrap_or_else(|_| candidate.clone());
    if !canonical.starts_with(dir) {
        return Err(BackupError::Invalid(
            "backup file must reside under the configured directory".into(),
        ));
    }
    Ok(candidate)
}

pub fn format_backup_name(timestamp_ms: u64) -> String {
    format!("wallet-backup-{timestamp_ms}.bin")
}

pub fn compute_checksums(payload: &BackupPayload) -> BTreeMap<String, String> {
    let mut checksums = BTreeMap::new();
    if let Some(keystore) = payload.keystore.as_ref() {
        checksums.insert(
            "keystore".to_string(),
            hex::encode(Sha256::digest(keystore)),
        );
    }
    let mut meta_bytes = Vec::new();
    for entry in &payload.meta {
        meta_bytes.extend_from_slice(entry.key.as_bytes());
        meta_bytes.extend_from_slice(&entry.value);
    }
    checksums.insert("meta".to_string(), hex::encode(Sha256::digest(&meta_bytes)));
    let mut policy_bytes = Vec::new();
    for (label, snapshot) in &payload.policies {
        policy_bytes.extend_from_slice(label.as_bytes());
        if let Ok(bytes) = bincode::DefaultOptions::new().serialize(snapshot) {
            policy_bytes.extend_from_slice(&bytes);
        }
    }
    checksums.insert(
        "policies".to_string(),
        hex::encode(Sha256::digest(&policy_bytes)),
    );
    let mut zsi_bytes = Vec::new();
    for artifact in &payload.zsi_artifacts {
        zsi_bytes.extend_from_slice(artifact.identity.as_bytes());
        zsi_bytes.extend_from_slice(artifact.commitment_digest.as_bytes());
        zsi_bytes.extend_from_slice(&artifact.recorded_at_ms.to_le_bytes());
        zsi_bytes.extend_from_slice(artifact.backend.as_bytes());
        zsi_bytes.extend_from_slice(artifact.proof.as_ref());
    }
    checksums.insert(
        "zsi_artifacts".to_string(),
        hex::encode(Sha256::digest(&zsi_bytes)),
    );
    checksums
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::indexer::checkpoints;
    use serde_json::Value;
    use std::borrow::Cow;
    use tempfile::tempdir;

    fn store_with_data(base: &Path) -> WalletStore {
        WalletStore::open(base).expect("open store")
    }

    fn write_keystore(path: &Path, data: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create keystore dir");
        }
        std::fs::write(path, data).expect("write keystore");
    }

    fn export_name(result: &BackupExportResult) -> String {
        result
            .path
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .to_string()
    }

    #[test]
    fn backup_round_trip_restores_state() {
        let temp = tempdir().expect("tempdir");
        let store_dir = temp.path().join("store");
        let backup_dir = temp.path().join("backups");
        let keystore_path = temp.path().join("keys").join("wallet.toml");
        std::fs::create_dir_all(&backup_dir).expect("create backup dir");
        let store = store_with_data(&store_dir);

        {
            let mut batch = store.batch().expect("batch");
            batch.put_meta("network", b"testnet");
            batch.put_meta("hint", b"example");
            let snapshot = PolicySnapshot::new(1, 1_234, vec!["allow *".into()]);
            batch
                .put_policy_snapshot("default", &snapshot)
                .expect("put policy");
            let artifact = StoredZsiArtifact::new(
                1_690_000_000_000,
                "alice".into(),
                "proof-digest".into(),
                "mock-backend".into(),
                Cow::Borrowed(&[1u8, 2, 3, 4]),
            );
            batch.put_zsi_artifact(&artifact).expect("put zsi artifact");
            checkpoints::persist_birthday_height(&mut batch, Some(777)).expect("persist birthday");
            batch.commit().expect("commit");
        }

        write_keystore(&keystore_path, b"encrypted-keystore");

        let passphrase = Zeroizing::new(b"correct horse battery staple".to_vec());
        let confirmation = Zeroizing::new(b"correct horse battery staple".to_vec());
        let export = backup_export(
            &store,
            &keystore_path,
            &backup_dir,
            passphrase.clone(),
            confirmation.clone(),
            BackupExportOptions::default(),
        )
        .expect("export");

        {
            let mut batch = store.batch().expect("clear batch");
            batch.delete_meta("network");
            batch.delete_meta("hint");
            batch.delete_policy_snapshot("default");
            batch.delete_zsi_artifact("alice", "proof-digest");
            batch.commit().expect("clear commit");
        }
        std::fs::remove_file(&keystore_path).expect("remove keystore");

        let import = backup_import(
            &store,
            &keystore_path,
            &backup_dir,
            &export_name(&export),
            Zeroizing::new(b"correct horse battery staple".to_vec()),
        )
        .expect("import");

        assert_eq!(import.metadata, export.metadata);
        assert!(import.restored_keystore);
        assert!(import.restored_policy);
        assert_eq!(import.rescan_from, 777);

        let network = store.get_meta("network").expect("meta").expect("value");
        assert_eq!(network, b"testnet");
        let hint = store.get_meta("hint").expect("meta").expect("value");
        assert_eq!(hint, b"example");

        let policies = store.iter_policy_snapshots().expect("policies");
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0].0, "default");
        assert_eq!(policies[0].1.statements, vec!["allow *".to_string()]);
        let zsi_artifacts = store.iter_zsi_artifacts().expect("zsi artifacts");
        assert_eq!(zsi_artifacts.len(), 1);
        assert_eq!(zsi_artifacts[0].identity, "alice");
        assert_eq!(zsi_artifacts[0].commitment_digest, "proof-digest");

        let restored = std::fs::read(&keystore_path).expect("restored keystore");
        assert_eq!(restored, b"encrypted-keystore");
    }

    #[test]
    fn import_with_wrong_passphrase_fails() {
        let temp = tempdir().expect("tempdir");
        let store_dir = temp.path().join("store");
        let backup_dir = temp.path().join("backups");
        let keystore_path = temp.path().join("keys").join("wallet.toml");
        std::fs::create_dir_all(&backup_dir).expect("create backup dir");
        let store = store_with_data(&store_dir);

        {
            let mut batch = store.batch().expect("batch");
            batch.put_meta("network", b"testnet");
            batch.commit().expect("commit");
        }

        write_keystore(&keystore_path, b"encrypted-keystore");

        let export = backup_export(
            &store,
            &keystore_path,
            &backup_dir,
            Zeroizing::new(b"secret".to_vec()),
            Zeroizing::new(b"secret".to_vec()),
            BackupExportOptions::default(),
        )
        .expect("export");

        let error = backup_import(
            &store,
            &keystore_path,
            &backup_dir,
            &export_name(&export),
            Zeroizing::new(b"wrong".to_vec()),
        )
        .expect_err("import should fail");
        assert!(matches!(error, BackupError::Encryption(_)));
    }

    #[test]
    fn tampered_archive_is_detected() {
        let temp = tempdir().expect("tempdir");
        let store_dir = temp.path().join("store");
        let backup_dir = temp.path().join("backups");
        let keystore_path = temp.path().join("keys").join("wallet.toml");
        std::fs::create_dir_all(&backup_dir).expect("create backup dir");
        let store = store_with_data(&store_dir);

        write_keystore(&keystore_path, b"encrypted-keystore");

        let export = backup_export(
            &store,
            &keystore_path,
            &backup_dir,
            Zeroizing::new(b"secret".to_vec()),
            Zeroizing::new(b"secret".to_vec()),
            BackupExportOptions::default(),
        )
        .expect("export");

        let mut envelope: Value =
            serde_json::from_slice(&std::fs::read(&export.path).expect("read backup"))
                .expect("decode backup");
        if let Some(Value::String(ciphertext)) = envelope.get_mut("ciphertext") {
            let mut bytes = BASE64
                .decode(ciphertext.as_bytes())
                .expect("decode ciphertext");
            bytes[0] ^= 0xAA;
            *ciphertext = BASE64.encode(bytes);
        } else {
            panic!("ciphertext missing");
        }
        std::fs::write(
            &export.path,
            serde_json::to_vec_pretty(&envelope).expect("encode"),
        )
        .expect("rewrite backup");

        let error = backup_validate(
            &store,
            &backup_dir,
            &export_name(&export),
            Zeroizing::new(b"secret".to_vec()),
            BackupValidationMode::Full,
        )
        .expect_err("validation should fail");
        assert!(matches!(error, BackupError::Encryption(_)));
    }

    #[test]
    fn metadata_only_exports_skip_keystore() {
        let temp = tempdir().expect("tempdir");
        let store_dir = temp.path().join("store");
        let backup_dir = temp.path().join("backups");
        let keystore_path = temp.path().join("keys").join("wallet.toml");
        std::fs::create_dir_all(&backup_dir).expect("create backup dir");
        let store = store_with_data(&store_dir);

        {
            let mut batch = store.batch().expect("batch");
            batch.put_meta("network", b"testnet");
            batch.commit().expect("commit");
        }

        let mut options = BackupExportOptions::default();
        options.metadata_only = true;
        let export = backup_export(
            &store,
            &keystore_path,
            &backup_dir,
            Zeroizing::new(b"secret".to_vec()),
            Zeroizing::new(b"secret".to_vec()),
            options,
        )
        .expect("metadata export");
        assert!(!export.metadata.has_keystore);

        let validation = backup_validate(
            &store,
            &backup_dir,
            &export_name(&export),
            Zeroizing::new(b"secret".to_vec()),
            BackupValidationMode::Full,
        )
        .expect("validate");
        assert!(!validation.has_keystore);

        let outcome = backup_import(
            &store,
            &keystore_path,
            &backup_dir,
            &export_name(&export),
            Zeroizing::new(b"secret".to_vec()),
        )
        .expect("import");
        assert!(!outcome.restored_keystore);
        assert!(!keystore_path.exists());
    }
}
