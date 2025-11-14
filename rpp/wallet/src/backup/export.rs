use std::fs;
use std::path::{Path, PathBuf};

use serde_json::to_vec_pretty;
use zeroize::{Zeroize, Zeroizing};

use super::{
    compute_checksums, format_backup_name, gather_meta, gather_policies, BackupError,
    BackupMetadata, BackupPayload,
};
use super::{ensure_backup_dir, prepare_envelope};
use crate::db::WalletStore;

#[derive(Debug, Clone, Copy)]
pub struct BackupExportOptions {
    pub metadata_only: bool,
    pub include_checksums: bool,
}

impl Default for BackupExportOptions {
    fn default() -> Self {
        Self {
            metadata_only: false,
            include_checksums: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackupExportResult {
    pub path: PathBuf,
    pub metadata: BackupMetadata,
}

pub fn backup_export(
    store: &WalletStore,
    keystore_path: &Path,
    backup_dir: &Path,
    passphrase: Zeroizing<Vec<u8>>,
    confirmation: Zeroizing<Vec<u8>>,
    options: BackupExportOptions,
) -> Result<BackupExportResult, BackupError> {
    if passphrase.as_ref() != confirmation.as_ref() {
        return Err(BackupError::PassphraseMismatch);
    }

    let meta = gather_meta(store)?;
    let policies = gather_policies(store)?;

    let keystore = if options.metadata_only {
        None
    } else {
        match fs::read(keystore_path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(BackupError::KeystoreMissing(
                    keystore_path.display().to_string(),
                ))
            }
            Err(error) => return Err(BackupError::Io(error)),
        }
    };

    let mut payload = BackupPayload {
        keystore,
        meta,
        policies,
        checksums: None,
    };

    if options.include_checksums {
        let checksums = compute_checksums(&payload);
        payload.checksums = Some(checksums);
    }

    let (envelope, mut plaintext) =
        prepare_envelope(&payload, options.include_checksums, &passphrase)?;

    ensure_backup_dir(backup_dir)?;
    let file_name = format_backup_name(envelope.metadata.created_at_ms);
    let path = backup_dir.join(file_name);
    let encoded =
        to_vec_pretty(&envelope).map_err(|err| BackupError::Serialization(err.to_string()))?;
    fs::write(&path, encoded)?;
    plaintext.zeroize();

    Ok(BackupExportResult {
        path,
        metadata: envelope.metadata,
    })
}
