use std::fs;
use std::path::{Path, PathBuf};

use serde_json::to_vec_pretty;
use zeroize::{Zeroize, Zeroizing};

use super::{
    compute_checksums, consensus_point, ensure_consensus_stable, format_backup_name, gather_meta,
    gather_policies, gather_zsi_artifacts, BackupError, BackupMetadata, BackupPayload,
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

    let consensus = super::consensus_point(store)?;
    let meta = gather_meta(store)?;
    let policies = gather_policies(store)?;
    let zsi_artifacts = gather_zsi_artifacts(store)?;

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
        zsi_artifacts,
        checksums: None,
    };

    if options.include_checksums {
        let checksums = compute_checksums(&payload);
        payload.checksums = Some(checksums);
    }

    let (envelope, mut plaintext) = prepare_envelope(
        &payload,
        options.include_checksums,
        consensus.clone(),
        &passphrase,
    )?;

    ensure_backup_dir(backup_dir)?;
    let file_name = format_backup_name(envelope.metadata.created_at_ms);
    let path = backup_dir.join(file_name);
    let encoded =
        to_vec_pretty(&envelope).map_err(|err| BackupError::Serialization(err.to_string()))?;
    ensure_consensus_stable(store, &consensus)?;
    fs::write(&path, encoded)?;
    plaintext.zeroize();
    super::debug_assert_zeroized(plaintext.as_ref());

    Ok(BackupExportResult {
        path,
        metadata: envelope.metadata,
    })
}
