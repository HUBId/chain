use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde_json::from_slice;
use zeroize::{Zeroize, Zeroizing};

use super::{
    apply_meta, compute_checksums, decode_payload, decrypt_envelope, resolve_backup_path,
    verify_schema_checksum, BackupEnvelope, BackupError, BackupMetadata, BackupPayload,
};
use crate::db::WalletStore;
use crate::indexer::checkpoints;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackupValidationMode {
    DryRun,
    Full,
}

#[derive(Debug, Clone)]
pub struct BackupValidation {
    pub metadata: BackupMetadata,
    pub has_keystore: bool,
    pub policy_count: usize,
    pub meta_entries: usize,
}

#[derive(Debug, Clone)]
pub struct BackupImportOutcome {
    pub metadata: BackupMetadata,
    pub restored_keystore: bool,
    pub restored_policy: bool,
    pub rescan_from: u64,
}

pub fn backup_validate(
    store: &WalletStore,
    backup_dir: &Path,
    name: &str,
    passphrase: Zeroizing<Vec<u8>>,
    mode: BackupValidationMode,
) -> Result<BackupValidation, BackupError> {
    let _ = store.schema_version()?;
    let (envelope, payload, mut plaintext) = load_backup(backup_dir, name, &passphrase)?;
    verify_schema_checksum(&envelope.metadata)?;
    if matches!(mode, BackupValidationMode::Full) {
        verify_checksums(&envelope.metadata, &payload)?;
    }

    plaintext.zeroize();

    Ok(BackupValidation {
        metadata: envelope.metadata,
        has_keystore: payload.keystore.is_some(),
        policy_count: payload.policies.len(),
        meta_entries: payload.meta.len(),
    })
}

pub fn backup_import(
    store: &WalletStore,
    keystore_path: &Path,
    backup_dir: &Path,
    name: &str,
    passphrase: Zeroizing<Vec<u8>>,
) -> Result<BackupImportOutcome, BackupError> {
    let (envelope, payload, mut plaintext) = load_backup(backup_dir, name, &passphrase)?;
    verify_schema_checksum(&envelope.metadata)?;
    verify_checksums(&envelope.metadata, &payload)?;
    plaintext.zeroize();

    let BackupPayload {
        keystore,
        meta,
        policies,
        zsi_artifacts,
        ..
    } = payload;

    let desired_meta: BTreeSet<String> = meta.iter().map(|entry| entry.key.clone()).collect();
    let existing_meta = store.iter_meta()?;

    let desired_policies: BTreeSet<String> =
        policies.iter().map(|(label, _)| label.clone()).collect();
    let existing_policies = store.iter_policy_snapshots()?;

    let desired_zsi: BTreeSet<(String, String)> = zsi_artifacts
        .iter()
        .map(|artifact| {
            (
                artifact.identity.clone(),
                artifact.commitment_digest.clone(),
            )
        })
        .collect();
    let existing_zsi = store.iter_zsi_artifacts()?;

    {
        let mut batch = store.batch()?;
        for (key, _) in existing_meta {
            if !desired_meta.contains(&key) {
                batch.delete_meta(&key);
            }
        }
        apply_meta(&mut batch, &meta);

        for (label, _) in existing_policies {
            if !desired_policies.contains(&label) {
                batch.delete_policy_snapshot(&label);
            }
        }
        for (label, snapshot) in &policies {
            batch.put_policy_snapshot(label, snapshot)?;
        }
        for artifact in existing_zsi {
            let key = (
                artifact.identity.clone(),
                artifact.commitment_digest.clone(),
            );
            if !desired_zsi.contains(&key) {
                batch.delete_zsi_artifact(&artifact.identity, &artifact.commitment_digest);
            }
        }
        for artifact in &zsi_artifacts {
            batch.put_zsi_artifact(artifact)?;
        }
        batch.commit()?;
    }

    if let Some(keystore) = keystore {
        if let Some(parent) = keystore_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut data = Zeroizing::new(keystore);
        fs::write(keystore_path, data.as_ref())?;
        data.zeroize();
    }

    let rescan_from = checkpoints::birthday_height(store)?.unwrap_or(0);
    Ok(BackupImportOutcome {
        metadata: envelope.metadata,
        restored_keystore: keystore.is_some(),
        restored_policy: !policies.is_empty(),
        rescan_from,
    })
}

fn load_backup(
    backup_dir: &Path,
    name: &str,
    passphrase: &Zeroizing<Vec<u8>>,
) -> Result<(BackupEnvelope, BackupPayload, Zeroizing<Vec<u8>>), BackupError> {
    let path = resolve_backup_path(backup_dir, name)?;
    let contents = fs::read(&path)?;
    let envelope: BackupEnvelope =
        from_slice(&contents).map_err(|err| BackupError::Serialization(err.to_string()))?;
    let plaintext = decrypt_envelope(&envelope, passphrase)?;
    let payload = decode_payload(plaintext.as_ref())?;
    Ok((envelope, payload, plaintext))
}

fn verify_checksums(metadata: &BackupMetadata, payload: &BackupPayload) -> Result<(), BackupError> {
    if !metadata.include_checksums {
        return Ok(());
    }
    let expected = payload
        .checksums
        .as_ref()
        .ok_or_else(|| BackupError::Invalid("backup is missing checksum manifest".into()))?;
    let actual = compute_checksums(payload);
    for (component, digest) in expected {
        match actual.get(component) {
            Some(current) if current == digest => {}
            _ => {
                return Err(BackupError::ChecksumMismatch {
                    component: component.clone(),
                })
            }
        }
    }
    Ok(())
}
