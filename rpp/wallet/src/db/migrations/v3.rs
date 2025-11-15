use std::fs;

use storage_firewood::kv::{FirewoodKv, KvError};

use crate::db::{codec, schema, store::WalletStoreError};

/// Apply the schema upgrades required for the v3 layout.
pub fn apply(kv: &mut FirewoodKv) -> Result<bool, WalletStoreError> {
    ensure_buckets(kv)?;
    seed_backup_meta(kv)
}

fn ensure_buckets(kv: &FirewoodKv) -> Result<(), WalletStoreError> {
    let base_dir = kv.base_dir().to_path_buf();
    for bucket in [
        schema::BUCKET_BACKUP_META,
        schema::BUCKET_WATCH_ONLY,
        schema::BUCKET_MULTISIG_SCOPE,
        schema::BUCKET_ZSI,
        schema::BUCKET_SECURITY_RBAC,
        schema::BUCKET_SECURITY_MTLS,
        schema::BUCKET_HW_REGISTRY,
    ] {
        fs::create_dir_all(base_dir.join(bucket))
            .map_err(|err| WalletStoreError::Storage(KvError::Io(err)))?;
    }
    Ok(())
}

fn seed_backup_meta(kv: &mut FirewoodKv) -> Result<bool, WalletStoreError> {
    let mut mutated = false;

    let schema_key = backup_meta_key(schema::BACKUP_META_SCHEMA_VERSION_KEY);
    if kv.get(&schema_key).is_none() {
        let encoded = codec::encode_schema_version(schema::SCHEMA_VERSION_V3)?;
        kv.put(schema_key, encoded);
        mutated = true;
    }

    let exported_at_key = backup_meta_key(schema::BACKUP_META_EXPORT_TS_KEY);
    if kv.get(&exported_at_key).is_none() {
        let encoded = codec::encode_checkpoint(0)?;
        kv.put(exported_at_key, encoded);
        mutated = true;
    }

    Ok(mutated)
}

fn backup_meta_key(key: &str) -> Vec<u8> {
    let mut namespaced = schema::BACKUP_META_NAMESPACE.to_vec();
    namespaced.extend_from_slice(key.as_bytes());
    namespaced
}
