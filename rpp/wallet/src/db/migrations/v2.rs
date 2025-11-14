use storage_firewood::{
    column_family::ColumnFamily,
    kv::{FirewoodKv, KvError},
};

use crate::db::{codec, schema, store::WalletStoreError};

/// Apply the schema upgrades required for the v2 layout.
pub fn apply(kv: &mut FirewoodKv) -> Result<bool, WalletStoreError> {
    ensure_extensions(kv)?;
    seed_meta_entries(kv)
}

fn ensure_extensions(kv: &FirewoodKv) -> Result<(), WalletStoreError> {
    let base_dir = kv.base_dir().to_path_buf();
    for name in [
        schema::EXTENSION_PENDING_LOCKS,
        schema::EXTENSION_PROVER_META,
        schema::EXTENSION_CHECKPOINTS,
    ] {
        ColumnFamily::open(&base_dir, name)
            .map_err(|err| WalletStoreError::Storage(KvError::Io(err)))?;
    }
    Ok(())
}

fn seed_meta_entries(kv: &mut FirewoodKv) -> Result<bool, WalletStoreError> {
    let mut mutated = false;
    let defaults = [
        schema::META_LAST_RESCAN_TS_KEY,
        schema::META_FEE_CACHE_FETCHED_TS_KEY,
        schema::META_FEE_CACHE_EXPIRES_TS_KEY,
    ];

    for key in defaults {
        let storage_key = meta_key(key);
        if kv.get(&storage_key).is_none() {
            let encoded = codec::encode_checkpoint(0)?;
            kv.put(storage_key, encoded);
            mutated = true;
        }
    }

    Ok(mutated)
}

fn meta_key(key: &str) -> Vec<u8> {
    let mut namespaced = schema::META_NAMESPACE.to_vec();
    namespaced.extend_from_slice(key.as_bytes());
    namespaced
}
