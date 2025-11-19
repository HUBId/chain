use storage_firewood::{
    column_family::ColumnFamily,
    kv::{FirewoodKv, KvError},
};

use crate::db::{schema, store::WalletStoreError};

/// Apply the schema upgrades required for the v4 layout.
pub fn apply(kv: &mut FirewoodKv) -> Result<bool, WalletStoreError> {
    ensure_prover_meta_extension(kv)?;
    Ok(false)
}

fn ensure_prover_meta_extension(kv: &FirewoodKv) -> Result<(), WalletStoreError> {
    ColumnFamily::open(kv.base_dir(), schema::EXTENSION_PROVER_META)
        .map_err(|err| WalletStoreError::Storage(KvError::Io(err)))?;
    Ok(())
}
