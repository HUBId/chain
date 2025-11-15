use storage_firewood::kv::FirewoodKv;

use crate::db::store::WalletStoreError;

/// Apply the schema upgrades required for the v3 layout.
pub fn apply(_kv: &mut FirewoodKv) -> Result<bool, WalletStoreError> {
    // No on-disk mutations are required for this version. The new ZSI namespace
    // is provisioned lazily when artefacts are written.
    Ok(false)
}
