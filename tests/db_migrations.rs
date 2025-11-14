use std::path::Path;

use rpp_wallet::db::{codec, schema, WalletStore};
use storage_firewood::kv::FirewoodKv;
use tempfile::tempdir;

#[test]
fn v1_wallet_store_upgrades_to_v2_schema() {
    let dir = tempdir().expect("tempdir");
    seed_v1_schema(dir.path());

    let store = WalletStore::open(dir.path()).expect("open store");

    assert_eq!(
        store.schema_version().expect("schema version"),
        schema::SCHEMA_VERSION_V2
    );
    assert_eq!(
        store
            .last_rescan_timestamp()
            .expect("last rescan timestamp"),
        Some(0)
    );
    assert_eq!(store.fee_cache_fetched_at().expect("fee fetched"), Some(0));
    assert_eq!(store.fee_cache_expires_at().expect("fee expires"), Some(0));

    assert_extension_exists(dir.path(), schema::EXTENSION_PENDING_LOCKS);
    assert_extension_exists(dir.path(), schema::EXTENSION_PROVER_META);
    assert_extension_exists(dir.path(), schema::EXTENSION_CHECKPOINTS);

    drop(store);

    // Re-opening should remain idempotent and keep the metadata intact.
    let reopened = WalletStore::open(dir.path()).expect("reopen store");
    assert_eq!(
        reopened.schema_version().expect("schema version"),
        schema::SCHEMA_VERSION_V2
    );
    assert_eq!(
        reopened
            .last_rescan_timestamp()
            .expect("last rescan timestamp"),
        Some(0)
    );
    assert_eq!(
        reopened.fee_cache_fetched_at().expect("fee fetched"),
        Some(0)
    );
    assert_eq!(
        reopened.fee_cache_expires_at().expect("fee expires"),
        Some(0)
    );
}

fn seed_v1_schema(path: &Path) {
    let mut kv = FirewoodKv::open(path).expect("open kv");
    kv.put(
        schema::SCHEMA_VERSION_KEY.to_vec(),
        codec::encode_schema_version(schema::SCHEMA_VERSION_V1).expect("encode v1"),
    );
    kv.commit().expect("commit v1 schema");
}

fn assert_extension_exists(base: &Path, extension: &str) {
    let extension_path = base.join(extension);
    assert!(extension_path.is_dir(), "missing extension {extension}");
}
