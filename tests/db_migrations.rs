#![cfg(feature = "wallet-integration")]

use std::path::Path;

use std::borrow::Cow;

use rpp_wallet::db::{codec, schema, StoredZsiArtifact, WalletStore, WatchOnlyRecord};
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

#[test]
fn v2_wallet_store_upgrades_to_v3_schema() {
    let dir = tempdir().expect("tempdir");
    let fixture = seed_v2_schema(dir.path());

    let store = WalletStore::open(dir.path()).expect("open store");

    assert_eq!(
        store.schema_version().expect("schema version"),
        schema::SCHEMA_VERSION_V3
    );
    assert_eq!(
        store.get_meta("network").expect("network meta"),
        Some(b"mainnet".to_vec())
    );
    assert_eq!(
        store.watch_only_record().expect("watch-only"),
        Some(fixture.watch_only.clone())
    );
    assert_eq!(
        store
            .get_zsi_artifact(&fixture.zsi_identity, &fixture.zsi_commitment)
            .expect("zsi artifact")
            .expect("artifact present"),
        fixture.zsi_artifact.clone()
    );

    let schema_bytes = store
        .get_backup_meta(schema::BACKUP_META_SCHEMA_VERSION_KEY)
        .expect("backup schema meta")
        .expect("schema entry present");
    assert_eq!(
        codec::decode_schema_version(&schema_bytes).expect("decode schema"),
        schema::SCHEMA_VERSION_V3
    );

    let export_bytes = store
        .get_backup_meta(schema::BACKUP_META_EXPORT_TS_KEY)
        .expect("backup export meta")
        .expect("export entry present");
    assert_eq!(
        codec::decode_checkpoint(&export_bytes).expect("decode export timestamp"),
        0
    );

    drop(store);

    let reopened = WalletStore::open(dir.path()).expect("reopen store");
    assert_eq!(
        reopened.watch_only_record().expect("watch-only"),
        Some(fixture.watch_only.clone())
    );
    assert_eq!(
        reopened
            .get_zsi_artifact(&fixture.zsi_identity, &fixture.zsi_commitment)
            .expect("zsi artifact")
            .expect("artifact present"),
        fixture.zsi_artifact
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

struct V2SchemaFixture {
    watch_only: WatchOnlyRecord,
    zsi_identity: String,
    zsi_commitment: String,
    zsi_artifact: StoredZsiArtifact<'static>,
}

fn seed_v2_schema(path: &Path) -> V2SchemaFixture {
    let mut kv = FirewoodKv::open(path).expect("open kv");
    kv.put(
        schema::SCHEMA_VERSION_KEY.to_vec(),
        codec::encode_schema_version(schema::SCHEMA_VERSION_V2).expect("encode v2"),
    );
    kv.put(
        namespaced(schema::META_NAMESPACE, b"network"),
        b"mainnet".to_vec(),
    );

    let watch_only = WatchOnlyRecord::new("wpkh(external)")
        .with_internal_descriptor("wpkh(internal)")
        .with_account_xpub("xpub-test")
        .with_birthday_height(Some(21));
    let encoded_watch_only = codec::encode_watch_only(&watch_only).expect("encode watch-only");
    kv.put(
        namespaced(
            schema::WATCH_ONLY_NAMESPACE,
            schema::WATCH_ONLY_STATE_KEY.as_bytes(),
        ),
        encoded_watch_only,
    );

    let identity = "alice".to_string();
    let commitment = "proof-digest".to_string();
    let artifact = StoredZsiArtifact::new(
        1_700_000_000_000,
        identity.clone(),
        commitment.clone(),
        "mock".into(),
        Cow::Owned(vec![9u8, 8, 7, 6]),
    );
    let encoded_artifact = codec::encode_zsi_artifact(&artifact).expect("encode artifact");
    kv.put(zsi_key(&identity, &commitment), encoded_artifact);

    kv.commit().expect("commit v2 schema");

    V2SchemaFixture {
        watch_only,
        zsi_identity: identity,
        zsi_commitment: commitment,
        zsi_artifact: artifact.into_owned(),
    }
}

fn assert_extension_exists(base: &Path, extension: &str) {
    let extension_path = base.join(extension);
    assert!(extension_path.is_dir(), "missing extension {extension}");
}

fn namespaced(prefix: &[u8], suffix: &[u8]) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(suffix);
    key
}

fn zsi_key(identity: &str, commitment_digest: &str) -> Vec<u8> {
    let mut key = schema::ZSI_NAMESPACE.to_vec();
    let identity_bytes = identity.as_bytes();
    let identity_len =
        u32::try_from(identity_bytes.len()).expect("identity label exceeds u32::MAX bytes");
    key.extend_from_slice(&identity_len.to_be_bytes());
    key.extend_from_slice(identity_bytes);
    key.extend_from_slice(commitment_digest.as_bytes());
    key
}
