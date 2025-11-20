pub mod codec;
pub(crate) mod migrations;
pub mod schema;
pub mod store;

pub use codec::StoredZsiArtifact;
pub use codec::{
    Address, AddressMetadata, PendingLock, PendingLockMetadata, PolicySnapshot, ProverMeta,
    TxCacheEntry, UtxoOutpoint, UtxoRecord, WatchOnlyRecord,
};
pub use store::{AddressKind, WalletStore, WalletStoreBatch, WalletStoreError};

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::path::Path;

    use tempfile::tempdir;

    use super::{
        codec, schema,
        store::{AddressKind, WalletStore},
        PendingLock, PolicySnapshot, ProverMeta, StoredZsiArtifact, TxCacheEntry, UtxoOutpoint,
        UtxoRecord, WatchOnlyRecord,
    };

    #[test]
    fn store_initialises_schema_marker() {
        let dir = tempdir().expect("tempdir");
        let store = WalletStore::open(dir.path()).expect("open store");
        assert_eq!(store.schema_version().unwrap(), schema::SCHEMA_VERSION_V4);

        let base = dir.path();
        for bucket in [
            schema::BUCKET_BACKUP_META,
            schema::BUCKET_WATCH_ONLY,
            schema::BUCKET_MULTISIG_SCOPE,
            schema::BUCKET_ZSI,
            schema::BUCKET_SECURITY_RBAC,
            schema::BUCKET_SECURITY_MTLS,
            schema::BUCKET_HW_REGISTRY,
        ] {
            assert!(base.join(bucket).is_dir(), "missing bucket {bucket}");
        }

        for extension in [
            schema::EXTENSION_PENDING_LOCKS,
            schema::EXTENSION_PROVER_META,
            schema::EXTENSION_CHECKPOINTS,
        ] {
            assert!(
                base.join(extension).is_dir(),
                "missing extension {extension}"
            );
        }

        let schema_bytes = store
            .get_backup_meta(schema::BACKUP_META_SCHEMA_VERSION_KEY)
            .expect("backup schema meta")
            .expect("schema marker present");
        assert_eq!(
            codec::decode_schema_version(&schema_bytes).expect("decode schema"),
            schema::SCHEMA_VERSION_V3
        );

        let export_bytes = store
            .get_backup_meta(schema::BACKUP_META_EXPORT_TS_KEY)
            .expect("backup export meta")
            .expect("export timestamp present");
        assert_eq!(
            codec::decode_checkpoint(&export_bytes).expect("decode export timestamp"),
            0
        );
    }

    #[test]
    fn store_migrates_schema_to_v3() {
        let dir = tempdir().expect("tempdir");
        {
            let mut kv = storage_firewood::kv::FirewoodKv::open(dir.path()).expect("open kv");
            kv.put(
                schema::SCHEMA_VERSION_KEY.to_vec(),
                codec::encode_schema_version(0).expect("encode"),
            );
            kv.commit().expect("commit");
        }
        let store = WalletStore::open(dir.path()).expect("open store");
        assert_eq!(store.schema_version().unwrap(), schema::SCHEMA_VERSION_V4);

        let base = dir.path();
        for bucket in [
            schema::BUCKET_BACKUP_META,
            schema::BUCKET_WATCH_ONLY,
            schema::BUCKET_MULTISIG_SCOPE,
            schema::BUCKET_ZSI,
            schema::BUCKET_SECURITY_RBAC,
            schema::BUCKET_SECURITY_MTLS,
            schema::BUCKET_HW_REGISTRY,
        ] {
            assert!(base.join(bucket).is_dir(), "missing bucket {bucket}");
        }

        for extension in [
            schema::EXTENSION_PENDING_LOCKS,
            schema::EXTENSION_PROVER_META,
            schema::EXTENSION_CHECKPOINTS,
        ] {
            assert!(
                base.join(extension).is_dir(),
                "missing extension {extension}"
            );
        }

        let schema_bytes = store
            .get_backup_meta(schema::BACKUP_META_SCHEMA_VERSION_KEY)
            .expect("backup schema meta")
            .expect("schema marker present");
        assert_eq!(
            codec::decode_schema_version(&schema_bytes).expect("decode schema"),
            schema::SCHEMA_VERSION_V3
        );

        let export_bytes = store
            .get_backup_meta(schema::BACKUP_META_EXPORT_TS_KEY)
            .expect("backup export meta")
            .expect("export timestamp present");
        assert_eq!(
            codec::decode_checkpoint(&export_bytes).expect("decode export timestamp"),
            0
        );
    }

    #[test]
    fn store_upgrades_v2_fixture_without_data_loss() {
        let dir = tempdir().expect("tempdir");
        let fixture = seed_v2_fixture(dir.path());

        let store = WalletStore::open(dir.path()).expect("open store");
        assert_eq!(store.schema_version().unwrap(), schema::SCHEMA_VERSION_V4);
        assert_eq!(
            store.get_meta("network").unwrap(),
            Some(b"mainnet".to_vec())
        );
        assert_eq!(
            store.watch_only_record().unwrap(),
            Some(fixture.watch_only.clone())
        );
        assert_eq!(
            store
                .get_zsi_artifact(&fixture.zsi_identity, &fixture.zsi_commitment)
                .unwrap()
                .unwrap(),
            fixture.zsi_artifact.clone()
        );

        let export_bytes = store
            .get_backup_meta(schema::BACKUP_META_EXPORT_TS_KEY)
            .expect("backup export meta")
            .expect("export timestamp present");
        assert_eq!(
            codec::decode_checkpoint(&export_bytes).expect("decode export timestamp"),
            0
        );

        drop(store);

        let reopened = WalletStore::open(dir.path()).expect("reopen store");
        assert_eq!(
            reopened.watch_only_record().unwrap(),
            Some(fixture.watch_only.clone())
        );
        assert_eq!(
            reopened
                .get_zsi_artifact(&fixture.zsi_identity, &fixture.zsi_commitment)
                .unwrap()
                .unwrap(),
            fixture.zsi_artifact
        );
    }

    #[test]
    fn bucket_roundtrip_exercises_core_helpers() {
        let dir = tempdir().expect("tempdir");
        let store = WalletStore::open(dir.path()).expect("open store");
        let mut batch = store.batch().expect("batch");
        batch.put_meta("network", b"testnet");
        batch
            .put_key_material("seed", &[7, 8, 9])
            .expect("key material");
        batch
            .put_address(AddressKind::External, 0, &"fw1addr".into())
            .expect("address");
        let utxo = UtxoRecord::new(
            UtxoOutpoint::new([3u8; 32], 11),
            "fw1addr".into(),
            1_000,
            Cow::Borrowed(&[0u8, 1, 2, 3]),
            Some(64),
        );
        batch.put_utxo(&utxo).expect("put utxo");
        let tx_entry = TxCacheEntry::new(5, 1_650_000_000_000, Cow::Borrowed(&[4u8; 4]));
        batch
            .put_tx_cache_entry(&[6u8; 32], &tx_entry)
            .expect("put tx cache");
        let snapshot = PolicySnapshot::new(2, 10, vec!["allow".into(), "deny".into()]);
        batch
            .put_policy_snapshot("default", &snapshot)
            .expect("policy snapshot");
        batch.put_checkpoint("sync", 256).expect("checkpoint");
        let watch_only = WatchOnlyRecord::new("wpkh(external)")
            .with_internal_descriptor("wpkh(internal)")
            .with_account_xpub("xpub-test")
            .with_birthday_height(Some(77));
        batch
            .put_watch_only(&watch_only)
            .expect("watch-only record");
        let artifact = StoredZsiArtifact::new(
            1_700_000_000_000,
            "alice".into(),
            "proof-digest".into(),
            "mock-backend".into(),
            Cow::Borrowed(&[5u8, 6, 7, 8]),
        );
        batch.put_zsi_artifact(&artifact).expect("put zsi artifact");
        batch.commit().expect("commit");

        let prover_meta = ProverMeta::new(
            [7u8; 32],
            "mock-backend".into(),
            500,
            256,
            Some(128),
            Some("face".into()),
            1_700_000_000_500,
            Some(1_700_000_000_750),
            "ok".into(),
        );
        store
            .put_prover_meta(&prover_meta)
            .expect("put prover meta");

        assert_eq!(
            store.get_meta("network").unwrap(),
            Some(b"testnet".to_vec())
        );
        assert_eq!(store.get_key_material("seed").unwrap(), Some(vec![7, 8, 9]));
        assert_eq!(
            store
                .get_address(AddressKind::External, 0)
                .unwrap()
                .as_deref(),
            Some("fw1addr")
        );
        assert_eq!(
            store.iter_addresses(AddressKind::External).unwrap().len(),
            1
        );
        assert_eq!(
            store
                .get_utxo(&utxo.outpoint)
                .unwrap()
                .unwrap()
                .into_owned(),
            utxo.clone().into_owned()
        );
        assert_eq!(store.iter_utxos().unwrap().len(), 1);
        assert_eq!(
            store
                .get_tx_cache_entry(&[6u8; 32])
                .unwrap()
                .unwrap()
                .into_owned(),
            tx_entry.clone().into_owned()
        );
        assert_eq!(store.iter_tx_cache_entries().unwrap().len(), 1);
        assert_eq!(
            store.get_policy_snapshot("default").unwrap().unwrap(),
            snapshot
        );
        assert_eq!(store.iter_policy_snapshots().unwrap().len(), 1);
        assert_eq!(store.get_checkpoint("sync").unwrap(), Some(256));
        assert_eq!(store.iter_checkpoints().unwrap().len(), 1);
        assert_eq!(store.watch_only_record().unwrap(), Some(watch_only.clone()));
        assert_eq!(
            store
                .get_zsi_artifact("alice", "proof-digest")
                .unwrap()
                .unwrap(),
            artifact.clone().into_owned()
        );
        assert_eq!(
            store.iter_zsi_artifacts().unwrap(),
            vec![artifact.clone().into_owned()]
        );
        assert_eq!(
            store.get_prover_meta(&[7u8; 32]).unwrap(),
            Some(prover_meta)
        );

        let mut cleanup = store.batch().expect("cleanup batch");
        cleanup.delete_utxo(&utxo.outpoint);
        cleanup.delete_tx_cache_entry(&[6u8; 32]);
        cleanup.delete_policy_snapshot("default");
        cleanup.delete_checkpoint("sync");
        cleanup.clear_watch_only();
        cleanup.delete_zsi_artifact("alice", "proof-digest");
        cleanup.commit().expect("cleanup commit");

        assert!(store.get_utxo(&utxo.outpoint).unwrap().is_none());
        assert!(store.get_tx_cache_entry(&[6u8; 32]).unwrap().is_none());
        assert!(store.get_policy_snapshot("default").unwrap().is_none());
        assert!(store.get_checkpoint("sync").unwrap().is_none());
        assert!(store.watch_only_record().unwrap().is_none());
        assert!(store
            .get_zsi_artifact("alice", "proof-digest")
            .unwrap()
            .is_none());
        assert!(store.iter_zsi_artifacts().unwrap().is_empty());
    }

    struct V2FixtureState {
        watch_only: WatchOnlyRecord,
        zsi_identity: String,
        zsi_commitment: String,
        zsi_artifact: StoredZsiArtifact<'static>,
    }

    fn seed_v2_fixture(path: &Path) -> V2FixtureState {
        let mut kv = storage_firewood::kv::FirewoodKv::open(path).expect("open kv");
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
            .with_birthday_height(Some(32));
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
            Cow::Owned(vec![1u8, 2, 3, 4]),
        );
        let encoded_artifact = codec::encode_zsi_artifact(&artifact).expect("encode artifact");
        kv.put(zsi_key(&identity, &commitment), encoded_artifact);

        kv.commit().expect("commit v2");

        V2FixtureState {
            watch_only,
            zsi_identity: identity,
            zsi_commitment: commitment,
            zsi_artifact: artifact.into_owned(),
        }
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

    #[test]
    fn pending_lock_helpers_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let store = WalletStore::open(dir.path()).expect("open store");
        let outpoint = UtxoOutpoint::new([8u8; 32], 3);
        let lock = PendingLock::new(outpoint.clone(), 1_650_000_123_000, Some([1u8; 32]));

        {
            let mut batch = store.batch().expect("batch");
            batch.put_pending_lock(&lock).expect("put lock");
            batch.commit().expect("commit");
        }

        let fetched = store
            .get_pending_lock(&outpoint)
            .expect("get lock")
            .expect("lock present");
        assert_eq!(fetched, lock);

        let iterated = store.iter_pending_locks().expect("iter locks");
        assert_eq!(iterated, vec![lock.clone()]);

        let mut cleanup = store.batch().expect("cleanup");
        cleanup.delete_pending_lock(&outpoint);
        cleanup.commit().expect("cleanup commit");

        assert!(store.get_pending_lock(&outpoint).unwrap().is_none());
        assert!(store.iter_pending_locks().unwrap().is_empty());
    }
}
