pub mod codec;
pub(crate) mod migrations;
pub mod schema;
pub mod store;

pub use codec::{
    Address, PendingLock, PendingLockMetadata, PolicySnapshot, TxCacheEntry, UtxoOutpoint,
    UtxoRecord, WatchOnlyRecord,
};
pub use store::{AddressKind, WalletStore, WalletStoreBatch, WalletStoreError};

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use tempfile::tempdir;

    use super::{
        codec, schema,
        store::{AddressKind, WalletStore},
        PendingLock, PolicySnapshot, TxCacheEntry, UtxoOutpoint, UtxoRecord, WatchOnlyRecord,
    };

    #[test]
    fn store_initialises_schema_marker() {
        let dir = tempdir().expect("tempdir");
        let store = WalletStore::open(dir.path()).expect("open store");
        assert_eq!(store.schema_version().unwrap(), schema::SCHEMA_VERSION_V2);
    }

    #[test]
    fn store_migrates_schema_to_v2() {
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
        assert_eq!(store.schema_version().unwrap(), schema::SCHEMA_VERSION_V2);
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
        batch.commit().expect("commit");

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

        let mut cleanup = store.batch().expect("cleanup batch");
        cleanup.delete_utxo(&utxo.outpoint);
        cleanup.delete_tx_cache_entry(&[6u8; 32]);
        cleanup.delete_policy_snapshot("default");
        cleanup.delete_checkpoint("sync");
        cleanup.clear_watch_only();
        cleanup.commit().expect("cleanup commit");

        assert!(store.get_utxo(&utxo.outpoint).unwrap().is_none());
        assert!(store.get_tx_cache_entry(&[6u8; 32]).unwrap().is_none());
        assert!(store.get_policy_snapshot("default").unwrap().is_none());
        assert!(store.get_checkpoint("sync").unwrap().is_none());
        assert!(store.watch_only_record().unwrap().is_none());
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
