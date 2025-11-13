use crate::db::{WalletStore, WalletStoreBatch, WalletStoreError};

const RESUME_HEIGHT_LABEL: &str = "indexer::resume_height";
const BIRTHDAY_HEIGHT_LABEL: &str = "indexer::birthday_height";
const LAST_SCAN_TS_LABEL: &str = "indexer::last_scan_ts";

/// Load the stored resume height from the wallet store.
pub fn resume_height(store: &WalletStore) -> Result<Option<u64>, WalletStoreError> {
    store.get_checkpoint(RESUME_HEIGHT_LABEL)
}

/// Persist the supplied resume height to the wallet store, removing it when `None`.
pub fn persist_resume_height(
    batch: &mut WalletStoreBatch<'_>,
    height: Option<u64>,
) -> Result<(), WalletStoreError> {
    match height {
        Some(value) => batch.put_checkpoint(RESUME_HEIGHT_LABEL, value)?,
        None => batch.delete_checkpoint(RESUME_HEIGHT_LABEL),
    }
    Ok(())
}

/// Load the configured birthday height from the wallet store.
pub fn birthday_height(store: &WalletStore) -> Result<Option<u64>, WalletStoreError> {
    store.get_checkpoint(BIRTHDAY_HEIGHT_LABEL)
}

/// Persist the supplied birthday height to the wallet store, removing it when `None`.
pub fn persist_birthday_height(
    batch: &mut WalletStoreBatch<'_>,
    height: Option<u64>,
) -> Result<(), WalletStoreError> {
    match height {
        Some(value) => batch.put_checkpoint(BIRTHDAY_HEIGHT_LABEL, value)?,
        None => batch.delete_checkpoint(BIRTHDAY_HEIGHT_LABEL),
    }
    Ok(())
}

/// Fetch the timestamp for the last scan operation, if any.
pub fn last_scan_ts(store: &WalletStore) -> Result<Option<u64>, WalletStoreError> {
    store.get_checkpoint(LAST_SCAN_TS_LABEL)
}

/// Update the stored timestamp for the last scan operation.
pub fn persist_last_scan_ts(
    batch: &mut WalletStoreBatch<'_>,
    timestamp: Option<u64>,
) -> Result<(), WalletStoreError> {
    match timestamp {
        Some(value) => batch.put_checkpoint(LAST_SCAN_TS_LABEL, value)?,
        None => batch.delete_checkpoint(LAST_SCAN_TS_LABEL),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::{
        birthday_height, last_scan_ts, persist_birthday_height, persist_last_scan_ts,
        persist_resume_height, resume_height,
    };
    use crate::db::WalletStore;

    #[test]
    fn resume_height_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let store = WalletStore::open(dir.path()).expect("open store");
        assert_eq!(resume_height(&store).unwrap(), None);

        let mut batch = store.batch().expect("batch");
        persist_resume_height(&mut batch, Some(42)).expect("persist height");
        batch.commit().expect("commit");

        assert_eq!(resume_height(&store).unwrap(), Some(42));

        let mut batch = store.batch().expect("batch update");
        persist_resume_height(&mut batch, None).expect("clear height");
        batch.commit().expect("commit clear");

        assert_eq!(resume_height(&store).unwrap(), None);
    }

    #[test]
    fn birthday_height_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let store = WalletStore::open(dir.path()).expect("open store");
        assert_eq!(birthday_height(&store).unwrap(), None);

        let mut batch = store.batch().expect("batch");
        persist_birthday_height(&mut batch, Some(77)).expect("persist birthday");
        batch.commit().expect("commit");

        assert_eq!(birthday_height(&store).unwrap(), Some(77));

        let mut batch = store.batch().expect("batch clear");
        persist_birthday_height(&mut batch, None).expect("clear");
        batch.commit().expect("commit clear");

        assert_eq!(birthday_height(&store).unwrap(), None);
    }

    #[test]
    fn last_scan_ts_roundtrip() {
        let dir = tempdir().expect("tempdir");
        let store = WalletStore::open(dir.path()).expect("open store");
        assert_eq!(last_scan_ts(&store).unwrap(), None);

        let mut batch = store.batch().expect("batch");
        persist_last_scan_ts(&mut batch, Some(1_650_000_000)).expect("persist ts");
        batch.commit().expect("commit");

        assert_eq!(last_scan_ts(&store).unwrap(), Some(1_650_000_000));

        let mut batch = store.batch().expect("batch clear");
        persist_last_scan_ts(&mut batch, None).expect("clear");
        batch.commit().expect("commit clear");

        assert_eq!(last_scan_ts(&store).unwrap(), None);
    }
}
