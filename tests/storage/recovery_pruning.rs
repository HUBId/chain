use std::sync::Arc;

use firewood_storage::{
    noop_storage_metrics, AreaIndex, Committed, LinearAddress, MemStore, NodeStore, WritableStorage,
};

fn setup_nodestore() -> (NodeStore<Committed, MemStore>, Arc<MemStore>) {
    let storage = Arc::new(MemStore::new(vec![]));
    let nodestore = NodeStore::new_empty_committed(storage.clone(), noop_storage_metrics())
        .expect("create empty nodestore");
    (nodestore, storage)
}

#[test]
fn leaked_area_reports_dual_error_for_invalid_index() {
    let (nodestore, storage) = setup_nodestore();
    let address = LinearAddress::new(AreaIndex::MIN_AREA_SIZE).expect("non-zero address");

    storage
        .write(address.get(), &[0xff])
        .expect("write corrupt header");

    let error = nodestore
        .read_leaked_area(address)
        .expect_err("invalid area metadata should fail");
    let message = error.to_string();

    assert!(
        message.contains("no free area"),
        "expected missing free area context, got: {message}",
    );
    assert!(
        message.contains("no stored area"),
        "expected missing stored area context, got: {message}",
    );
    assert!(
        message.contains("StoredArea::from_storage"),
        "expected stored area helper in message, got: {message}",
    );
}

#[test]
fn leaked_area_reports_dual_error_for_free_marker_conflict() {
    let (nodestore, storage) = setup_nodestore();
    let address = LinearAddress::new(AreaIndex::MIN_AREA_SIZE * 2).expect("non-zero address");
    let corrupt_bytes = [AreaIndex::MIN.get(), 0xff];

    storage
        .write(address.get(), &corrupt_bytes)
        .expect("write conflicting header");

    let error = nodestore
        .read_leaked_area(address)
        .expect_err("invalid area metadata should fail");
    let message = error.to_string();

    assert!(
        message.contains("no free area"),
        "expected missing free area context, got: {message}",
    );
    assert!(
        message.contains("no stored area"),
        "expected missing stored area context, got: {message}",
    );
    assert!(
        message.contains("Stored area marker indicates a free area"),
        "expected stored area marker diagnostic, got: {message}",
    );
}
