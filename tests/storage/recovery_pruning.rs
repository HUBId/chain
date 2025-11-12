use std::io::Read;
use std::sync::Arc;

use firewood_storage::{
    noop_storage_metrics, AreaIndex, CheckOpt, Committed, ImmutableProposal, LinearAddress,
    MemStore, MutableProposal, NodeStore, NodeStoreHeader, WritableStorage,
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

#[test]
fn leaked_area_fix_enqueues_and_reuses_free_blocks() {
    let (_, storage) = setup_nodestore();

    let mut header = NodeStoreHeader::new();
    let area_index = AreaIndex::MIN;
    let area_size = area_index.size();
    let leak_span = area_size * 2;
    header.set_size(NodeStoreHeader::SIZE + leak_span);

    storage
        .write(0, bytemuck::bytes_of(&header))
        .expect("persist header");

    let first_addr = LinearAddress::new(NodeStoreHeader::SIZE).expect("aligned address");
    let second_addr = first_addr
        .advance(area_size)
        .expect("second leaked area address");

    write_free_area_stub(storage.as_ref(), first_addr, area_index, None);
    write_free_area_stub(storage.as_ref(), second_addr, area_index, None);

    let committed = NodeStore::open(storage.clone(), noop_storage_metrics())
        .expect("open nodestore with leaks");

    let (committed_res, fix_report) = committed.check_and_fix(CheckOpt {
        hash_check: false,
        progress_bar: None,
    });
    assert!(
        fix_report.unfixable.is_empty(),
        "unexpected unfixable errors"
    );
    assert_eq!(fix_report.fixed.len(), 1, "expected single leak fix");

    let committed = committed_res.expect("proposal conversion succeeded");
    committed
        .flush_freelist()
        .expect("flush freelist after recovery");

    let mutable_after_fix = NodeStore::<MutableProposal, _>::new(&committed)
        .expect("create proposal after recovery");
    let immutable_after_fix =
        NodeStore::<Arc<ImmutableProposal>, _>::try_from(mutable_after_fix)
            .expect("convert repaired proposal to immutable");
    let recommitted = immutable_after_fix.as_committed(&committed);
    recommitted
        .flush_freelist()
        .expect("flush freelist after recommitting repaired store");

    let header_after_fix = read_header(storage.as_ref());
    let freelist_head = header_after_fix.free_lists()[area_index.as_usize()]
        .expect("leaked areas added to free list");
    assert_eq!(
        freelist_head, second_addr,
        "latest leak should head freelist"
    );

    let (second_index, second_next) = parse_free_area(storage.as_ref(), second_addr);
    assert_eq!(
        second_index,
        area_index.get(),
        "freelist head size mismatch"
    );
    assert_eq!(
        second_next,
        Some(first_addr),
        "head should reference first leak"
    );

    let (first_index, first_next) = parse_free_area(storage.as_ref(), first_addr);
    assert_eq!(first_index, area_index.get(), "first leak size mismatch");
    assert!(first_next.is_none(), "first leak should terminate chain");

    // Simulate allocations by updating the freelist head to the recorded next pointers.
    let mut header_after_first_alloc = header_after_fix;
    header_after_first_alloc.free_lists_mut()[area_index.as_usize()] = second_next;
    storage
        .write(0, bytemuck::bytes_of(&header_after_first_alloc))
        .expect("persist freelist pop");

    let header_after_consume_one = read_header(storage.as_ref());
    assert_eq!(
        header_after_consume_one.free_lists()[area_index.as_usize()],
        Some(first_addr),
        "freelist should advance to first leak after consumption",
    );

    let mut header_after_second_alloc = header_after_consume_one;
    header_after_second_alloc.free_lists_mut()[area_index.as_usize()] = None;
    storage
        .write(0, bytemuck::bytes_of(&header_after_second_alloc))
        .expect("persist freelist exhaustion");

    let header_after_consume_all = read_header(storage.as_ref());
    assert!(
        header_after_consume_all.free_lists()[area_index.as_usize()].is_none(),
        "freelist should be empty after consuming all leaked blocks",
    );
}

fn write_free_area_stub(
    storage: &MemStore,
    address: LinearAddress,
    area_index: AreaIndex,
    next: Option<LinearAddress>,
) {
    let mut bytes = vec![0u8; area_index.size() as usize];
    bytes[0] = area_index.get();
    bytes[1] = 0xff;

    let mut next_value = next.map_or(0, LinearAddress::get);
    let mut offset = 2usize;
    loop {
        let mut byte = (next_value & 0x7f) as u8;
        next_value >>= 7;
        if next_value != 0 {
            byte |= 0x80;
        }
        bytes[offset] = byte;
        offset += 1;
        if next_value == 0 {
            break;
        }
    }

    storage
        .write(address.get(), &bytes)
        .expect("write free area stub");
}

fn parse_free_area(storage: &MemStore, address: LinearAddress) -> (u8, Option<LinearAddress>) {
    let mut reader = storage
        .stream_from(address.get())
        .expect("stream free area bytes");

    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf).expect("read area index");
    let area_index = buf[0];

    reader.read_exact(&mut buf).expect("read free marker");
    assert_eq!(buf[0], 0xff, "expected free area marker");

    let next = read_varint(&mut reader);
    let next_addr = if next == 0 {
        None
    } else {
        Some(LinearAddress::new(next).expect("valid next pointer"))
    };

    (area_index, next_addr)
}

fn read_varint(reader: &mut impl Read) -> u64 {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf).expect("read varint byte");
        let byte = buf[0];
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

fn read_header(storage: &MemStore) -> NodeStoreHeader {
    let mut reader = storage.stream_from(0).expect("stream header");
    let mut header_bytes = vec![0u8; std::mem::size_of::<NodeStoreHeader>()];
    reader
        .read_exact(&mut header_bytes)
        .expect("read header bytes");
    *NodeStoreHeader::from_bytes(&header_bytes)
}
