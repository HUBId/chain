use rpp_chain::runtime::wallet::sync::{DeterministicSync, SyncProvider};

#[test]
fn deterministic_sync_provider_is_stable() {
    let provider = DeterministicSync::new("wallet-sync").with_height(42);
    let first = provider.latest_checkpoint().expect("checkpoint");
    let second = provider.latest_checkpoint().expect("checkpoint");
    assert_eq!(first, second);
    assert_eq!(first.height, 42);
    assert_ne!(first.hash, [0u8; 32]);
}
