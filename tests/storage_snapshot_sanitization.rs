use anyhow::Result;
use tempfile::tempdir;

use rpp_chain::storage::Storage;
use rpp_chain::types::{Account, Stake};

#[test]
fn account_snapshots_prune_missing_identities() -> Result<()> {
    let tempdir = tempdir()?;
    let storage = Storage::open(tempdir.path())?;

    let mut alice = Account::new("alice".to_string(), 100, Stake::from_u128(10));
    alice.reputation.zsi.validate("alice-proof");
    let mut bob = Account::new("bob".to_string(), 200, Stake::from_u128(20));
    bob.reputation.zsi.validate("bob-proof");

    storage.apply_account_snapshot(Some(0), &[alice.clone(), bob.clone()])?;
    let initial = storage.load_accounts()?;
    assert_eq!(initial.len(), 2, "both accounts persisted");

    storage.apply_account_snapshot(Some(1), &[alice.clone()])?;
    let sanitized = storage.load_accounts()?;
    assert_eq!(sanitized.len(), 1, "stale accounts removed");
    assert_eq!(sanitized[0].address, alice.address);
    assert_eq!(sanitized[0].balance, alice.balance);

    Ok(())
}
