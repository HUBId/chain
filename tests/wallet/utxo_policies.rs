use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use rpp_chain::crypto::address_from_public_key;
use rpp_chain::errors::ChainError;
use rpp_chain::reputation::{Tier, TimetokeBalance};
use rpp_chain::runtime::RuntimeMetrics;
use rpp_chain::storage::Storage;
use rpp_chain::types::{Account, Stake};
use rpp_chain::wallet::wallet::Wallet;
use tempfile::TempDir;

use rpp_chain::rpp::{UtxoOutpoint};
use rpp_chain::state::utxo::StoredUtxo;

fn wallet_with_tier_and_utxos(
    tier: Tier,
    balance: u128,
    utxo_values: &[u128],
) -> (Wallet, TempDir) {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let storage = Storage::open(tempdir.path()).expect("open storage");
    let mut rng = OsRng;
    let keypair = Keypair::generate(&mut rng);
    let address = address_from_public_key(&keypair.public);
    let mut account = Account::new(address.clone(), balance, Stake::default());
    account.reputation.tier = tier;
    account.reputation.score = 1.0;
    account.reputation.consensus_success = 200;
    account.reputation.timetokes = TimetokeBalance {
        hours_online: 72,
        ..TimetokeBalance::default()
    };
    account.reputation.zsi.validate("proof");
    storage
        .persist_account(&account)
        .expect("persist account");
    let snapshot: Vec<_> = utxo_values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let mut tx_id = [0u8; 32];
            tx_id[0] = (index as u8).wrapping_add(1);
            (
                UtxoOutpoint {
                    tx_id,
                    index: index as u32,
                },
                StoredUtxo::new(address.clone(), *value),
            )
        })
        .collect();
    storage
        .persist_utxo_snapshot(&snapshot)
        .expect("persist snapshot");
    let wallet = Wallet::new(storage, keypair, RuntimeMetrics::noop());
    (wallet, tempdir)
}

#[test]
fn high_tier_allows_bulk_spend() {
    let utxo_values = [90_000u128, 80_000, 70_000, 60_000];
    let (wallet, _tempdir) = wallet_with_tier_and_utxos(Tier::Tl5, 400_000, &utxo_values);
    let recipient = wallet.address().clone();
    let workflow = wallet
        .workflows()
        .transaction_bundle(recipient, 200_000, 150, None)
        .expect("tl5 spend succeeds");
    assert_eq!(workflow.utxo_inputs.len(), 3);
    assert_eq!(workflow.policy.utxo.tier, Tier::Tl5);
    assert!(workflow.policy.utxo.max_inputs >= 3);
    assert!(workflow.policy.utxo.max_debit_value > 200_000);
}

#[test]
fn tier_two_rejects_excess_inputs() {
    let utxo_values = [20_000u128; 5];
    let (wallet, _tempdir) = wallet_with_tier_and_utxos(Tier::Tl2, 150_000, &utxo_values);
    let recipient = wallet.address().clone();
    let result = wallet
        .workflows()
        .transaction_bundle(recipient, 80_000, 100, None);
    match result {
        Err(ChainError::Transaction(message)) => {
            assert!(message.contains("input count"), "unexpected message: {message}");
        }
        other => panic!("expected policy rejection, got {other:?}"),
    }
}

#[test]
fn tier_two_rejects_large_change() {
    let utxo_values = [120_000u128];
    let (wallet, _tempdir) = wallet_with_tier_and_utxos(Tier::Tl2, 200_000, &utxo_values);
    let recipient = wallet.address().clone();
    let result = wallet
        .workflows()
        .transaction_bundle(recipient, 50_000, 100, None);
    match result {
        Err(ChainError::Transaction(message)) => {
            assert!(message.contains("change value"), "unexpected message: {message}");
        }
        other => panic!("expected policy rejection, got {other:?}"),
    }
}
