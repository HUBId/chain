#![cfg(all(feature = "wallet-integration", feature = "wallet-ui"))]

use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use rpp_chain::crypto::address_from_public_key;
use rpp_chain::errors::ChainError;
use rpp_chain::rpp::{UtxoOutpoint, UtxoRecord};
use rpp_chain::runtime::RuntimeMetrics;
use rpp_chain::state::utxo::{StoredUtxo, UtxoState, locking_script_hash};
use rpp_chain::storage::Storage;
use rpp_chain::types::{Account, Stake};
use rpp_chain::wallet::{Wallet, WalletWorkflows};

#[test]
fn transaction_workflow_matches_snapshot_commitment() {
    let tempdir = tempfile::tempdir().expect("temp dir");
    let storage = Storage::open(tempdir.path()).expect("open storage");

    let mut rng = OsRng;
    let keypair = Keypair::generate(&mut rng);
    let address = address_from_public_key(&keypair.public);

    let mut account = Account::new(address.clone(), 75_000, Stake::default());
    account.reputation.zsi.validate("proof");
    storage.persist_account(&account).expect("persist account");

    let snapshot: Vec<_> = [30_000u128, 25_000, 20_000]
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            let mut tx_id = [0u8; 32];
            tx_id[0] = index as u8 + 1;
            (
                UtxoOutpoint {
                    tx_id,
                    index: index as u32,
                },
                StoredUtxo::new(address.clone(), value),
            )
        })
        .collect();

    storage
        .persist_utxo_snapshot(&snapshot)
        .expect("persist snapshot");

    let wallet = Wallet::new(storage.clone(), keypair, RuntimeMetrics::noop());
    let workflows = WalletWorkflows::new(&wallet);

    let amount = 25_000u128;
    let fee = 100u64;
    let recipient = "recipient-address".to_string();
    let workflow = workflows
        .transaction_bundle(recipient.clone(), amount, fee, None)
        .expect("build workflow");

    let mut expected_records: Vec<UtxoRecord> = snapshot
        .iter()
        .map(|(outpoint, stored)| stored.to_record(outpoint))
        .collect();
    expected_records.sort_by(|a, b| a.outpoint.cmp(&b.outpoint));

    let total_required = amount + u128::from(fee);
    let mut gathered = Vec::new();
    let mut total = 0u128;
    for record in expected_records.iter() {
        if total >= total_required {
            break;
        }
        total = total.checked_add(record.value).expect("sum inputs");
        gathered.push(record.clone());
    }

    assert_eq!(workflow.utxo_inputs.len(), gathered.len());
    for (actual, expected) in workflow.utxo_inputs.iter().zip(gathered.iter()) {
        assert_eq!(actual.outpoint, expected.outpoint);
        assert_eq!(actual.owner, expected.owner);
        assert_eq!(actual.value, expected.value);
        assert_eq!(actual.script_hash, expected.script_hash);
    }

    for output in &workflow.planned_outputs {
        assert_eq!(
            output.script_hash,
            locking_script_hash(&output.owner, output.value)
        );
    }

    let state = UtxoState::new();
    for (outpoint, stored) in &snapshot {
        state.insert(outpoint.clone(), stored.clone());
    }
    let expected_commitment = hex::encode(state.commitment());
    assert_eq!(workflow.utxo_commitment, expected_commitment);

    assert!(matches!(
        workflows
            .transaction_bundle(recipient, 200_000, fee, None)
            .unwrap_err(),
        ChainError::Transaction(_)
    ));
}
