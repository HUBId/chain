#![cfg(feature = "wallet-integration")]

//! Wallet backup and recovery integration tests.
//!
//! Exercises the backup export/import helpers against the mocked wallet
//! environment to ensure metadata, policy snapshots, and keystore payloads
//! round-trip via the encrypted archive.

#[path = "common/mod.rs"]
mod common;

use std::fs;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use common::wallet::{wait_for, WalletTestBuilder};
use rpp_wallet::backup::{backup_export, backup_import, BackupExportOptions};
use rpp_wallet::db::PolicySnapshot;
use zeroize::Zeroizing;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_backup_round_trip_restores_metadata() -> Result<()> {
    let fixture = WalletTestBuilder::default()
        .with_deposits(vec![110_000, 55_000])
        .build()
        .context("initialise wallet fixture")?;
    let wallet = fixture.wallet();
    let sync = Arc::new(
        fixture
            .start_sync()
            .context("start wallet sync coordinator")?,
    );

    wait_for(|| {
        let wallet = Arc::clone(&wallet);
        async move {
            wallet
                .list_utxos()
                .map(|utxos| !utxos.is_empty())
                .unwrap_or(false)
        }
    })
    .await;

    sync.shutdown()
        .await
        .context("shutdown wallet sync coordinator")?;

    let store = wallet.store();
    let keystore_path = wallet.keystore_path().clone();
    ensure_parent(&keystore_path)?;
    fs::write(&keystore_path, b"encrypted-keystore").context("write keystore")?;

    {
        let mut batch = store.batch().context("seed policy snapshot")?;
        batch.put_meta("wallet.network", b"regtest");
        batch.put_meta("wallet.notes", b"backup-e2e");
        let policy = PolicySnapshot::new(1, 1_234_567, vec!["allow *".into()]);
        batch
            .put_policy_snapshot("default", &policy)
            .context("persist default policy snapshot")?;
        batch.commit().context("commit seeded metadata")?;
    }

    let passphrase = Zeroizing::new(b"correct horse battery staple".to_vec());
    let export = backup_export(
        store.as_ref(),
        &keystore_path,
        wallet.backup_dir(),
        passphrase.clone(),
        passphrase.clone(),
        BackupExportOptions::default(),
    )
    .context("export wallet backup")?;
    let backup_name = export
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .context("derive backup archive name")?
        .to_string();

    {
        let mut batch = store.batch().context("prepare wipe batch")?;
        batch.delete_meta("wallet.network");
        batch.delete_meta("wallet.notes");
        batch.delete_policy_snapshot("default");
        batch.commit().context("commit metadata wipe")?;
    }
    if keystore_path.exists() {
        fs::remove_file(&keystore_path).context("remove keystore before restore")?;
    }

    let import = backup_import(
        store.as_ref(),
        &keystore_path,
        wallet.backup_dir(),
        &backup_name,
        Zeroizing::new(b"correct horse battery staple".to_vec()),
    )
    .context("import wallet backup")?;

    assert!(import.restored_keystore, "keystore should be restored");
    assert!(import.restored_policy, "policy snapshot should be restored");
    assert_eq!(import.rescan_from, fixture.birthday_height());
    assert_eq!(import.metadata.policy_entries, 1);
    assert_eq!(import.metadata.meta_entries, 2);

    let network = store
        .get_meta("wallet.network")
        .context("read restored network meta")?
        .expect("network metadata restored");
    assert_eq!(network, b"regtest");
    let note = store
        .get_meta("wallet.notes")
        .context("read restored note meta")?
        .expect("note metadata restored");
    assert_eq!(note, b"backup-e2e");

    let policies = store
        .iter_policy_snapshots()
        .context("list restored policy snapshots")?;
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].0, "default");
    assert_eq!(policies[0].1.revision, 1);

    let keystore = fs::read(&keystore_path).context("read restored keystore")?;
    assert_eq!(keystore, b"encrypted-keystore");

    Ok(())
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("create keystore parent")?;
    }
    Ok(())
}
