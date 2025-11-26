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
use rpp_wallet::db::{PolicySnapshot, WalletStore};
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_backup_survives_snapshot_restore_and_signs() -> Result<()> {
    let fixture = WalletTestBuilder::default()
        .with_deposits(vec![125_000, 75_000])
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

    let initial_balance = wallet
        .balance()
        .context("read initial wallet balance")?
        .total();
    let recipient = wallet
        .derive_address(false)
        .context("derive recipient address")?;
    let draft_bundle = wallet
        .create_draft(recipient, 50_000, Some(2))
        .context("build draft before backup")?;
    let (_, baseline_meta) = wallet
        .sign_and_prove(&draft_bundle.draft)
        .context("sign draft before backup")?;

    sync.shutdown()
        .await
        .context("shutdown wallet sync coordinator")?;

    let keystore_path = wallet.keystore_path().clone();
    ensure_parent(&keystore_path)?;
    fs::write(&keystore_path, b"encrypted-keystore").context("write keystore")?;

    let passphrase = Zeroizing::new(b"correct horse battery staple".to_vec());
    let export = backup_export(
        wallet.store().as_ref(),
        &keystore_path,
        wallet.backup_dir(),
        passphrase.clone(),
        passphrase.clone(),
        BackupExportOptions::default(),
    )
    .context("export snapshot backup")?;

    let wallet_root = keystore_path
        .parent()
        .context("derive wallet root dir")?
        .to_path_buf();
    let snapshot_root = tempfile::tempdir().context("create snapshot root")?;
    let snapshot_wallet_dir = snapshot_root.path().join("node-snapshot/wallet");
    copy_dir(&wallet_root, &snapshot_wallet_dir).context("persist wallet data alongside snapshot")?;

    let restored_root = snapshot_root.path().join("restored/wallet");
    copy_dir(&snapshot_wallet_dir, &restored_root).context("restore wallet data from snapshot")?;
    let restored_keystore = restored_root.join(
        keystore_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("keystore.toml")),
    );
    if restored_keystore.exists() {
        fs::remove_file(&restored_keystore).context("remove keystore to force restore")?;
    }

    let restored_store = WalletStore::open(&restored_root).context("open restored wallet store")?;
    let import = backup_import(
        &restored_store,
        &restored_keystore,
        &restored_root.join("backups"),
        export
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .context("derive backup archive name")?,
        Zeroizing::new(b"correct horse battery staple".to_vec()),
    )
    .context("restore wallet backup into snapshot")?;

    assert!(import.restored_keystore, "keystore should be restored from backup");

    let restored_wallet = fixture
        .restore_wallet_from(&restored_root)
        .context("construct restored wallet")?;
    let restored_sync = Arc::new(
        restored_wallet
            .start_sync_coordinator(fixture.indexer_client())
            .context("start restored wallet sync")?,
    );
    wait_for(|| {
        let wallet = Arc::clone(&restored_wallet);
        async move {
            wallet
                .list_utxos()
                .map(|utxos| !utxos.is_empty())
                .unwrap_or(false)
        }
    })
    .await;

    restored_sync
        .shutdown()
        .await
        .context("shutdown restored sync")?;

    let restored_balance = restored_wallet
        .balance()
        .context("read restored balance")?
        .total();
    assert_eq!(restored_balance, initial_balance);

    let (_, restored_meta) = restored_wallet
        .sign_and_prove(&draft_bundle.draft)
        .context("sign draft after restore")?;
    assert_eq!(restored_meta.backend, baseline_meta.backend);

    Ok(())
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("create keystore parent")?;
    }
    Ok(())
}

fn copy_dir(src: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest).with_context(|| format!("create {dest:?}"))?;
    for entry in fs::read_dir(src).with_context(|| format!("read {src:?}"))? {
        let entry = entry?;
        let path = entry.path();
        let target = dest.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&path, &target)?;
        } else {
            fs::copy(&path, &target)
                .with_context(|| format!("copy {path:?} to {target:?}"))?;
        }
    }
    Ok(())
}
