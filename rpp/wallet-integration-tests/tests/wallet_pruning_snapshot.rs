use std::borrow::Cow;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use hex;
use rpp_wallet::backup::{backup_export, backup_import, BackupExportOptions};
use rpp_wallet::config::wallet::{
    WalletFeeConfig, WalletHwConfig, WalletPolicyConfig, WalletProverConfig, WalletZsiConfig,
};
use rpp_wallet::db::WalletStore;
use rpp_wallet::indexer::checkpoints::persist_birthday_height;
use rpp_wallet::indexer::client::{IndexedUtxo, IndexerClient, TransactionPayload, TxOutpoint};
use rpp_wallet::tests::{
    wait_for, RecordingNodeClient, TestIndexer,
};
use rpp_wallet::wallet::{Wallet, WalletMode, WalletPaths, WalletSyncCoordinator};
use serde_json::json;
use tempfile::TempDir;
use zeroize::Zeroizing;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_prunes_snapshots_and_restores_balances() -> Result<()> {
    let fixture = SnapshotRestoreFixture::new().context("initialise pruning snapshot fixture")?;

    let sync = Arc::new(fixture.start_sync().context("start initial sync coordinator")?);
    let wallet = fixture.wallet();

    wait_for(|| {
        let wallet = Arc::clone(&wallet);
        async move {
            wallet
                .balance()
                .map(|balance| balance.total() > 0)
                .unwrap_or(false)
        }
    })
    .await;

    let initial_balance = wallet.balance().context("read initial balance")?.total();
    let first_recipient = wallet
        .derive_address(false)
        .context("derive initial recipient")?;
    let first_draft = wallet
        .create_draft(first_recipient, fixture.transfer_amount(), Some(2))
        .context("create initial draft")?;
    let _ = wallet
        .sign_and_prove(&first_draft.draft)
        .context("sign initial draft")?;
    wallet
        .broadcast(&first_draft.draft)
        .context("broadcast initial draft")?;
    assert_eq!(fixture.node().submission_count(), 1, "first receipt recorded");

    sync.shutdown()
        .await
        .context("shutdown initial sync coordinator")?;

    let export = fixture
        .export_backup()
        .context("export pruning snapshot backup")?;
    let restored = fixture
        .restore_from_backup(&export)
        .context("restore snapshot to new data dir")?;

    let restored_wallet = restored.wallet();
    let restored_sync = Arc::new(
        restored
            .start_sync()
            .context("start restored sync coordinator")?,
    );
    wait_for(|| {
        let wallet = Arc::clone(&restored_wallet);
        async move {
            wallet
                .balance()
                .map(|balance| balance.total() == initial_balance)
                .unwrap_or(false)
        }
    })
    .await;

    let restored_balance = restored_wallet
        .balance()
        .context("read restored balance")?
        .total();
    assert_eq!(restored_balance, initial_balance, "balance restored after snapshot");

    let second_recipient = restored_wallet
        .derive_address(false)
        .context("derive post-restore recipient")?;
    let second_draft = restored_wallet
        .create_draft(second_recipient, restored.transfer_amount(), Some(3))
        .context("create post-restore draft")?;
    let _ = restored_wallet
        .sign_and_prove(&second_draft.draft)
        .context("sign post-restore draft")?;
    restored_wallet
        .broadcast(&second_draft.draft)
        .context("broadcast post-restore draft")?;
    assert_eq!(restored.node().submission_count(), 1, "restored receipts recorded");

    restored_sync
        .shutdown()
        .await
        .context("shutdown restored sync coordinator")?;

    restored
        .write_artifact(initial_balance, restored_balance, &export)
        .context("persist pruning snapshot artifact")?;

    Ok(())
}

struct SnapshotRestoreFixture {
    _tempdir: TempDir,
    wallet: Arc<Wallet>,
    store: Arc<WalletStore>,
    indexer: TestIndexer,
    node: Arc<RecordingNodeClient>,
    birthday: u64,
    latest_height: u64,
    deposit_value: u64,
    root_seed: [u8; 32],
    keystore_path: PathBuf,
    backup_dir: PathBuf,
}

impl SnapshotRestoreFixture {
    fn new() -> Result<Self> {
        let tempdir = TempDir::new().context("create wallet temp directory")?;
        let store = Arc::new(WalletStore::open(tempdir.path()).context("open wallet store")?);
        let birthday = 96u64;
        {
            let mut batch = store.batch().context("seed birthday checkpoint")?;
            persist_birthday_height(&mut batch, Some(birthday))
                .context("persist birthday checkpoint")?;
            batch.commit().context("commit birthday checkpoint")?;
        }

        let node = Arc::new(RecordingNodeClient::default());
        let policy = WalletPolicyConfig {
            external_gap_limit: 4,
            internal_gap_limit: 4,
            min_confirmations: 1,
        };
        let keystore_path = tempdir.path().join("keystore.toml");
        let backup_dir = tempdir.path().join("backups");
        fs::create_dir_all(&backup_dir).context("create backup directory")?;

        let root_seed = [7u8; 32];
        let wallet = Arc::new(
            Wallet::new(
                Arc::clone(&store),
                WalletMode::Full { root_seed },
                policy,
                WalletFeeConfig::default(),
                WalletProverConfig::default(),
                WalletHwConfig::default(),
                WalletZsiConfig::default(),
                None,
                node.clone(),
                WalletPaths::new(keystore_path.clone(), backup_dir.clone()),
                Arc::new(rpp_wallet::telemetry::WalletActionTelemetry::new(false)),
            )
            .context("construct wallet instance")?,
        );
        let deposit_address = wallet
            .derive_address(false)
            .context("derive deposit address")?;

        let latest_height = 140u64;
        let deposit_value = 110_000u64;
        let indexer = TestIndexer::new(latest_height);
        let txid = [2u8; 32];
        let utxo = IndexedUtxo::new(
            TxOutpoint::new(txid, 0),
            deposit_value,
            hex::decode(&deposit_address).context("decode deposit script")?,
            Some(latest_height - 2),
        );
        let payload = TransactionPayload::new(
            txid,
            Some(latest_height - 2),
            Cow::Owned(vec![0xca, 0xfe, 0xba, 0xbe]),
        );
        indexer.register_utxo(&deposit_address, utxo, payload);

        Ok(Self {
            _tempdir: tempdir,
            wallet,
            store,
            indexer,
            node,
            birthday,
            latest_height,
            deposit_value,
            root_seed,
            keystore_path,
            backup_dir,
        })
    }

    fn wallet(&self) -> Arc<Wallet> {
        Arc::clone(&self.wallet)
    }

    fn node(&self) -> Arc<RecordingNodeClient> {
        Arc::clone(&self.node)
    }

    fn transfer_amount(&self) -> u128 {
        u128::from(self.deposit_value / 4)
    }

    fn start_sync(&self) -> Result<WalletSyncCoordinator> {
        self.wallet
            .start_sync_coordinator(self.indexer_client())
            .context("start sync coordinator")
    }

    fn export_backup(&self) -> Result<PathBuf> {
        if !self.keystore_path.exists() {
            if let Some(parent) = self.keystore_path.parent() {
                fs::create_dir_all(parent).context("create keystore parent")?;
            }
            fs::write(&self.keystore_path, b"pruning-snapshot-keystore")
                .context("write keystore bytes")?;
        }

        let passphrase = Zeroizing::new(b"wallet-pruning-snapshot".to_vec());
        let export = backup_export(
            self.store.as_ref(),
            &self.keystore_path,
            &self.backup_dir,
            passphrase.clone(),
            passphrase,
            BackupExportOptions::default(),
        )
        .context("export wallet backup")?;

        Ok(export.path)
    }

    fn restore_from_backup(&self, export: &Path) -> Result<Self> {
        let tempdir = TempDir::new().context("create restore temp directory")?;
        let store = Arc::new(WalletStore::open(tempdir.path()).context("open restored store")?);

        let restore_keystore = tempdir.path().join("keystore.toml");
        let restore_backups = tempdir.path().join("backups");
        fs::create_dir_all(&restore_backups).context("create restored backup dir")?;
        let backup_name = export
            .file_name()
            .and_then(|name| name.to_str())
            .context("derive backup filename")?;
        fs::copy(export, restore_backups.join(backup_name)).context("copy backup to restore dir")?;

        let import = backup_import(
            store.as_ref(),
            &restore_keystore,
            &restore_backups,
            backup_name,
            Zeroizing::new(b"wallet-pruning-snapshot".to_vec()),
        )
        .context("import pruning snapshot backup")?;

        assert!(import.restored_keystore, "keystore should restore from backup");
        assert_eq!(import.rescan_from, self.birthday, "birthday checkpoint restored");

        let node = Arc::new(RecordingNodeClient::default());
        let mut policy = WalletPolicyConfig::default();
        policy.min_confirmations = 1;
        let wallet = Arc::new(
            Wallet::new(
                Arc::clone(&store),
                WalletMode::Full {
                    root_seed: self.root_seed,
                },
                policy,
                WalletFeeConfig::default(),
                WalletProverConfig::default(),
                WalletHwConfig::default(),
                WalletZsiConfig::default(),
                None,
                node.clone(),
                WalletPaths::new(restore_keystore.clone(), restore_backups.clone()),
                Arc::new(rpp_wallet::telemetry::WalletActionTelemetry::new(false)),
            )
            .context("construct restored wallet instance")?,
        );

        Ok(Self {
            _tempdir: tempdir,
            wallet,
            store,
            indexer: self.indexer.clone(),
            node,
            birthday: self.birthday,
            latest_height: self.latest_height,
            deposit_value: self.deposit_value,
            root_seed: self.root_seed,
            keystore_path: restore_keystore,
            backup_dir: restore_backups,
        })
    }

    fn indexer_client(&self) -> Arc<dyn IndexerClient> {
        Arc::new(self.indexer.clone())
    }

    fn write_artifact(&self, initial: u128, restored: u128, export: &Path) -> Result<()> {
        let mut artifact = json!({
            "initial_balance": initial,
            "restored_balance": restored,
            "latest_height": self.latest_height,
            "birthday": self.birthday,
            "backup_file": export.file_name().and_then(|name| name.to_str()),
        });
        artifact["receipt_count"] = json!(self.node().submission_count());

        let base = artifact_dir();
        fs::create_dir_all(&base).context("create pruning snapshot artifact directory")?;
        let path = base.join("summary.json");
        fs::write(&path, serde_json::to_vec_pretty(&artifact)?).context("write pruning snapshot artifact")?;
        Ok(())
    }
}

fn artifact_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("logs")
        .join("wallet-pruning-snapshot")
}
