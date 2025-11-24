#![cfg(feature = "wallet-integration")]

//! Wallet key rotation integration tests.
//!
//! These scenarios toggle between hot (full) and cold (watch-only) wallet
//! states to ensure signing continues to function after a rotation and that
//! missing or outdated keys surface clear errors.

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;

use anyhow::{Context, Result};
use common::wallet::{wait_for, WalletTestBuilder};
use rpp_wallet::modes::watch_only::WatchOnlyRecord;
use rpp_wallet::wallet::{Wallet, WalletError, WatchOnlyError};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hot_cold_rotation_preserves_signing_and_nonces() -> Result<()> {
    let fixture = WalletTestBuilder::default()
        .with_deposits(vec![110_000, 75_000])
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
                .balance()
                .map(|balance| balance.total() > 0)
                .unwrap_or(false)
        }
    })
    .await;

    let first = wallet
        .create_draft(wallet.derive_address(false)?, 45_000, Some(2))
        .context("create first draft")?;
    let first_lock = Wallet::draft_lock_id(&first.draft);
    wallet
        .sign_and_prove(&first.draft)
        .context("sign first draft")?;
    wallet
        .broadcast(&first.draft)
        .context("broadcast first draft")?;

    // Rotate into a cold/watch-only profile to mimic hot key removal.
    let cold_record = WatchOnlyRecord::new("wpkh(external)")
        .with_account_xpub("xpub-rotated")
        .with_birthday_height(Some(fixture.birthday_height()));
    wallet
        .enable_watch_only(cold_record)
        .context("enable cold watch-only mode")?;

    let signing_err = wallet
        .sign_and_prove(&first.draft)
        .expect_err("signing should be blocked after cold rotation");
    assert!(matches!(
        signing_err,
        WalletError::WatchOnly(WatchOnlyError::SigningDisabled)
    ));

    // Rotate back to a hot wallet and ensure nonces/locks continue to advance.
    wallet
        .disable_watch_only()
        .context("disable watch-only mode")?;
    let second = wallet
        .create_draft(wallet.derive_address(false)?, 20_000, Some(2))
        .context("create second draft after rotation")?;
    let second_lock = Wallet::draft_lock_id(&second.draft);
    assert_ne!(first_lock, second_lock, "nonce/lock sequencing should advance");

    wallet
        .sign_and_prove(&second.draft)
        .context("sign second draft after hot rotation")?;
    wallet
        .broadcast(&second.draft)
        .context("broadcast second draft")?;

    sync
        .shutdown()
        .await
        .context("shutdown wallet sync coordinator")?;

    assert_eq!(fixture.node().submission_count(), 2);

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotation_surfaces_missing_or_outdated_keys() -> Result<()> {
    let fixture = WalletTestBuilder::default()
        .with_deposits(vec![95_000])
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

    let draft_bundle = wallet
        .create_draft(wallet.derive_address(false)?, 25_000, Some(2))
        .context("create draft before rotation")?;
    let draft = draft_bundle.draft;

    // Cold rotation without an xpub mimics missing key material.
    let missing_key = WatchOnlyRecord::new("wpkh(external)")
        .with_birthday_height(Some(fixture.birthday_height()));
    wallet
        .enable_watch_only(missing_key)
        .context("enable watch-only without key material")?;
    let missing_err = wallet
        .sign_and_prove(&draft)
        .expect_err("rotation without keys should block signing");
    assert!(matches!(
        missing_err,
        WalletError::WatchOnly(WatchOnlyError::SigningDisabled)
    ));

    // Stale/outdated key rotations should also block attempts to broadcast.
    wallet
        .disable_watch_only()
        .context("re-enable hot wallet for signing")?;
    let _ = wallet
        .sign_and_prove(&draft)
        .context("sign draft with refreshed hot key")?;
    let outdated = WatchOnlyRecord::new("wpkh(external)")
        .with_account_xpub("xpub-outdated")
        .with_birthday_height(Some(fixture.latest_height() + 1));
    wallet
        .enable_watch_only(outdated)
        .context("rotate to outdated cold key")?;
    let broadcast_err = wallet
        .broadcast(&draft)
        .expect_err("broadcast should fail when cold key is outdated");
    assert!(matches!(
        broadcast_err,
        WalletError::WatchOnly(WatchOnlyError::BroadcastDisabled)
    ));

    sync
        .shutdown()
        .await
        .context("shutdown wallet sync coordinator")?;

    Ok(())
}
