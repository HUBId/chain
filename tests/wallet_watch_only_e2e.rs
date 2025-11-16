#![cfg(feature = "wallet-integration")]

//! Watch-only integration tests.
//!
//! Validates that enabling watch-only mode on a running wallet blocks
//! signing and broadcast flows until the restriction is lifted again.

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;

use anyhow::{Context, Result};
use common::wallet::{wait_for, WalletTestBuilder};
use rpp_wallet::modes::watch_only::WatchOnlyRecord;
use rpp_wallet::wallet::{WalletError, WatchOnlyError};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_watch_only_mode_blocks_signing_paths() -> Result<()> {
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

    let recipient = wallet
        .derive_address(false)
        .context("derive recipient address")?;
    let draft_bundle = wallet
        .create_draft(recipient, 25_000, Some(2))
        .context("create transfer draft")?;
    let draft = draft_bundle.draft;

    let record = WatchOnlyRecord::new("wpkh(external)")
        .with_account_xpub("xpub-example")
        .with_birthday_height(Some(fixture.birthday_height()));
    let status = wallet
        .enable_watch_only(record.clone())
        .context("enable watch-only mode")?;
    assert!(status.enabled);
    assert_eq!(status.birthday_height, Some(fixture.birthday_height()));

    let sign_err = wallet
        .sign_and_prove(&draft)
        .expect_err("signing should be rejected");
    assert!(matches!(
        sign_err,
        WalletError::WatchOnly(WatchOnlyError::SigningDisabled)
    ));

    let broadcast_err = wallet
        .broadcast(&draft)
        .expect_err("broadcast should be rejected");
    assert!(matches!(
        broadcast_err,
        WalletError::WatchOnly(WatchOnlyError::BroadcastDisabled)
    ));

    wallet
        .disable_watch_only()
        .context("disable watch-only mode")?;

    let proof = wallet
        .sign_and_prove(&draft)
        .context("sign draft after disabling watch-only")?;
    assert_eq!(proof.backend, "instant");

    wallet
        .broadcast(&draft)
        .context("broadcast draft after disabling watch-only")?;

    sync.shutdown()
        .await
        .context("shutdown wallet sync coordinator")?;

    Ok(())
}
