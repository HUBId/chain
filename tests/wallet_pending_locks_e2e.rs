#![cfg(feature = "wallet-integration")]

//! Wallet pending lock lifecycle integration tests.
//!
//! These tests exercise different lock release paths against both the mock and
//! STWO prover configurations. They complete in under a second on typical CI
//! hardware.

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use common::wallet::{wait_for, WalletTestBuilder};
use rpp_wallet::config::wallet::WalletPolicyConfig;
use rpp_wallet::node_client::NodeClientError;
use rpp_wallet::wallet::WalletError;
use tokio::time::sleep;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_releases_locks_via_all_paths() -> Result<()> {
    let mut policy = WalletPolicyConfig::default();
    policy.pending_lock_timeout = 1;

    let mut prover_config = rpp_wallet::config::wallet::WalletProverConfig::default();
    if cfg!(feature = "prover-stwo") {
        prover_config.enabled = true;
        prover_config.mock_fallback = true;
    }

    let fixture = WalletTestBuilder::default()
        .with_deposits(vec![75_000])
        .with_policy(policy)
        .with_prover(prover_config)
        .build()
        .context("prepare wallet fixture")?;
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
                .map(|utxos| utxos.len() == 1)
                .unwrap_or(false)
        }
    })
    .await;

    let recipient = wallet
        .derive_address(false)
        .context("derive first recipient")?;
    let amount = u128::from(fixture.deposits()[0].amount / 2);

    wallet
        .create_draft(recipient.clone(), amount, None)
        .context("create draft for stale lock check")?;
    assert_eq!(wallet.pending_locks()?.len(), 1);
    sleep(Duration::from_secs(2)).await;
    let released = wallet
        .release_stale_locks()
        .context("release stale locks")?;
    assert_eq!(released.len(), 1);
    assert!(wallet.pending_locks()?.is_empty());

    let retry = wallet
        .create_draft(recipient.clone(), amount, None)
        .context("create draft for rejection")?;
    wallet
        .sign_and_prove(&retry)
        .context("sign draft before rejection")?;
    assert_eq!(wallet.pending_locks()?.len(), 1);

    fixture
        .node()
        .fail_next_submission(NodeClientError::network_with_message("node offline", None));
    match wallet.broadcast(&retry) {
        Err(WalletError::Node(_)) => {}
        result => panic!("unexpected broadcast result {result:?}"),
    }
    assert!(wallet.pending_locks()?.is_empty());

    let manual = wallet
        .create_draft(recipient.clone(), amount, None)
        .context("create draft for manual release")?;
    let manual_proof = wallet
        .sign_and_prove(&manual)
        .context("sign draft before manual release")?;
    let locks = wallet
        .release_pending_locks()
        .context("manual lock release")?;
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0].metadata.backend, manual_proof.backend);
    assert!(wallet.pending_locks()?.is_empty());

    let abort = wallet
        .create_draft(recipient, amount, None)
        .context("create draft for abort flow")?;
    let abort_proof = wallet
        .sign_and_prove(&abort)
        .context("sign draft before abort")?;
    let aborted = wallet
        .abort_draft(&abort)
        .context("abort draft to release locks")?;
    assert_eq!(aborted.len(), 1);
    assert_eq!(aborted[0].metadata.backend, abort_proof.backend);
    assert!(wallet.pending_locks()?.is_empty());

    sync.shutdown()
        .await
        .context("shutdown wallet sync coordinator")?;

    Ok(())
}
