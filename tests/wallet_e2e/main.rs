#![cfg(feature = "wallet-integration")]

//! Wallet end-to-end regression coverage.
//! Exercises transaction submission, signing, nonce sequencing, and fee
//! handling across restarts and backend error surfaces.

#[path = "../common/mod.rs"]
mod common;

use std::sync::Arc;

use anyhow::{Context, Result};
use common::wallet::{wait_for, WalletTestBuilder};
use rpp_wallet::engine::{BuilderError, EngineError};
use rpp_wallet::node_client::NodeClientError;
use rpp_wallet::wallet::WalletError;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn submits_signed_transactions_across_restarts() -> Result<()> {
    let fixture = WalletTestBuilder::default()
        .with_deposits(vec![120_000, 80_000])
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
                .balance()
                .map(|balance| balance.total() > 0)
                .unwrap_or(false)
        }
    })
    .await;

    let recipient = wallet
        .derive_address(false)
        .context("derive first recipient")?;
    let first = wallet
        .create_draft(recipient, 50_000, Some(2))
        .context("create first draft")?;
    let first_lock = rpp_wallet::wallet::Wallet::draft_lock_id(&first.draft);
    let (first_proof, _) = wallet
        .sign_and_prove(&first.draft)
        .context("sign first draft")?;
    let locks = wallet
        .locks_for_draft(&first.draft)
        .context("load locks for first draft")?;
    assert_eq!(locks.len(), first.draft.inputs.len(), "all inputs locked");
    assert!(locks
        .iter()
        .all(|lock| lock.metadata.proof_present == first_proof.proof().is_some()));

    wallet
        .broadcast(&first.draft)
        .context("broadcast first draft")?;
    let submission = fixture
        .node()
        .last_submission()
        .expect("first submission captured");
    assert_eq!(
        first.draft.total_input_value(),
        submission.total_input_value,
        "node saw expected input value",
    );
    assert_eq!(
        first.draft.total_input_value() - first.draft.total_output_value(),
        first.draft.fee,
        "fee deducted from inputs",
    );

    let restarted = fixture.restart_wallet().context("restart wallet")?;
    let second_recipient = restarted
        .derive_address(false)
        .context("derive second recipient")?;
    let second = restarted
        .create_draft(second_recipient, 30_000, Some(2))
        .context("create second draft")?;
    let second_lock = rpp_wallet::wallet::Wallet::draft_lock_id(&second.draft);
    assert_ne!(first_lock, second_lock, "lock identifiers should sequence");
    let _ = restarted
        .sign_and_prove(&second.draft)
        .context("sign second draft")?;
    restarted
        .broadcast(&second.draft)
        .context("broadcast second draft")?;

    sync.shutdown()
        .await
        .context("shutdown wallet sync coordinator")?;

    assert_eq!(
        fixture.node().submission_count(),
        2,
        "two submissions recorded"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn surfaces_insufficient_funds_and_rejection_errors() -> Result<()> {
    let fixture = WalletTestBuilder::default()
        .with_deposits(vec![40_000])
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
                .balance()
                .map(|balance| balance.total() > 0)
                .unwrap_or(false)
        }
    })
    .await;

    let oversized = wallet
        .create_draft(wallet.derive_address(false)?, 200_000, None)
        .expect_err("oversized draft should fail");
    assert!(matches!(
        oversized,
        WalletError::Engine(EngineError::Builder(BuilderError::InsufficientFunds { .. }))
    ));

    let recipient = wallet
        .derive_address(false)
        .context("derive recipient for rejection test")?;
    let draft = wallet
        .create_draft(recipient, 10_000, None)
        .context("create rejection draft")?;
    fixture
        .node()
        .fail_next_submission(NodeClientError::rejected("invalid signature"));
    let _ = wallet
        .sign_and_prove(&draft.draft)
        .context("sign rejection draft")?;
    let rejection = wallet
        .broadcast(&draft.draft)
        .expect_err("broadcast should surface rejection");
    assert!(matches!(
        rejection,
        WalletError::Node(NodeClientError::Rejected { .. })
    ));
    assert!(
        wallet
            .pending_locks()
            .context("pending locks after rejection")?
            .is_empty(),
        "locks released after failed submission"
    );

    sync.shutdown()
        .await
        .context("shutdown wallet sync coordinator")?;

    Ok(())
}
