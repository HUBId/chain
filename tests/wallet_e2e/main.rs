#![cfg(feature = "wallet-integration")]

//! Wallet end-to-end regression coverage.
//! Exercises transaction submission, signing, nonce sequencing, and fee
//! handling across restarts and backend error surfaces.

#[path = "../common/mod.rs"]
mod common;

use std::borrow::Cow;
use std::sync::Arc;

use anyhow::{Context, Result};
use common::wallet::{wait_for, wait_for_status, WalletTestBuilder};
use rpp::runtime::wallet::sync::SyncMode;
use rpp_wallet::engine::{BuilderError, EngineError};
use rpp_wallet::indexer::client::{IndexedUtxo, TransactionPayload, TxOutpoint};
use rpp_wallet::node_client::NodeClientError;
use rpp_wallet::wallet::WalletError;
use rpp_wallet::zsi::prove::DummyBackend;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconciles_reorgs_for_rest_wallets() -> Result<()> {
    let fixture = WalletTestBuilder::default()
        .with_deposits(vec![110_000, 70_000])
        .with_latest_height(240)
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
                .map(|balance| balance.total() >= 180_000)
                .unwrap_or(false)
        }
    })
    .await;

    let recipient = wallet
        .derive_address(false)
        .context("derive recipient before reorg")?;
    let draft = wallet
        .create_draft(recipient, 60_000, Some(2))
        .context("create outbound draft")?;
    let first_lock = rpp_wallet::wallet::Wallet::draft_lock_id(&draft.draft);
    let _ = wallet
        .sign_and_prove(&draft.draft)
        .context("sign outbound draft")?;
    wallet
        .broadcast(&draft.draft)
        .context("broadcast outbound draft")?;

    let reorg_height = fixture.latest_height() + 3;
    let reclaimed = fixture
        .deposits()
        .first()
        .expect("first deposit present")
        .address
        .clone();
    let mut reorg_txid = [9u8; 32];
    reorg_txid[31] = 7;
    let reorg_utxo = IndexedUtxo::new(
        TxOutpoint::new(reorg_txid, 0),
        185_000,
        hex::decode(&reclaimed).expect("decode reorg address"),
        Some(reorg_height.saturating_sub(1)),
    );
    let reorg_payload = TransactionPayload::new(
        reorg_txid,
        Some(reorg_height.saturating_sub(1)),
        Cow::Owned(vec![0xaa, 0xbb, 0xcc]),
    );

    fixture.indexer().rewrite_chain(
        reorg_height,
        vec![(reclaimed.clone(), reorg_utxo.clone(), reorg_payload)],
    );

    sync.request_rescan(fixture.birthday_height())
        .context("request wallet rescan")?;

    let _ = wait_for_status(&sync, |status| {
        status.latest_height >= reorg_height && matches!(status.mode, SyncMode::Rescan { .. })
    })
    .await;

    assert!(wallet
        .pending_locks()
        .context("load locks after reorg")?
        .is_empty());

    let balance = wallet.balance().context("load balance after reorg")?;
    assert_eq!(balance.total(), reorg_utxo.value(), "balance reconciles");

    let next = wallet
        .create_draft(wallet.derive_address(false)?, 40_000, Some(2))
        .context("create draft after reorg")?;
    let next_lock = rpp_wallet::wallet::Wallet::draft_lock_id(&next.draft);
    assert_ne!(first_lock, next_lock, "nonce/lock id advanced after fork");

    sync.shutdown()
        .await
        .context("shutdown wallet sync coordinator")?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconciles_reorgs_for_cli_and_zk_backends() -> Result<()> {
    let fixture = WalletTestBuilder::default()
        .with_deposits(vec![95_000])
        .with_latest_height(180)
        .with_zsi_backend(Arc::new(DummyBackend::default()))
        .build()
        .context("prepare zk wallet fixture")?;
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
                .map(|balance| balance.total() == 95_000)
                .unwrap_or(false)
        }
    })
    .await;

    let recipient = wallet
        .derive_address(false)
        .context("derive cli recipient")?;
    let draft = wallet
        .create_draft(recipient, 25_000, Some(1))
        .context("prepare cli draft")?;
    wallet
        .sign_and_prove(&draft.draft)
        .context("sign cli draft")?;
    wallet
        .broadcast(&draft.draft)
        .context("broadcast cli draft")?;

    let reorg_height = fixture.latest_height() + 2;
    let mut txid = [5u8; 32];
    txid[0] = 13;
    let restored = IndexedUtxo::new(
        TxOutpoint::new(txid, 1),
        120_000,
        hex::decode(&fixture.deposits()[0].address).expect("decode restored address"),
        Some(reorg_height.saturating_sub(1)),
    );
    let restored_payload = TransactionPayload::new(
        txid,
        Some(reorg_height.saturating_sub(1)),
        Cow::Owned(vec![0xde, 0xad, 0xbe, 0xef]),
    );
    fixture.indexer().rewrite_chain(
        reorg_height,
        vec![(
            fixture.deposits()[0].address.clone(),
            restored.clone(),
            restored_payload,
        )],
    );

    sync.request_rescan(fixture.birthday_height())
        .context("request cli rescan")?;
    let status = wait_for_status(&sync, |status| status.latest_height >= reorg_height).await;
    assert!(matches!(status.mode, SyncMode::Rescan { .. }));

    let balance = wallet.balance().context("balance after cli reorg")?;
    assert_eq!(balance.spendable(), restored.value(), "cli view reconciles");

    sync.shutdown()
        .await
        .context("shutdown wallet sync coordinator")?;

    Ok(())
}
