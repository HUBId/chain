#![cfg(feature = "wallet-integration")]

//! Wallet policy and fee handling integration tests.
//!
//! These scenarios complete in under a second on the mock prover backend. When the
//! `prover-stwo` feature is enabled the same assertions execute against the STWO
//! backend and include additional proof metadata checks.

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use common::wallet::{wait_for, wait_for_status, WalletTestBuilder};
use rpp_wallet::engine::fees::{FeeCongestionLevel, FeeError, FeeEstimateSource};
use rpp_wallet::engine::EngineError;
use rpp_wallet::indexer::scanner::SyncMode;
use rpp_wallet::node_client::{BlockFeeSummary, MempoolInfo, NodeClientError, NodeRejectionHint};
use rpp_wallet::wallet::WalletError;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_respects_fee_hints_and_policy_limits() -> Result<()> {
    let mut prover_config = rpp_wallet::config::wallet::WalletProverConfig::default();
    if cfg!(feature = "prover-stwo") {
        prover_config.backend = rpp_wallet::config::wallet::WalletProverBackend::Stwo;
        prover_config.require_proof = true;
    }

    let fixture = WalletTestBuilder::default()
        .with_latest_height(240)
        .with_prover(prover_config)
        .build()
        .context("initialise wallet test fixture")?;
    let wallet = fixture.wallet();
    let sync = Arc::new(
        fixture
            .start_sync()
            .context("start wallet sync coordinator")?,
    );

    wait_for(|| {
        let wallet = Arc::clone(&wallet);
        let expected = fixture.deposits().len();
        async move {
            wallet
                .list_utxos()
                .map(|utxos| utxos.len() == expected)
                .unwrap_or(false)
        }
    })
    .await;

    let status = wait_for_status(&sync, |status| {
        matches!(status.mode, SyncMode::Resume { .. })
    })
    .await;
    assert_eq!(status.latest_height, fixture.latest_height());
    assert_eq!(
        status.pending_ranges,
        vec![(fixture.birthday_height(), fixture.latest_height())]
    );
    assert_eq!(
        status.checkpoints.resume_height,
        Some(fixture.latest_height())
    );

    let node = fixture.node();
    node.set_mempool_info(MempoolInfo {
        tx_count: 42,
        vsize_limit: 1_000_000,
        vsize_in_use: 900_000,
        min_fee_rate: Some(10),
        max_fee_rate: Some(40),
    });
    node.set_recent_blocks(vec![
        BlockFeeSummary {
            height: fixture.latest_height() - 1,
            median_fee_rate: Some(9),
            max_fee_rate: Some(15),
        },
        BlockFeeSummary {
            height: fixture.latest_height(),
            median_fee_rate: Some(10),
            max_fee_rate: Some(18),
        },
        BlockFeeSummary {
            height: fixture.latest_height() + 1,
            median_fee_rate: Some(12),
            max_fee_rate: Some(20),
        },
    ]);

    let recipient = wallet
        .derive_address(false)
        .context("derive spend recipient")?;
    let spend_amount = u128::from(fixture.deposits()[0].amount / 2);
    let draft = wallet
        .create_draft(recipient.clone(), spend_amount, None)
        .context("create draft with node fee hints")?;
    assert_eq!(
        draft.fee_rate, 20,
        "high congestion should double the median fee"
    );

    let quote = wallet
        .latest_fee_quote()
        .expect("fee quote cached after draft creation");
    assert_eq!(quote.rate(), 20);
    match quote.source() {
        FeeEstimateSource::Node {
            congestion,
            samples,
        } => {
            assert_eq!(*samples, 3);
            assert_eq!(*congestion, FeeCongestionLevel::High);
        }
        other => panic!("unexpected fee source {other:?}"),
    }

    let locks = wallet
        .pending_locks()
        .context("inspect pending locks after draft")?;
    assert_eq!(locks.len(), 1);
    assert!(locks[0].metadata.backend.is_empty());
    assert!(locks[0].spending_txid.is_none());

    let (prove_result, meta) = wallet
        .sign_and_prove(&draft)
        .context("sign and prove draft")?;
    assert!(!meta.backend.is_empty());
    assert!(meta.witness_bytes > 0);
    if cfg!(feature = "prover-stwo") {
        assert_eq!(meta.backend, "stwo");
        assert!(prove_result.proof().is_some());
    } else {
        assert_eq!(meta.backend, "mock");
    }

    let locks = wallet.pending_locks().context("locks after signing")?;
    assert_eq!(locks.len(), 1);
    assert!(locks[0].spending_txid.is_some());
    assert_eq!(locks[0].metadata.backend, meta.backend);
    assert_eq!(locks[0].metadata.witness_bytes, meta.witness_bytes as u64);

    node.fail_next_submission(NodeClientError::rejected_with_hint(
        "fee below floor",
        NodeRejectionHint::FeeRateTooLow { required: Some(28) },
    ));
    let broadcast_err = wallet
        .broadcast(&draft)
        .expect_err("node rejection should bubble up");
    let required_fee = match broadcast_err {
        WalletError::Node(ref err) => {
            sync.record_node_failure(err);
            match err {
                NodeClientError::Rejected {
                    hint: Some(NodeRejectionHint::FeeRateTooLow { required }),
                    ..
                } => required.unwrap_or(0),
                _ => panic!("unexpected rejection hint {err:?}"),
            }
        }
        other => panic!("unexpected wallet error {other:?}"),
    };
    assert_eq!(required_fee, 28);
    assert!(
        wallet
            .pending_locks()
            .context("locks after rejection")?
            .is_empty(),
        "failed broadcast should release locks",
    );

    let status_with_hint = sync
        .latest_status()
        .expect("status available after rejection");
    assert!(status_with_hint.node_issue.is_some());
    assert!(!status_with_hint.hints.is_empty());
    sync.clear_node_failure();

    let override_rate = 30;
    let retry = wallet
        .create_draft(recipient, spend_amount, Some(override_rate))
        .context("create override draft")?;
    assert_eq!(retry.fee_rate, override_rate);
    let (_, retry_meta) = wallet.sign_and_prove(&retry).context("sign retry draft")?;
    assert_eq!(retry_meta.backend, meta.backend);
    wallet
        .broadcast(&retry)
        .context("successful broadcast should clear locks")?;
    assert!(wallet
        .pending_locks()
        .context("locks after success")?
        .is_empty());
    assert_eq!(
        node.submission_count(),
        1,
        "only successful submission recorded"
    );
    let submitted = node
        .last_submission()
        .expect("expected recorded submission");
    assert_eq!(submitted.fee_rate, override_rate);

    sync.shutdown()
        .await
        .context("shutdown wallet sync coordinator")?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fee_estimates_scale_with_mempool_load_and_failures() -> Result<()> {
    let mut prover_config = rpp_wallet::config::wallet::WalletProverConfig::default();
    if cfg!(feature = "prover-stwo") {
        prover_config.backend = rpp_wallet::config::wallet::WalletProverBackend::Stwo;
        prover_config.require_proof = true;
    }

    let mut fees = rpp_wallet::config::wallet::WalletFeeConfig::default();
    fees.cache_ttl_secs = 0;

    let fixture = WalletTestBuilder::default()
        .with_deposits(vec![160_000, 90_000])
        .with_fees(fees)
        .with_prover(prover_config)
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

    let node = fixture.node();
    node.set_mempool_info(MempoolInfo {
        tx_count: 1_200,
        vsize_limit: 1_000_000,
        vsize_in_use: 120_000,
        min_fee_rate: Some(2),
        max_fee_rate: None,
    });
    node.set_recent_blocks(vec![
        BlockFeeSummary {
            height: fixture.latest_height() - 1,
            median_fee_rate: Some(3),
            max_fee_rate: Some(5),
        },
        BlockFeeSummary {
            height: fixture.latest_height(),
            median_fee_rate: Some(4),
            max_fee_rate: Some(6),
        },
    ]);

    let recipient = wallet
        .derive_address(false)
        .context("derive recipient for fee estimation")?;
    let base_draft = wallet
        .create_draft(recipient.clone(), 50_000, None)
        .context("draft with light mempool load")?;
    assert_eq!(
        base_draft.fee_rate, 4,
        "low congestion should keep base rate"
    );

    let base_quote = wallet
        .latest_fee_quote()
        .expect("fee quote cached after base draft");
    match base_quote.source() {
        FeeEstimateSource::Node {
            congestion,
            samples,
        } => {
            assert_eq!(*samples, 2);
            assert_eq!(*congestion, FeeCongestionLevel::Low);
        }
        other => panic!("unexpected fee source {other:?}"),
    }

    wallet
        .engine_handle()
        .release_pending_locks()
        .context("release locks after base draft")?;

    node.set_mempool_info(MempoolInfo {
        tx_count: 9_900,
        vsize_limit: 1_000_000,
        vsize_in_use: 920_000,
        min_fee_rate: Some(15),
        max_fee_rate: Some(70),
    });
    node.set_recent_blocks(vec![
        BlockFeeSummary {
            height: fixture.latest_height() + 1,
            median_fee_rate: Some(20),
            max_fee_rate: Some(24),
        },
        BlockFeeSummary {
            height: fixture.latest_height() + 2,
            median_fee_rate: Some(22),
            max_fee_rate: Some(30),
        },
        BlockFeeSummary {
            height: fixture.latest_height() + 3,
            median_fee_rate: Some(24),
            max_fee_rate: Some(32),
        },
    ]);

    let surge_draft = wallet
        .create_draft(recipient.clone(), 60_000, None)
        .context("draft under high mempool load")?;
    assert_eq!(
        surge_draft.fee_rate, 70,
        "high congestion should cap at max hint"
    );

    let surge_quote = wallet
        .latest_fee_quote()
        .expect("fee quote cached after surge draft");
    match surge_quote.source() {
        FeeEstimateSource::Node {
            congestion,
            samples,
        } => {
            assert_eq!(*samples, 3);
            assert_eq!(*congestion, FeeCongestionLevel::High);
        }
        other => panic!("unexpected fee source {other:?}"),
    }

    wallet
        .engine_handle()
        .release_pending_locks()
        .context("release locks after surge draft")?;

    node.fail_fee_estimates(NodeClientError::network(anyhow!(
        "fee estimation rpc unavailable"
    )));
    let estimation_failure = wallet
        .create_draft(recipient, 40_000, None)
        .expect_err("estimation failure should be surfaced");
    assert!(matches!(
        estimation_failure,
        WalletError::Engine(EngineError::Fee(FeeError::Node(_)))
    ));

    sync.shutdown()
        .await
        .context("shutdown wallet sync coordinator")?;

    Ok(())
}
