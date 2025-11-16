#![cfg(feature = "wallet-integration")]

//! Wallet resume and rescan integration tests.
//!
//! These scenarios validate checkpoint handling, rescan scheduling, and node
//! hint propagation. They execute quickly with both the mock and STWO prover
//! configurations.

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;

use anyhow::{Context, Result};
use common::wallet::{wait_for, wait_for_status, WalletTestBuilder};
use rpp_wallet::config::wallet::WalletProverConfig;
use rpp_wallet::indexer::scanner::SyncMode;
use rpp_wallet::node_client::{NodeClientError, NodeRejectionHint};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wallet_records_rescan_and_resume_checkpoints() -> Result<()> {
    let mut prover_config = WalletProverConfig::default();
    if cfg!(feature = "prover-stwo") {
        prover_config.enabled = true;
        prover_config.mock_fallback = true;
    }

    let fixture = WalletTestBuilder::default()
        .with_birthday_height(96)
        .with_latest_height(208)
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
                .list_utxos()
                .map(|utxos| !utxos.is_empty())
                .unwrap_or(false)
        }
    })
    .await;

    let initial = wait_for_status(&sync, |status| {
        matches!(status.mode, SyncMode::Resume { .. })
    })
    .await;
    assert_eq!(initial.latest_height, fixture.latest_height());
    assert_eq!(
        initial.pending_ranges,
        vec![(fixture.birthday_height(), fixture.latest_height())]
    );
    assert_eq!(
        initial.checkpoints.birthday_height,
        Some(fixture.birthday_height())
    );
    assert_eq!(
        initial.checkpoints.resume_height,
        Some(fixture.latest_height())
    );

    let mut requests = fixture.indexer().scan_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0], fixture.birthday_height());

    let rejection = NodeClientError::rejected_with_hint(
        "fee too low",
        NodeRejectionHint::FeeRateTooLow { required: Some(32) },
    );
    sync.record_node_failure(&rejection);
    let failure_status = sync.latest_status().expect("status with node failure");
    assert!(failure_status.node_issue.is_some());
    assert!(!failure_status.hints.is_empty());
    sync.clear_node_failure();

    let rescan_from = fixture.latest_height() - 12;
    assert!(sync
        .request_rescan(rescan_from)
        .context("schedule rescan")?);
    assert!(!sync
        .request_rescan(rescan_from + 1)
        .context("second rescan request should be coalesced")?);

    let rescan_status = wait_for_status(&sync, |status| {
        matches!(status.mode, SyncMode::Rescan { .. })
    })
    .await;
    assert_eq!(rescan_status.latest_height, fixture.latest_height());
    assert_eq!(
        rescan_status.pending_ranges,
        vec![(rescan_from, fixture.latest_height())]
    );
    assert_eq!(
        rescan_status.checkpoints.resume_height,
        Some(fixture.latest_height())
    );

    requests = fixture.indexer().scan_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1], rescan_from);

    assert!(sync.request_resume_sync().context("schedule resume")?);
    let resume_status = wait_for_status(&sync, |status| {
        matches!(status.mode, SyncMode::Resume { .. })
            && status.checkpoints.last_targeted_rescan_ts.is_some()
    })
    .await;
    assert_eq!(resume_status.latest_height, fixture.latest_height());
    assert!(resume_status.checkpoints.last_targeted_rescan_ts.is_some());

    requests = fixture.indexer().scan_requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[2], fixture.latest_height());

    sync.shutdown()
        .await
        .context("shutdown wallet sync coordinator")?;

    Ok(())
}
