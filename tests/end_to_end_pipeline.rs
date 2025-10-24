use std::collections::HashSet;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use rpp_chain::orchestration::PipelineStage;

mod support;

use support::cluster::{HarnessPipelineEvent, PipelineEventStream, ProcessTestCluster};

const PIPELINE_STAGE_TIMEOUT: Duration = Duration::from_secs(90);
const EVENT_SEQUENCE_TIMEOUT: Duration = Duration::from_secs(120);

/// Test setup:
/// - Requires the `rpp-node` binary to be available via `CARGO_BIN_EXE_rpp-node` (set by
///   `cargo test`).
/// - Relies on the default RPC/orchestrator endpoints exposed by the validator binary—no
///   additional feature flags are required.
/// - The process-based cluster spawns external validators and binds to ephemeral localhost
///   ports, so the test must run in an environment where spawning subprocesses and opening
///   TCP sockets is permitted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn orchestrated_pipeline_finalises_transaction() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match ProcessTestCluster::start(3).await {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping orchestrated pipeline test: {err:?}");
            return;
        }
    };

    let nodes = cluster.nodes();
    let primary_harness = match nodes[0].harness() {
        Ok(harness) => harness,
        Err(err) => {
            eprintln!("skipping orchestrated pipeline test: {err:?}");
            return;
        }
    };
    let recipient_harness = match nodes[1].harness() {
        Ok(harness) => harness,
        Err(err) => {
            eprintln!("skipping orchestrated pipeline test: {err:?}");
            return;
        }
    };

    let primary_rpc = primary_harness.rpc();
    let recipient_rpc = recipient_harness.rpc();

    let primary_summary = primary_rpc
        .account_summary()
        .await
        .expect("fetch primary wallet summary");
    let recipient_summary = recipient_rpc
        .account_summary()
        .await
        .expect("fetch recipient wallet summary");
    let recipient_address = recipient_summary.address.clone();

    let orchestrator_client = primary_harness.orchestrator();
    let event_stream = orchestrator_client
        .subscribe_events()
        .expect("subscribe to pipeline events");

    let expected_events = vec![
        PipelineStage::LeaderElected,
        PipelineStage::BftFinalised,
        PipelineStage::FirewoodCommitted,
    ];
    let monitor_expected = expected_events.clone();
    let (hash_tx, hash_rx) = tokio::sync::oneshot::channel();
    let event_monitor = tokio::spawn(async move {
        let hash = hash_rx.await.context("receive pipeline hash")?;
        monitor_pipeline_events(event_stream, hash, monitor_expected, EVENT_SEQUENCE_TIMEOUT).await
    });

    let amount = 5_000u128;
    let fee = 100u64;

    let submitted = orchestrator_client
        .submit_transaction(recipient_address, amount, fee, None)
        .await
        .expect("submit transaction via orchestrator client");

    hash_tx
        .send(submitted.hash.clone())
        .expect("notify event monitor of pipeline hash");

    let restart_binary = cluster.binary().to_string();
    let stage_sequence = [
        PipelineStage::GossipReceived,
        PipelineStage::MempoolAccepted,
        PipelineStage::LeaderElected,
        PipelineStage::BftFinalised,
        PipelineStage::FirewoodCommitted,
        PipelineStage::RewardsDistributed,
    ];

    for stage in stage_sequence {
        orchestrator_client
            .wait_for_stage(&submitted.hash, stage, PIPELINE_STAGE_TIMEOUT)
            .await
            .unwrap_or_else(|err| panic!("stage {stage:?} not reached: {err}"));

        if stage == PipelineStage::LeaderElected {
            let restart_client = cluster.client();
            cluster.nodes_mut()[0]
                .respawn(&restart_binary, &restart_client)
                .await
                .expect("respawn primary validator");
            primary_harness
                .wait_for_ready(PIPELINE_STAGE_TIMEOUT)
                .await
                .expect("primary validator ready after respawn");
        }
    }

    let observed = event_monitor
        .await
        .expect("pipeline event monitor task")
        .expect("pipeline event sequence");
    assert_eq!(
        observed, expected_events,
        "pipeline events observed out of order"
    );

    let dashboard = orchestrator_client
        .pipeline_dashboard()
        .await
        .expect("fetch pipeline dashboard snapshot");
    for stage in stage_sequence {
        assert!(
            dashboard.is_stage_complete(&submitted.hash, stage),
            "dashboard missing stage {stage:?}"
        );
    }

    let final_summary = primary_rpc
        .account_summary()
        .await
        .expect("fetch final wallet summary");

    assert_eq!(
        final_summary.nonce,
        primary_summary.nonce + 1,
        "sender nonce should increment after submission",
    );

    assert!(
        primary_summary.balance >= amount + u128::from(fee),
        "sender balance should cover transfer and fee",
    );
    let expected_balance = primary_summary.balance - amount - u128::from(fee);
    assert_eq!(
        final_summary.balance, expected_balance,
        "sender balance should reflect amount and fee",
    );

    cluster.shutdown().await.expect("shutdown cluster");
}

async fn monitor_pipeline_events(
    mut stream: PipelineEventStream,
    hash: String,
    expected: Vec<PipelineStage>,
    total_timeout: Duration,
) -> Result<Vec<PipelineStage>> {
    let mut observed = Vec::new();
    let mut seen = HashSet::new();
    let mut errors = Vec::new();
    let deadline = Instant::now() + total_timeout;

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let wait_for = if remaining < Duration::from_secs(5) {
            remaining
        } else {
            Duration::from_secs(5)
        };
        if wait_for.is_zero() {
            break;
        }
        match stream.next_event(wait_for).await? {
            Some(HarnessPipelineEvent::Dashboard { snapshot }) => {
                for stage in &expected {
                    if snapshot.is_stage_complete(&hash, *stage) && seen.insert(*stage) {
                        observed.push(*stage);
                        if observed.len() == expected.len() {
                            return Ok(observed);
                        }
                    }
                }
            }
            Some(HarnessPipelineEvent::Error { error }) => errors.push(error),
            None => {}
        }
    }

    let missing = expected
        .into_iter()
        .filter(|stage| !seen.contains(stage))
        .collect::<Vec<_>>();
    Err(anyhow!(
        "missing pipeline stages {:?}; errors observed: {:?}",
        missing,
        errors
    ))
}
