use std::collections::HashSet;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use rpp_chain::orchestration::PipelineStage;

type StageList = [PipelineStage; 4];

use crate::support::cluster::{
    HarnessPipelineEvent, PipelineEventStream, ProcessTestCluster,
};

const STAGE_TIMEOUT: Duration = Duration::from_secs(90);
const STREAM_TIMEOUT: Duration = Duration::from_secs(120);
const PIPELINE_SEQUENCE: StageList = [
    PipelineStage::GossipReceived,
    PipelineStage::MempoolAccepted,
    PipelineStage::BftFinalised,
    PipelineStage::FirewoodCommitted,
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wallet_proof_bft_firewood_pipeline_reaches_all_stages() {
    let _ = tracing_subscriber::fmt::try_init();

    let mut cluster = match ProcessTestCluster::start(3).await {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping pipeline smoke-test: {err:?}");
            return;
        }
    };

    let nodes = cluster.nodes();
    let primary = match nodes[0].harness() {
        Ok(handle) => handle,
        Err(err) => {
            eprintln!("skipping pipeline smoke-test: {err:?}");
            return;
        }
    };
    let recipient = match nodes[1].harness() {
        Ok(handle) => handle,
        Err(err) => {
            eprintln!("skipping pipeline smoke-test: {err:?}");
            return;
        }
    };

    let primary_rpc = primary.rpc();
    let primary_summary = primary_rpc
        .account_summary()
        .await
        .expect("fetch primary account summary");
    let recipient_summary = recipient
        .rpc()
        .account_summary()
        .await
        .expect("fetch recipient account summary");

    let orchestrator = primary.orchestrator();
    let event_stream = match orchestrator.subscribe_events() {
        Ok(stream) => stream,
        Err(err) => {
            eprintln!("skipping pipeline smoke-test: {err:?}");
            return;
        }
    };

    let (hash_tx, hash_rx) = tokio::sync::oneshot::channel();
    let monitor = tokio::spawn(async move {
        let hash = hash_rx.await.context("receive pipeline hash")?;
        monitor_sequence(event_stream, hash, &PIPELINE_SEQUENCE, STREAM_TIMEOUT).await
    });

    let amount = 5_000u128;
    let fee = 100u64;

    let submission = orchestrator
        .submit_transaction(recipient_summary.address.clone(), amount, fee, None)
        .await
        .expect("submit transaction via orchestrator");

    hash_tx
        .send(submission.hash.clone())
        .expect("notify monitor of pipeline hash");

    for stage in PIPELINE_SEQUENCE {
        orchestrator
            .wait_for_stage(&submission.hash, stage, STAGE_TIMEOUT)
            .await
            .unwrap_or_else(|err| panic!("stage {stage:?} not reached: {err}"));
    }

    let observed = monitor
        .await
        .expect("stage monitor task")
        .expect("pipeline stage sequence");
    assert_eq!(
        observed.as_slice(),
        PIPELINE_SEQUENCE,
        "pipeline stages observed out of order",
    );

    let dashboard = orchestrator
        .pipeline_dashboard()
        .await
        .expect("fetch pipeline dashboard");

    for stage in PIPELINE_SEQUENCE {
        assert!(
            dashboard.is_stage_complete(&submission.hash, stage),
            "dashboard missing stage {stage:?}",
        );
    }

    let flow = dashboard
        .flows
        .iter()
        .find(|flow| flow.hash == submission.hash)
        .expect("pipeline flow present in dashboard");
    assert!(
        flow.commit_height.is_some(),
        "firewood stage should record commit height",
    );

    let final_summary = primary_rpc
        .account_summary()
        .await
        .expect("fetch final sender summary");
    assert_eq!(
        final_summary.nonce,
        primary_summary.nonce + 1,
        "sender nonce should increase after submission",
    );
    let expected_balance = primary_summary.balance - amount - u128::from(fee);
    assert_eq!(
        final_summary.balance,
        expected_balance,
        "sender balance should reflect amount and fee",
    );

    cluster.shutdown().await.expect("shutdown cluster");
}

async fn monitor_sequence(
    mut stream: PipelineEventStream,
    hash: String,
    expected: &[PipelineStage],
    total_timeout: Duration,
) -> Result<Vec<PipelineStage>> {
    let mut observed = Vec::new();
    let mut seen = HashSet::new();
    let mut errors = Vec::new();
    let deadline = Instant::now() + total_timeout;

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let wait_for = remaining.min(Duration::from_secs(5));
        if wait_for.is_zero() {
            break;
        }

        match stream.next_event(wait_for).await? {
            Some(HarnessPipelineEvent::Dashboard { snapshot }) => {
                for stage in expected {
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

    Err(anyhow!(
        "pipeline stages not observed within {:?}: {errors:?}",
        total_timeout
    ))
}
