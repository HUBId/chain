use std::fs::{self, File};
use std::io::Write;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use rpp_chain::orchestration::PipelineStage;
use tokio::time::sleep;

#[path = "support/mod.rs"]
mod support;

use support::cluster::{HarnessPipelineEvent, PipelineEventStream, ProcessTestCluster};

#[path = "mempool/helpers.rs"]
mod mempool_helpers;

use mempool_helpers::{enabled_backends, ProofBackend};

const STREAM_POLL: Duration = Duration::from_millis(200);
const STREAM_TIMEOUT: Duration = Duration::from_secs(30);
const PIPELINE_TIMEOUT: Duration = Duration::from_secs(60);

fn backend_label(backend: ProofBackend) -> String {
    match backend {
        ProofBackend::Stwo => "stwo".to_string(),
        #[cfg(feature = "backend-plonky3")]
        ProofBackend::Plonky3 => "plonky3".to_string(),
        #[cfg(feature = "backend-rpp-stark")]
        ProofBackend::RppStark => "rpp-stark".to_string(),
    }
}

#[derive(Clone, Copy, Debug)]
enum SubscriptionMode {
    Wallet,
    Node,
}

impl SubscriptionMode {
    fn as_str(&self) -> &'static str {
        match self {
            SubscriptionMode::Wallet => "wallet",
            SubscriptionMode::Node => "node",
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rpc_subscription_resilience_under_reorg_and_pruning() {
    let _ = tracing_subscriber::fmt::try_init();

    let backends = enabled_backends();
    let modes = [SubscriptionMode::Wallet, SubscriptionMode::Node];

    for backend in backends {
        for mode in modes {
            run_subscription_probe(&backend_label(backend), mode)
                .await
                .unwrap_or_else(|err| {
                    panic!("subscription probe for {backend:?} {mode:?} failed: {err}")
                });
        }
    }
}

async fn run_subscription_probe(backend: &str, mode: SubscriptionMode) -> Result<()> {
    let mut cluster = match ProcessTestCluster::start_with(2, |config, _| {
        config.rollout.feature_gates.pruning = true;
        config.rollout.feature_gates.reconstruction = true;
        config.rollout.feature_gates.recursive_proofs = true;
        config.rollout.feature_gates.consensus_enforcement = true;
        if backend == "plonky3" {
            config.rollout.feature_gates.malachite_consensus = true;
        }
        Ok(())
    })
    .await
    {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!("skipping subscription probe: {err:?}");
            return Ok(());
        }
    };

    let nodes = cluster.nodes();
    let primary = match nodes.get(0).and_then(|node| node.harness().ok()) {
        Some(harness) => harness,
        None => {
            eprintln!("skipping subscription probe: missing primary harness");
            return Ok(());
        }
    };

    let orchestrator = primary.orchestrator();
    let stream = orchestrator
        .subscribe_events()
        .context("subscribe to pipeline stream")?;

    let transcript = format!(
        "logs/stream-{}-{}-{}.log",
        backend,
        mode.as_str(),
        chrono::Utc::now().timestamp()
    );
    let transcript = StreamTranscript::new(&transcript)?;

    let primary_summary = primary
        .rpc()
        .account_summary()
        .await
        .context("load primary account summary")?;
    let recipient_summary = nodes
        .get(1)
        .and_then(|node| node.harness().ok())
        .and_then(|harness| harness.rpc().account_summary().await.ok())
        .context("load recipient account summary")?;

    let monitor = tokio::spawn(monitor_stream(stream, transcript));

    let submitted = orchestrator
        .submit_transaction(
            recipient_summary.address.clone(),
            1_000,
            25,
            Some(format!("mode: {} backend: {backend}", mode.as_str())),
        )
        .await
        .context("submit transaction via orchestrator")?;

    orchestrator
        .wait_for_stage(
            &submitted.hash,
            PipelineStage::LeaderElected,
            PIPELINE_TIMEOUT,
        )
        .await
        .context("wait for leader election")?;

    trigger_reorg_like_restart(&mut cluster).await?;

    orchestrator
        .wait_for_stage(
            &submitted.hash,
            PipelineStage::FirewoodCommitted,
            PIPELINE_TIMEOUT,
        )
        .await
        .context("wait for commit after restart")?;

    orchestrator
        .wait_for_stage(
            &submitted.hash,
            PipelineStage::RewardsDistributed,
            PIPELINE_TIMEOUT,
        )
        .await
        .context("wait for reward distribution")?;

    if let Some(node) = cluster.nodes_mut().get_mut(0) {
        let restart_binary = cluster.binary().to_string();
        let client = cluster.client();
        node.respawn(&restart_binary, &client, cluster.log_root())
            .await
            .context("respawn primary for pruning cycle")?;
    }

    sleep(Duration::from_secs(1)).await;

    orchestrator
        .wait_for_stage(
            &submitted.hash,
            PipelineStage::FirewoodCommitted,
            PIPELINE_TIMEOUT,
        )
        .await
        .context("verify commit after pruning restart")?;

    monitor
        .await
        .context("stream monitor join")?
        .context("monitor result")?;

    cluster.shutdown().await?;

    Ok(())
}

async fn monitor_stream(
    mut stream: PipelineEventStream,
    mut transcript: StreamTranscript,
) -> Result<()> {
    let mut observed = 0usize;
    loop {
        match stream.next_event(STREAM_TIMEOUT).await? {
            Some(event) => {
                observed += 1;
                transcript.record(&event)?;
            }
            None => {
                transcript.note("stream heartbeat timeout")?;
            }
        }
        if observed >= 3 {
            return Ok(());
        }
        sleep(STREAM_POLL).await;
    }
}

async fn trigger_reorg_like_restart(cluster: &mut ProcessTestCluster) -> Result<()> {
    if let Some(node) = cluster.nodes_mut().get_mut(0) {
        let binary = cluster.binary().to_string();
        let client = cluster.client();
        node.respawn(&binary, &client, cluster.log_root())
            .await
            .context("restart primary node to simulate reorg")?;
    }
    Ok(())
}

struct StreamTranscript {
    file: File,
}

impl StreamTranscript {
    fn new(path: &str) -> Result<Self> {
        if let Some(parent) = std::path::Path::new(path).parent() {
            fs::create_dir_all(parent).context("create transcript directory")?;
        }
        let file = File::create(path).context("create transcript file")?;
        Ok(Self { file })
    }

    fn record(&mut self, event: &HarnessPipelineEvent) -> Result<()> {
        writeln!(self.file, "{event:?}").context("write pipeline event")
    }

    fn note(&mut self, message: &str) -> Result<()> {
        writeln!(self.file, "{message}").context("write note")
    }
}
