use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use libp2p::gossipsub::IdentTopic;
use tokio::runtime::Builder;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::info;

use crate::metrics::{exporters, Collector, SimulationSummary};
use crate::node_adapter::{spawn_node, Node};
use crate::scenario::Scenario;
use crate::topology::RingTopology;
use crate::traffic::PoissonTraffic;

pub struct SimHarness;

impl SimHarness {
    pub fn run_from_path(&self, scenario_path: impl AsRef<Path>) -> Result<SimulationSummary> {
        let scenario = Scenario::from_path(&scenario_path)?;
        self.run_scenario(scenario)
    }

    pub fn run_scenario(&self, scenario: Scenario) -> Result<SimulationSummary> {
        let runtime = Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to build tokio runtime")?;
        runtime.block_on(run_simulation(scenario))
    }
}

async fn run_simulation(scenario: Scenario) -> Result<SimulationSummary> {
    tracing_subscriber::fmt::try_init().ok();

    let topic = IdentTopic::new("/rpp/sim/tx");
    let ring = RingTopology::new(scenario.topology.k)?;
    let node_count = scenario.topology.n;

    info!(
        target = "rpp::sim::harness",
        node_count, "starting simulation"
    );

    let mut nodes = Vec::with_capacity(node_count);
    for idx in 0..node_count {
        let node = spawn_node(idx, topic.clone()).context("failed to spawn node")?;
        nodes.push(node);
    }

    let mut handles = Vec::with_capacity(node_count);
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let mut forwarders = Vec::new();

    for Node { handle, mut events } in nodes.into_iter() {
        let tx_clone = event_tx.clone();
        forwarders.push(tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                if tx_clone.send(event).is_err() {
                    break;
                }
            }
        }));
        handles.push(handle);
    }
    drop(event_tx);

    let collector = Arc::new(Mutex::new(Collector::new(Instant::now())));
    let collector_task = {
        let collector = Arc::clone(&collector);
        tokio::spawn(async move {
            let mut rx = event_rx;
            while let Some(event) = rx.recv().await {
                collector.lock().await.ingest(event);
            }
        })
    };

    let edges = ring.build(node_count);
    for (a, b) in edges {
        let target_peer = handles[b].peer_id.clone();
        let target_addr = handles[b].listen_addr().clone();
        handles[a]
            .dial(target_peer, target_addr)
            .await
            .context("dial failed")?;
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut traffic = PoissonTraffic::new(scenario.traffic.tx.lambda_per_sec, scenario.sim.seed)?;
    let total_duration = Duration::from_millis(scenario.sim.duration_ms);
    let mut elapsed = Duration::ZERO;
    let mut message_counter: u64 = 0;

    while elapsed < total_duration {
        let wait = traffic.next_arrival();
        elapsed += wait;
        if elapsed > total_duration {
            break;
        }
        tokio::time::sleep(wait).await;
        let publisher_idx = traffic.pick_publisher(handles.len());
        let payload = format!("{{\"message\":{message_counter}}}").into_bytes();
        handles[publisher_idx]
            .publish(payload)
            .await
            .context("publish failed")?;
        message_counter += 1;
    }

    tokio::time::sleep(Duration::from_millis(1_000)).await;

    for handle in &handles {
        let _ = handle.shutdown().await;
    }

    for task in forwarders {
        let _ = task.await;
    }

    collector_task.await.context("collector task failed")?;

    let collector = Arc::try_unwrap(collector)
        .map_err(|_| anyhow!("collector still in use"))?
        .into_inner();
    let summary = collector.finalize();

    if let Some(output_path) = scenario.metrics_output() {
        exporters::export_json(output_path, &summary)?;
    }

    Ok(summary)
}
