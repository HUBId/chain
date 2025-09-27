use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use libp2p::gossipsub::IdentTopic;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use tokio::runtime::Builder;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::info;

use crate::metrics::{exporters, Collector, SimulationSummary};
use crate::node_adapter::{spawn_node, Node, NodeHandle};
use crate::scenario::{LinkParams, Scenario, TopologyType};
use crate::topology::{
    annotate_links, AnnotatedLink, ErdosRenyiTopology, KRegularTopology, RingTopology,
    ScaleFreeTopology, SmallWorldTopology, Topology,
};
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

    let mut rng = StdRng::seed_from_u64(scenario.sim.seed);
    let edges = build_topology_edges(&scenario, node_count, &mut rng)?;
    let regions = scenario.node_regions();
    let annotated = annotate_links(&edges, &regions, &scenario.links)?;
    establish_links(&handles, &annotated, &mut rng).await?;

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

fn build_topology_edges(
    scenario: &Scenario,
    n: usize,
    rng: &mut StdRng,
) -> Result<Vec<(usize, usize)>> {
    match scenario.topology.topology_type {
        TopologyType::Ring => {
            let k = scenario
                .topology
                .k
                .ok_or_else(|| anyhow!("ring topology requires k parameter"))?;
            let topo = RingTopology::new(k)?;
            topo.build(n, rng)
        }
        TopologyType::ErdosRenyi => {
            let p = scenario
                .topology
                .p
                .ok_or_else(|| anyhow!("erdos-renyi topology requires p parameter"))?;
            let topo = ErdosRenyiTopology::new(p)?;
            topo.build(n, rng)
        }
        TopologyType::KRegular => {
            let k = scenario
                .topology
                .k
                .ok_or_else(|| anyhow!("k-regular topology requires k parameter"))?;
            let topo = KRegularTopology::new(k)?;
            topo.build(n, rng)
        }
        TopologyType::SmallWorld => {
            let k = scenario
                .topology
                .k
                .ok_or_else(|| anyhow!("small-world topology requires k parameter"))?;
            let rewire = scenario
                .topology
                .rewire_p
                .ok_or_else(|| anyhow!("small-world topology requires rewire_p parameter"))?;
            let topo = SmallWorldTopology::new(k, rewire)?;
            topo.build(n, rng)
        }
        TopologyType::ScaleFree => {
            let k = scenario.topology.k.unwrap_or(2);
            let topo = ScaleFreeTopology::new(k)?;
            topo.build(n, rng)
        }
    }
}

async fn establish_links(
    handles: &[NodeHandle],
    annotated: &[AnnotatedLink],
    rng: &mut StdRng,
) -> Result<()> {
    let mut tasks = Vec::new();
    for link in annotated {
        if handles.get(link.a).is_none() || handles.get(link.b).is_none() {
            return Err(anyhow!("link references out of range node"));
        }
        let drop_chance = rng.gen::<f64>() * 100.0;
        if drop_chance < link.params.loss {
            continue;
        }
        let delay = jittered_delay(&link.params, rng);
        let handle = handles[link.a].clone();
        let target_peer = handles[link.b].peer_id.clone();
        let target_addr = handles[link.b].listen_addr().clone();
        tasks.push(tokio::spawn(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            if let Err(err) = handle.dial(target_peer, target_addr).await {
                tracing::warn!(target = "rpp::sim::harness", "dial failed: {err:?}");
            }
        }));
    }
    for task in tasks {
        let _ = task.await;
    }
    Ok(())
}

fn jittered_delay(params: &LinkParams, rng: &mut StdRng) -> Duration {
    let base = Duration::from_millis(params.delay_ms);
    if params.jitter_ms == 0 {
        return base;
    }
    let jitter = params.jitter_ms as i64;
    let offset = rng.gen_range(-jitter, jitter + 1);
    if offset >= 0 {
        base + Duration::from_millis(offset as u64)
    } else {
        base.saturating_sub(Duration::from_millis((-offset) as u64))
    }
}
