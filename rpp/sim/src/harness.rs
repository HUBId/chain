use std::mem::MaybeUninit;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rpp_p2p::peerstore::peer_class::PeerClass;
use rpp_p2p::vendor::gossipsub::IdentTopic;
use tokio::runtime::Builder;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::info;

use crate::faults::PartitionFault;
use crate::metrics::{
    exporters, Collector, FaultEvent, PropagationProbeKind, ResourceUsageMetrics, SimEvent,
    SimulationSummary,
};
use crate::multiprocess;
use crate::node_adapter::{classify_peer_id, spawn_node, Node, NodeHandle};
use crate::scenario::{LinkParams, PeerClassLatencyProfile, Scenario, TopologyType};
use crate::topology::{
    annotate_links, AnnotatedLink, ErdosRenyiTopology, KRegularTopology, RingTopology,
    ScaleFreeTopology, SmallWorldTopology, Topology,
};

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
        runtime.block_on(async {
            match scenario.sim.mode.as_deref() {
                Some(mode)
                    if mode.eq_ignore_ascii_case("multiprocess")
                        || mode.eq_ignore_ascii_case("multi-process")
                        || mode.eq_ignore_ascii_case("compare") =>
                {
                    multiprocess::run(scenario).await
                }
                Some(mode) if mode.eq_ignore_ascii_case("inprocess") => {
                    run_in_process(scenario).await
                }
                Some(other) => Err(anyhow!("unknown simulation mode: {other}")),
                None => run_in_process(scenario).await,
            }
        })
    }
}

pub(crate) async fn run_in_process(scenario: Scenario) -> Result<SimulationSummary> {
    tracing_subscriber::fmt::try_init().ok();

    let topic = IdentTopic::new("/rpp/sim/tx");
    let node_count = scenario.topology.n;
    let backend_label = std::env::var("SIM_BACKEND_LABEL")
        .ok()
        .or_else(|| scenario.sim.mode.clone())
        .unwrap_or_else(|| "inprocess".to_string());

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
    let harness_event_tx = event_tx.clone();
    let mut forwarders = Vec::new();

    for Node {
        handle, mut events, ..
    } in nodes.into_iter()
    {
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

    let collector_start = Instant::now();
    let collector = Arc::new(Mutex::new(Collector::new(collector_start)));
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
    let latency_seed = scenario.latency_profile_seed();
    let mut latency_rng = StdRng::seed_from_u64(latency_seed);
    let latency_profile = scenario.latency_profile.clone();
    let edges = build_topology_edges(&scenario, node_count, &mut rng)?;
    let regions = scenario.node_regions();
    let annotated = annotate_links(&edges, &regions, &scenario.links)?;
    let adjacency = build_adjacency(node_count, &annotated);
    let peer_classes: Vec<PeerClass> = handles
        .iter()
        .map(|handle| classify_peer_id(&handle.peer_id))
        .collect();
    dial_links(
        &handles,
        &annotated,
        &mut rng,
        &mut latency_rng,
        latency_profile.as_ref(),
        &peer_classes,
    )
    .await?;

    let partition_fault = scenario.partition_fault();
    let churn_fault = scenario.churn_fault();
    let byzantine_fault = scenario.byzantine_fault();
    let partition_active = Arc::new(AtomicBool::new(false));
    let active_nodes = Arc::new(Mutex::new((0..handles.len()).collect::<Vec<_>>()));
    let mut fault_tasks: Vec<JoinHandle<()>> = Vec::new();

    if let Some(partition) = partition_fault.clone() {
        let handles_clone = handles.clone();
        let events = harness_event_tx.clone();
        let partition_active_flag = Arc::clone(&partition_active);
        let peer_classes_clone = peer_classes.clone();
        let latency_profile_clone = latency_profile.clone();
        let links: Vec<AnnotatedLink> = annotated
            .iter()
            .filter(|link| link_crosses_partition(&partition, &regions, link))
            .cloned()
            .collect();
        if !links.is_empty() {
            fault_tasks.push(tokio::spawn(async move {
                tokio::time::sleep(partition.start).await;
                partition_active_flag.store(true, Ordering::SeqCst);
                let detail = Some(format!("{}-{}", partition.group_a, partition.group_b));
                let _ = events.send(SimEvent::Fault {
                    kind: FaultEvent::PartitionStart,
                    detail: detail.clone(),
                    timestamp: Instant::now(),
                });
                if let Err(err) = disconnect_links(&handles_clone, &links).await {
                    tracing::warn!(
                        target = "rpp::sim::harness",
                        "partition disconnect failed: {err:?}"
                    );
                }
                tokio::time::sleep(partition.duration).await;
                partition_active_flag.store(false, Ordering::SeqCst);
                let mut rng =
                    StdRng::seed_from_u64(0x7061_7274 ^ partition.start.as_millis() as u64);
                let mut latency_rng =
                    StdRng::seed_from_u64(latency_seed ^ partition.start.as_millis() as u64);
                if let Err(err) = dial_links(
                    &handles_clone,
                    &links,
                    &mut rng,
                    &mut latency_rng,
                    latency_profile_clone.as_ref(),
                    &peer_classes_clone,
                )
                .await
                {
                    tracing::warn!(
                        target = "rpp::sim::harness",
                        "partition reconnect failed: {err:?}"
                    );
                }
                let _ = events.send(SimEvent::Fault {
                    kind: FaultEvent::PartitionEnd,
                    detail,
                    timestamp: Instant::now(),
                });
            }));
        }
    }

    if let Some(churn) = churn_fault.clone() {
        if let Some(interval) = churn.interval() {
            let handles_clone = handles.clone();
            let annotated_clone = annotated.clone();
            let adjacency_clone = adjacency.clone();
            let regions_clone = regions.clone();
            let active_nodes_clone = Arc::clone(&active_nodes);
            let events = harness_event_tx.clone();
            let partition_flag = Arc::clone(&partition_active);
            let partition_for_churn = partition_fault.clone();
            let peer_classes_clone = peer_classes.clone();
            let latency_profile_clone = latency_profile.clone();
            let seed = scenario.sim.seed ^ 0x4355_524e;
            fault_tasks.push(tokio::spawn(async move {
                if churn.start > Duration::ZERO {
                    tokio::time::sleep(churn.start).await;
                }
                let mut rng = StdRng::seed_from_u64(seed);
                loop {
                    tokio::time::sleep(interval).await;
                    let node_idx = {
                        let mut nodes = active_nodes_clone.lock().await;
                        if nodes.is_empty() {
                            None
                        } else {
                            let choice = rng.gen_range(0, nodes.len());
                            Some(nodes.remove(choice))
                        }
                    };
                    let Some(node_idx) = node_idx else {
                        continue;
                    };
                    let detail = Some(format!("node:{node_idx}"));
                    let _ = events.send(SimEvent::Fault {
                        kind: FaultEvent::ChurnDown,
                        detail: detail.clone(),
                        timestamp: Instant::now(),
                    });
                    let link_indices = adjacency_clone.get(node_idx).cloned().unwrap_or_default();
                    let mut node_links = Vec::with_capacity(link_indices.len());
                    for link_idx in link_indices {
                        node_links.push(annotated_clone[link_idx].clone());
                    }
                    if let Err(err) = disconnect_links(&handles_clone, &node_links).await {
                        tracing::warn!(
                            target = "rpp::sim::harness",
                            "churn disconnect failed: {err:?}"
                        );
                    }
                    tokio::time::sleep(churn.restart_after).await;
                    {
                        let mut nodes = active_nodes_clone.lock().await;
                        if !nodes.contains(&node_idx) {
                            nodes.push(node_idx);
                            nodes.sort_unstable();
                        }
                    }
                    let _ = events.send(SimEvent::Fault {
                        kind: FaultEvent::ChurnUp,
                        detail: detail.clone(),
                        timestamp: Instant::now(),
                    });
                    let mut rng_local = StdRng::seed_from_u64(seed ^ (node_idx as u64 + 1));
                    let mut latency_rng =
                        StdRng::seed_from_u64(latency_seed ^ (node_idx as u64 + 1));
                    let mut to_restore = Vec::new();
                    for link in node_links.iter() {
                        if partition_flag.load(Ordering::SeqCst) {
                            if let Some(partition) = &partition_for_churn {
                                if link_crosses_partition(partition, &regions_clone, link) {
                                    continue;
                                }
                            }
                        }
                        to_restore.push(link.clone());
                    }
                    if let Err(err) = dial_links(
                        &handles_clone,
                        &to_restore,
                        &mut rng_local,
                        &mut latency_rng,
                        latency_profile_clone.as_ref(),
                        &peer_classes_clone,
                    )
                    .await
                    {
                        tracing::warn!(
                            target = "rpp::sim::harness",
                            "churn reconnect failed: {err:?}"
                        );
                    }
                }
            }));
        }
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut traffic = scenario.traffic_program()?;
    let mut payload_generator = scenario.payload_generator();
    let total_duration = Duration::from_millis(scenario.sim.duration_ms);
    let mut elapsed = Duration::ZERO;
    let mut message_counter: u64 = 0;
    let mut probe_sequence: u64 = 0;
    let mut next_probe_at = Duration::ZERO;
    let probe_interval = Duration::from_secs(30);

    while elapsed < total_duration {
        while elapsed >= next_probe_at && next_probe_at <= total_duration {
            emit_propagation_probes(
                &handles,
                &peer_classes,
                &mut payload_generator,
                &mut probe_sequence,
            )
            .await?;
            next_probe_at = next_probe_at.saturating_add(probe_interval);
            if probe_interval.is_zero() {
                break;
            }
        }

        let step = match traffic.next_step() {
            Some(step) => step,
            None => {
                let remaining = total_duration.saturating_sub(elapsed);
                if remaining > Duration::ZERO {
                    tokio::time::sleep(remaining).await;
                    elapsed += remaining;
                }
                break;
            }
        };
        let wait = step.wait;
        if elapsed + wait > total_duration {
            let remaining = total_duration - elapsed;
            if remaining > Duration::ZERO {
                tokio::time::sleep(remaining).await;
                elapsed += remaining;
            }
            break;
        }
        tokio::time::sleep(wait).await;
        elapsed += wait;
        if !step.publish {
            continue;
        }
        let publisher_idx = {
            let nodes = active_nodes.lock().await;
            if nodes.is_empty() {
                None
            } else {
                traffic
                    .pick_publisher(nodes.len())
                    .map(|selected| nodes[selected])
            }
        };
        let Some(publisher_idx) = publisher_idx else {
            continue;
        };
        let payload = payload_generator.next_payload(message_counter);
        handles[publisher_idx]
            .publish(payload.clone())
            .await
            .context("publish failed")?;
        if let Some(byzantine) = &byzantine_fault {
            if elapsed >= byzantine.start && byzantine.is_publisher(publisher_idx) {
                let detail = Some(format!("node:{publisher_idx}"));
                let _ = harness_event_tx.send(SimEvent::Fault {
                    kind: FaultEvent::ByzantineSpam,
                    detail: detail.clone(),
                    timestamp: Instant::now(),
                });
                for _ in 1..byzantine.spam_factor {
                    handles[publisher_idx]
                        .publish(payload.clone())
                        .await
                        .context("byzantine publish failed")?;
                }
            }
        }
        message_counter += 1;
    }

    tokio::time::sleep(Duration::from_millis(1_000)).await;

    for task in fault_tasks {
        task.abort();
        let _ = task.await;
    }

    drop(harness_event_tx);

    for handle in &handles {
        let _ = handle.shutdown().await;
    }

    for task in forwarders {
        let _ = task.await;
    }

    collector_task.await.context("collector task failed")?;

    let end_time = Instant::now();

    let mut collector = Arc::try_unwrap(collector)
        .map_err(|_| anyhow!("collector still in use"))?
        .into_inner();
    if let Some(resource_usage) = capture_resource_usage(collector_start, end_time) {
        collector.record_resource_usage(resource_usage);
    }
    let summary = collector.finalize(Some(backend_label.clone()));

    for traffic in &summary.peer_traffic {
        info!(
            target = "rpp::sim::harness",
            peer = %traffic.peer_id,
            peer_class = %traffic.peer_class,
            bytes_in = traffic.bytes_in,
            bytes_out = traffic.bytes_out,
            "peer traffic totals"
        );
    }

    let metrics_outputs = scenario.metrics_outputs();
    if let Some(output_path) = metrics_outputs.json {
        exporters::export_json(output_path, &summary)?;
    }
    if let Some(csv_path) = metrics_outputs.csv {
        exporters::export_csv(csv_path, &summary)?;
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

async fn dial_links(
    handles: &[NodeHandle],
    annotated: &[AnnotatedLink],
    rng: &mut StdRng,
    latency_rng: &mut StdRng,
    latency_profile: Option<&PeerClassLatencyProfile>,
    peer_classes: &[PeerClass],
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
        let target_class = peer_classes.get(link.b).copied();
        let class_params =
            target_class.and_then(|class| latency_profile.and_then(|p| p.params_for(class)));
        let delay = jittered_delay(&link.params, class_params, latency_rng);
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

async fn disconnect_links(handles: &[NodeHandle], annotated: &[AnnotatedLink]) -> Result<()> {
    let mut tasks = Vec::new();
    for link in annotated {
        if handles.get(link.a).is_none() || handles.get(link.b).is_none() {
            return Err(anyhow!("link references out of range node"));
        }
        let handle_a = handles[link.a].clone();
        let peer_b = handles[link.b].peer_id.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(err) = handle_a.disconnect(peer_b).await {
                tracing::warn!(target = "rpp::sim::harness", "disconnect failed: {err:?}");
            }
        }));
        let handle_b = handles[link.b].clone();
        let peer_a = handles[link.a].peer_id.clone();
        tasks.push(tokio::spawn(async move {
            if let Err(err) = handle_b.disconnect(peer_a).await {
                tracing::warn!(target = "rpp::sim::harness", "disconnect failed: {err:?}");
            }
        }));
    }
    for task in tasks {
        let _ = task.await;
    }
    Ok(())
}

async fn emit_propagation_probes(
    handles: &[NodeHandle],
    peer_classes: &[PeerClass],
    payload_generator: &mut PayloadGenerator,
    probe_sequence: &mut u64,
) -> Result<()> {
    for class in [PeerClass::Trusted, PeerClass::Untrusted] {
        let Some(publisher_idx) = pick_peer_by_class(peer_classes, class) else {
            continue;
        };

        for kind in [
            PropagationProbeKind::Block,
            PropagationProbeKind::Transaction,
        ] {
            *probe_sequence = probe_sequence.saturating_add(1);
            let payload = payload_generator.probe_payload(kind, *probe_sequence);
            handles[publisher_idx]
                .publish_probe(payload.clone(), kind)
                .await?;
        }
    }

    Ok(())
}

fn pick_peer_by_class(peer_classes: &[PeerClass], class: PeerClass) -> Option<usize> {
    peer_classes.iter().position(|entry| *entry == class)
}

fn jittered_delay(
    link_params: &LinkParams,
    class_params: Option<&PeerClassLatency>,
    rng: &mut StdRng,
) -> Duration {
    let mut base = Duration::from_millis(link_params.delay_ms);
    if let Some(class) = class_params {
        base += Duration::from_millis(class.extra_delay_ms);
    }

    base = apply_jitter(base, link_params.jitter_ms, rng);
    if let Some(class) = class_params {
        base = apply_jitter(base, class.jitter_ms, rng);
    }

    base
}

fn apply_jitter(base: Duration, jitter_ms: u64, rng: &mut StdRng) -> Duration {
    if jitter_ms == 0 {
        return base;
    }
    let jitter = jitter_ms as i64;
    let offset = rng.gen_range(-jitter, jitter + 1);
    if offset >= 0 {
        base + Duration::from_millis(offset as u64)
    } else {
        base.saturating_sub(Duration::from_millis((-offset) as u64))
    }
}

fn build_adjacency(n: usize, links: &[AnnotatedLink]) -> Vec<Vec<usize>> {
    let mut adjacency = vec![Vec::new(); n];
    for (idx, link) in links.iter().enumerate() {
        adjacency[link.a].push(idx);
        adjacency[link.b].push(idx);
    }
    adjacency
}

fn link_crosses_partition(
    partition: &PartitionFault,
    regions: &[String],
    link: &AnnotatedLink,
) -> bool {
    let region_a = regions.get(link.a).map(|s| s.as_str()).unwrap_or("");
    let region_b = regions.get(link.b).map(|s| s.as_str()).unwrap_or("");
    partition.affects(region_a, region_b)
}

fn capture_resource_usage(start: Instant, end: Instant) -> Option<ResourceUsageMetrics> {
    let mut usage = MaybeUninit::<libc::rusage>::uninit();
    let result = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
    if result != 0 {
        tracing::warn!(target = "rpp::sim::harness", "getrusage failed: {result}");
        return None;
    }
    let usage = unsafe { usage.assume_init() };
    let cpu_time_secs = timeval_to_secs(usage.ru_utime) + timeval_to_secs(usage.ru_stime);
    let wall_time_secs = end.duration_since(start).as_secs_f64();
    let avg_cpu_percent = if wall_time_secs > 0.0 {
        (cpu_time_secs / wall_time_secs) * 100.0
    } else {
        0.0
    };
    let max_rss_bytes = usage.ru_maxrss.saturating_mul(1024) as u64;

    Some(ResourceUsageMetrics {
        cpu_time_secs,
        wall_time_secs,
        avg_cpu_percent,
        max_rss_bytes,
    })
}

fn timeval_to_secs(value: libc::timeval) -> f64 {
    value.tv_sec as f64 + f64::from(value.tv_usec) / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::scenario::Scenario;
    use std::sync::{Mutex as StdMutex, OnceLock};

    fn scenario_from_str(toml: &str) -> Scenario {
        let mut scenario: Scenario = toml::from_str(toml).expect("valid scenario");
        scenario.links = scenario.links.with_defaults();
        scenario
    }

    fn harness_lock() -> &'static StdMutex<()> {
        static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| StdMutex::new(()))
    }

    #[test]
    fn partition_fault_records_events() {
        let scenario = scenario_from_str(
            r#"
[sim]
seed = 7
duration_ms = 600

[topology]
type = "ring"
n = 4
k = 2

[regions]
assignments = ["EU", "US", "EU", "US"]

[links]
default = { delay_ms = 0, jitter_ms = 0, loss = 0.0 }

[traffic.tx]

[[traffic.tx.phases]]
duration_ms = 600
model = "poisson"
lambda_per_sec = 40.0

[faults.partition]
start_ms = 10
duration_ms = 100
group_a = "EU"
group_b = "US"
            "#,
        );
        let _guard = harness_lock().lock().unwrap();
        let harness = SimHarness;
        let summary = harness
            .run_scenario(scenario)
            .expect("partition scenario executes");
        let kinds: Vec<_> = summary.faults.iter().map(|f| f.kind.clone()).collect();
        let start_pos = kinds.iter().position(|k| k == "partition_start");
        let end_pos = kinds.iter().position(|k| k == "partition_end");
        assert!(start_pos.is_some(), "partition_start missing");
        assert!(end_pos.is_some(), "partition_end missing");
        assert!(start_pos.unwrap() < end_pos.unwrap());
    }

    #[test]
    fn churn_fault_emits_down_and_up() {
        let scenario = scenario_from_str(
            r#"
[sim]
seed = 9
duration_ms = 800

[topology]
type = "ring"
n = 3
k = 2

[links]
default = { delay_ms = 0, jitter_ms = 0, loss = 0.0 }

[traffic.tx]

[[traffic.tx.phases]]
duration_ms = 800
model = "poisson"
lambda_per_sec = 35.0

[faults.churn]
start_ms = 50
rate_per_min = 600.0
restart_after_ms = 100
            "#,
        );
        let _guard = harness_lock().lock().unwrap();
        let harness = SimHarness;
        let summary = harness
            .run_scenario(scenario)
            .expect("churn scenario executes");
        let kinds: Vec<_> = summary.faults.iter().map(|f| f.kind.as_str()).collect();
        assert!(kinds.contains(&"churn_down"));
        assert!(kinds.contains(&"churn_up"));
    }

    #[test]
    fn byzantine_spam_is_logged() {
        let scenario = scenario_from_str(
            r#"
[sim]
seed = 11
duration_ms = 500

[topology]
type = "ring"
n = 1
k = 2

[links]
default = { delay_ms = 0, jitter_ms = 0, loss = 0.0 }

[traffic.tx]

[[traffic.tx.phases]]
duration_ms = 500
model = "poisson"
lambda_per_sec = 20.0

[faults.byzantine]
start_ms = 0
spam_factor = 3
publishers = [0]
            "#,
        );
        let _guard = harness_lock().lock().unwrap();
        let harness = SimHarness;
        let summary = harness
            .run_scenario(scenario)
            .expect("byzantine scenario executes");
        let kinds: Vec<_> = summary.faults.iter().map(|f| f.kind.as_str()).collect();
        assert!(kinds.contains(&"byzantine_spam"));
    }

    #[test]
    fn jittered_delay_applies_peer_class_overrides() {
        let base = LinkParams {
            delay_ms: 20,
            jitter_ms: 0,
            loss: 0.0,
        };
        let class = PeerClassLatency {
            extra_delay_ms: 10,
            jitter_ms: 0,
        };
        let mut rng = StdRng::seed_from_u64(1);
        let without_class = jittered_delay(&base, None, &mut rng);
        let mut rng = StdRng::seed_from_u64(1);
        let with_class = jittered_delay(&base, Some(&class), &mut rng);
        assert_eq!(without_class, Duration::from_millis(20));
        assert_eq!(with_class, Duration::from_millis(30));

        let jittery = LinkParams {
            delay_ms: 0,
            jitter_ms: 2,
            loss: 0.0,
        };
        let class_jitter = PeerClassLatency {
            extra_delay_ms: 0,
            jitter_ms: 2,
        };
        let mut rng = StdRng::seed_from_u64(99);
        let combined = jittered_delay(&jittery, Some(&class_jitter), &mut rng);
        assert!(combined <= Duration::from_millis(4));
    }
}
