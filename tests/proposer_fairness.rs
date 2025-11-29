use std::collections::HashMap;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use tokio::time::timeout;

use rpp_chain::consensus::ConsensusRound;
use rpp_chain::runtime::types::block::Block;

mod support;

use support::cluster::TestCluster;
use support::consensus::consensus_round_for_block;

const SAMPLE_SLOTS: u64 = 180;
const NETWORK_TIMEOUT: Duration = Duration::from_secs(30);
const BLOCK_POLL_INTERVAL: Duration = Duration::from_millis(300);
const TEST_TIMEOUT: Duration = Duration::from_secs(240);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum BackendKind {
    Stwo,
    #[cfg(feature = "backend-rpp-stark")]
    RppStark,
}

impl BackendKind {
    fn label(&self) -> &'static str {
        match self {
            BackendKind::Stwo => "stwo",
            #[cfg(feature = "backend-rpp-stark")]
            BackendKind::RppStark => "rpp-stark",
        }
    }
}

#[derive(Serialize)]
struct AddressStats {
    stake: String,
    expected: f64,
    selected: u64,
    produced: u64,
}

#[derive(Serialize)]
struct DistributionStats {
    backend: String,
    slots: u64,
    chi_square: HashMap<&'static str, f64>,
    kolmogorov_smirnov: HashMap<&'static str, f64>,
    addresses: HashMap<String, AddressStats>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proposer_fairness_under_proving_backpressure() -> Result<()> {
    let _ = tracing_subscriber::fmt::try_init();

    for backend in enabled_backends() {
        let run = timeout(TEST_TIMEOUT, run_backend_trial(backend)).await;
        match run {
            Ok(result) => result?,
            Err(_) => {
                return Err(anyhow!(
                    "proposer fairness trial for {} timed out",
                    backend.label()
                ))
            }
        }
    }

    Ok(())
}

fn enabled_backends() -> Vec<BackendKind> {
    let mut backends = vec![BackendKind::Stwo];
    #[cfg(feature = "backend-rpp-stark")]
    {
        backends.push(BackendKind::RppStark);
    }
    backends
}

async fn run_backend_trial(backend: BackendKind) -> Result<()> {
    let mut cluster = match TestCluster::start_with(4, |config, _| {
        config.block_time_ms = 250;
        config.mempool_limit = 512;
        config.rollout.feature_gates.recursive_proofs = true;
        config.rollout.feature_gates.reconstruction = true;
        config.rollout.feature_gates.malachite_consensus = true;
        config.rollout.feature_gates.consensus_enforcement = true;
        Ok(())
    })
    .await
    {
        Ok(cluster) => cluster,
        Err(err) => {
            eprintln!(
                "skipping proposer fairness trial for {}: {err:?}",
                backend.label()
            );
            return Ok(());
        }
    };

    let result = async {
        cluster
            .wait_for_full_mesh(NETWORK_TIMEOUT)
            .await
            .context("cluster mesh")?;

        let primary = &cluster.nodes()[0];
        wait_for_height(primary, SAMPLE_SLOTS).await?;

        let blocks = collect_blocks(primary, SAMPLE_SLOTS as usize)
            .await
            .context("collect blocks for fairness sampling")?;
        let validators = cluster.nodes();
        let stakes = stake_weights(cluster.genesis_accounts());

        let mut expected_counts = HashMap::new();
        let total_stake: f64 = stakes.values().sum();
        for (address, stake) in &stakes {
            expected_counts.insert(
                address.clone(),
                (*stake as f64 / total_stake) * SAMPLE_SLOTS as f64,
            );
        }

        let mut selected_counts: HashMap<String, u64> = HashMap::new();
        let mut produced_counts: HashMap<String, u64> = HashMap::new();

        for block in &blocks {
            let mut round = rebuild_round(primary, block, validators)
                .with_context(|| format!("rebuild round for height {}", block.header.height))?;
            let selection = round.select_proposer().ok_or_else(|| {
                anyhow!(
                    "missing proposer selection for height {}",
                    block.header.height
                )
            })?;

            *selected_counts
                .entry(selection.proposer.clone())
                .or_default() += 1;
            *produced_counts
                .entry(block.header.proposer.clone())
                .or_default() += 1;
        }

        let stats = compute_stats(
            backend,
            &stakes,
            &expected_counts,
            &selected_counts,
            &produced_counts,
        );

        persist_artifacts(backend, &stats)?;
        Ok(())
    }
    .await;

    cluster.shutdown().await.context("cluster shutdown")?;
    result
}

fn compute_stats(
    backend: BackendKind,
    stakes: &HashMap<String, u128>,
    expected: &HashMap<String, f64>,
    selected: &HashMap<String, u64>,
    produced: &HashMap<String, u64>,
) -> DistributionStats {
    let slots = SAMPLE_SLOTS;
    let mut chi_square = HashMap::new();
    chi_square.insert(
        "selected",
        chi_square_statistic(expected, selected, slots as f64),
    );
    chi_square.insert(
        "produced",
        chi_square_statistic(expected, produced, slots as f64),
    );

    let mut ks = HashMap::new();
    ks.insert(
        "selected",
        kolmogorov_smirnov(expected, selected, slots as f64),
    );
    ks.insert(
        "produced",
        kolmogorov_smirnov(expected, produced, slots as f64),
    );

    let mut addresses = HashMap::new();
    for (address, stake) in stakes {
        let expected_count = *expected.get(address).unwrap_or(&0.0);
        let selected_count = *selected.get(address).unwrap_or(&0);
        let produced_count = *produced.get(address).unwrap_or(&0);
        addresses.insert(
            address.clone(),
            AddressStats {
                stake: stake.to_string(),
                expected: expected_count,
                selected: selected_count,
                produced: produced_count,
            },
        );
    }

    DistributionStats {
        backend: backend.label().to_string(),
        slots,
        chi_square,
        kolmogorov_smirnov: ks,
        addresses,
    }
}

fn chi_square_statistic(
    expected: &HashMap<String, f64>,
    observed: &HashMap<String, u64>,
    total: f64,
) -> f64 {
    let mut statistic = 0.0;
    for (address, expected_count) in expected {
        if *expected_count == 0.0 {
            continue;
        }
        let observed_count = *observed.get(address).unwrap_or(&0) as f64;
        let diff = observed_count - expected_count;
        statistic += (diff * diff) / expected_count.max(1e-9);
    }

    // Count any unexpected proposers that were not in the genesis map.
    for (address, observed_count) in observed {
        if expected.contains_key(address) {
            continue;
        }
        let expected_count = total / expected.len().max(1) as f64;
        let diff = *observed_count as f64 - expected_count;
        statistic += (diff * diff) / expected_count.max(1e-9);
    }

    statistic
}

fn kolmogorov_smirnov(
    expected: &HashMap<String, f64>,
    observed: &HashMap<String, u64>,
    total: f64,
) -> f64 {
    let mut entries: Vec<_> = expected
        .iter()
        .map(|(address, expected)| (address.clone(), *expected))
        .collect();

    entries.sort_by(|lhs, rhs| {
        rhs.1
            .partial_cmp(&lhs.1)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut cumulative_expected = 0.0;
    let mut cumulative_observed = 0.0;
    let mut max_diff = 0.0;

    for (address, expected_count) in entries {
        cumulative_expected += expected_count / total;
        let observed_count = *observed.get(&address).unwrap_or(&0) as f64;
        cumulative_observed += observed_count / total;
        max_diff = max_diff.max((cumulative_observed - cumulative_expected).abs());
    }

    max_diff
}

fn persist_artifacts(backend: BackendKind, stats: &DistributionStats) -> Result<()> {
    let artifact_dir = PathBuf::from("tests/artifacts");
    create_dir_all(&artifact_dir).context("create artifact directory")?;

    let json_path = artifact_dir.join(format!("proposer_fairness_{}.json", backend.label()));
    let mut file = File::create(&json_path)
        .with_context(|| format!("create proposer fairness report at {}", json_path.display()))?;
    serde_json::to_writer_pretty(&mut file, stats).context("serialize fairness report")?;
    file.flush().context("flush fairness report")?;

    let histogram_path = artifact_dir.join(format!(
        "proposer_fairness_histogram_{}.txt",
        backend.label()
    ));
    let mut histogram = File::create(&histogram_path).with_context(|| {
        format!(
            "create proposer fairness histogram at {}",
            histogram_path.display()
        )
    })?;
    writeln!(histogram, "backend: {}", backend.label())?;
    writeln!(histogram, "slots: {}", stats.slots)?;
    writeln!(histogram, "address,stake,expected,selected,produced")?;
    for (address, entry) in stats.addresses.iter() {
        writeln!(
            histogram,
            "{address},{},{:.2},{},{}",
            entry.stake, entry.expected, entry.selected, entry.produced
        )?;
    }
    histogram.flush().context("flush proposer histogram")?;

    Ok(())
}

fn stake_weights(genesis: &[rpp_chain::config::GenesisAccount]) -> HashMap<String, u128> {
    let mut stakes = HashMap::new();
    for account in genesis {
        if let Ok(value) = account.stake.parse::<u128>() {
            stakes.insert(account.address.clone(), value);
        }
    }
    stakes
}

async fn wait_for_height(node: &support::cluster::TestClusterNode, target: u64) -> Result<()> {
    let mut attempts = 0usize;
    loop {
        if attempts >= 400 {
            return Err(anyhow!("timed out waiting for target height"));
        }
        if let Some(block) = node
            .node_handle
            .latest_block()
            .context("poll latest block for height")?
        {
            if block.header.height >= target {
                return Ok(());
            }
        }
        attempts += 1;
        tokio::time::sleep(BLOCK_POLL_INTERVAL).await;
    }
}

async fn collect_blocks(
    node: &support::cluster::TestClusterNode,
    count: usize,
) -> Result<Vec<Block>> {
    let tip = node
        .node_handle
        .latest_block()
        .context("fetch tip block")?
        .ok_or_else(|| anyhow!("validator tip missing"))?;
    let start_height = tip
        .header
        .height
        .saturating_sub((count as u64).saturating_sub(1));
    let mut blocks = Vec::new();
    for height in start_height..=tip.header.height {
        let block = node
            .node_handle
            .get_block(height)
            .with_context(|| format!("fetch block at height {height}"))?
            .ok_or_else(|| anyhow!("missing block at height {height}"))?;
        blocks.push(block);
    }
    Ok(blocks)
}

fn rebuild_round<'a>(
    node: &support::cluster::TestClusterNode,
    block: &Block,
    participants: &'a [support::cluster::TestClusterNode],
) -> Result<ConsensusRound<'a>> {
    consensus_round_for_block(node, block, participants)
}
