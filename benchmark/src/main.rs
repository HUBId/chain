// Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE.md for licensing terms.
//

#![expect(
    clippy::arithmetic_side_effects,
    reason = "Found 2 occurrences after enabling the lint."
)]
#![expect(
    clippy::match_same_arms,
    reason = "Found 1 occurrences after enabling the lint."
)]
#![doc = include_str!("../README.md")]

use clap::{Parser, Subcommand, ValueEnum};
use fastrace_opentelemetry::OpenTelemetryReporter;
use firewood::logger::trace;
use log::LevelFilter;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::error::Error;
use std::fmt::Display;
use std::fs;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use firewood::db::{BatchOp, Db, DbConfig};
use firewood::manager::{CacheReadStrategy, RevisionManagerConfig};
use firewood_storage::noop_storage_metrics;

use fastrace::collector::Config;

use opentelemetry::InstrumentationScope;
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::Resource;

#[derive(Parser, Debug)]
struct Args {
    #[clap(flatten)]
    global_opts: GlobalOpts,

    #[clap(subcommand)]
    test_name: TestName,
}

#[derive(clap::Args, Debug)]
struct GlobalOpts {
    #[arg(
        short = 'e',
        long,
        default_value_t = false,
        help = "Enable telemetry server reporting"
    )]
    telemetry_server: bool,
    #[arg(short, long, default_value_t = 10000)]
    batch_size: u64,
    #[arg(short, long, default_value_t = 1000)]
    number_of_batches: u64,
    #[arg(short, long, default_value_t = NonZeroUsize::new(1500000).expect("is non-zero"))]
    cache_size: NonZeroUsize,
    #[arg(short, long, default_value_t = 128)]
    revisions: usize,
    #[cfg(feature = "prometheus")]
    #[arg(
        short = 'p',
        long,
        default_value_t = 3000,
        help = "Port to listen for prometheus"
    )]
    prometheus_port: u16,
    #[cfg(feature = "prometheus")]
    #[arg(
        short = 's',
        long,
        default_value_t = false,
        help = "Dump prometheus stats on exit"
    )]
    stats_dump: bool,

    #[arg(
        long,
        short = 'l',
        required = false,
        help = "Log level. Respects RUST_LOG.",
        value_name = "LOG_LEVEL",
        num_args = 1,
        value_parser = ["trace", "debug", "info", "warn", "none"],
        default_value_t = String::from("info"),
    )]
    log_level: String,
    #[arg(
        long,
        short = 'd',
        required = false,
        help = "Use this database name instead of the default",
        default_value = PathBuf::from("benchmark_db").into_os_string(),
    )]
    dbname: PathBuf,
    #[arg(
        long,
        short = 't',
        required = false,
        help = "Terminate the test after this many minutes",
        default_value_t = 65
    )]
    duration_minutes: u64,
    #[arg(
        long,
        short = 'C',
        required = false,
        help = "Read cache strategy",
        default_value_t = ArgCacheReadStrategy::WritesOnly
    )]
    cache_read_strategy: ArgCacheReadStrategy,
}
#[derive(Debug, PartialEq, ValueEnum, Clone)]
pub enum ArgCacheReadStrategy {
    WritesOnly,
    BranchReads,
    All,
}
impl Display for ArgCacheReadStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArgCacheReadStrategy::WritesOnly => write!(f, "writes-only"),
            ArgCacheReadStrategy::BranchReads => write!(f, "branch-reads"),
            ArgCacheReadStrategy::All => write!(f, "all"),
        }
    }
}
impl From<ArgCacheReadStrategy> for CacheReadStrategy {
    fn from(arg: ArgCacheReadStrategy) -> Self {
        match arg {
            ArgCacheReadStrategy::WritesOnly => CacheReadStrategy::WritesOnly,
            ArgCacheReadStrategy::BranchReads => CacheReadStrategy::BranchReads,
            ArgCacheReadStrategy::All => CacheReadStrategy::All,
        }
    }
}

mod create;
mod single;
mod tenkrandom;
mod zipf;

#[derive(Debug, Subcommand, PartialEq)]
enum TestName {
    /// Create a database
    Create,

    /// Insert batches of random keys
    TenKRandom,

    /// Insert batches of keys following a Zipf distribution
    Zipf(zipf::Args),

    /// Repeatedly update a single row
    Single,
}

trait TestRunner {
    fn run(&self, db: &Db, args: &Args) -> Result<ScenarioSummary, Box<dyn Error>>;

    fn generate_inserts(
        start: u64,
        count: u64,
    ) -> impl Iterator<Item = BatchOp<Box<[u8]>, Box<[u8]>>> {
        (start..start + count)
            .map(|inner_key| {
                let digest: Box<[u8]> = Sha256::digest(inner_key.to_ne_bytes())[..].into();
                trace!(
                    "inserting {:?} with digest {}",
                    inner_key,
                    hex::encode(&digest),
                );
                (digest.clone(), digest)
            })
            .map(|(key, value)| BatchOp::Put { key, value })
            .collect::<Vec<_>>()
            .into_iter()
    }
}

#[global_allocator]
#[cfg(unix)]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    if args.global_opts.telemetry_server {
        let reporter = OpenTelemetryReporter::new(
            SpanExporter::builder()
                .with_tonic()
                .with_endpoint("http://127.0.0.1:4317".to_string())
                .with_protocol(opentelemetry_otlp::Protocol::Grpc)
                .with_timeout(opentelemetry_otlp::OTEL_EXPORTER_OTLP_TIMEOUT_DEFAULT)
                .build()
                .expect("initialize oltp exporter"),
            Cow::Owned(
                Resource::builder()
                    .with_service_name("avalabs.firewood.benchmark")
                    .build(),
            ),
            InstrumentationScope::builder("firewood")
                .with_version(env!("CARGO_PKG_VERSION"))
                .build(),
        );
        fastrace::set_reporter(reporter, Config::default());
    }

    assert!(
        !(args.test_name == TestName::Single && args.global_opts.batch_size > 1000),
        "Single test is not designed to handle batch sizes > 1000"
    );

    env_logger::Builder::new()
        .filter_level(match args.global_opts.log_level.as_str() {
            "debug" => LevelFilter::Debug,
            "info" => LevelFilter::Info,
            "trace" => LevelFilter::Trace,
            "none" => LevelFilter::Off,
            _ => LevelFilter::Info,
        })
        .init();

    // Manually set up prometheus
    #[cfg(feature = "prometheus")]
    let prometheus_handle = spawn_prometheus_listener(args.global_opts.prometheus_port)
        .expect("failed to spawn prometheus listener");

    let mgrcfg = RevisionManagerConfig::builder()
        .node_cache_size(args.global_opts.cache_size)
        .free_list_cache_size(
            NonZeroUsize::new(4 * args.global_opts.batch_size as usize).expect("batch size > 0"),
        )
        .cache_read_strategy(args.global_opts.cache_read_strategy.clone().into())
        .max_revisions(args.global_opts.revisions)
        .build();
    let cfg = DbConfig::builder()
        .truncate(matches!(args.test_name, TestName::Create))
        .manager(mgrcfg)
        .build();

    let db = Db::new(args.global_opts.dbname.clone(), cfg, noop_storage_metrics())
        .expect("db initiation should succeed");

    let summary = match args.test_name {
        TestName::Create => {
            let runner = create::Create;
            runner.run(&db, &args)?
        }
        TestName::TenKRandom => {
            let runner = tenkrandom::TenKRandom;
            runner.run(&db, &args)?
        }
        TestName::Zipf(_) => {
            let runner = zipf::Zipf;
            runner.run(&db, &args)?
        }
        TestName::Single => {
            let runner = single::Single;
            runner.run(&db, &args)?
        }
    };

    write_summary(&summary)?;

    #[cfg(feature = "prometheus")]
    if args.global_opts.stats_dump {
        println!("{}", prometheus_handle.render());
    }

    fastrace::flush();

    Ok(())
}

fn write_summary(summary: &ScenarioSummary) -> Result<(), Box<dyn Error>> {
    let mut output_path = PathBuf::from("target/perf-results");
    fs::create_dir_all(&output_path)?;
    output_path.push(format!("{}.json", summary.scenario));
    let writer = fs::File::create(output_path)?;
    serde_json::to_writer_pretty(writer, summary)?;
    Ok(())
}

#[derive(Debug, Serialize)]
pub(crate) struct ScenarioSummary {
    scenario: &'static str,
    started_at_unix: u64,
    total_batches: u64,
    total_operations: u64,
    total_duration_seconds: f64,
    throughput_tps: f64,
    latency_ms: LatencyPercentiles,
    latency_samples: usize,
}

#[derive(Debug, Serialize, Default)]
struct LatencyPercentiles {
    p50: f64,
    p95: f64,
    p99: f64,
}

#[derive(Debug)]
pub(crate) struct ScenarioMetrics {
    scenario: &'static str,
    batch_size: u64,
    latencies_ms: Vec<f64>,
    total_batches: u64,
    started_at: SystemTime,
}

impl ScenarioMetrics {
    fn new(scenario: &'static str, batch_size: u64) -> Self {
        Self {
            scenario,
            batch_size,
            latencies_ms: Vec::new(),
            total_batches: 0,
            started_at: SystemTime::now(),
        }
    }

    fn record_batch(&mut self, duration: Duration) {
        self.total_batches += 1;
        self.latencies_ms
            .push((duration.as_secs_f64() * 1_000.0).max(0.0));
    }

    fn finish(self, total_duration: Duration) -> ScenarioSummary {
        let total_ops = self.total_batches.saturating_mul(self.batch_size);
        let duration_secs = total_duration.as_secs_f64();
        let throughput = if duration_secs > 0.0 {
            total_ops as f64 / duration_secs
        } else {
            0.0
        };

        let mut percentiles = LatencyPercentiles::default();
        if !self.latencies_ms.is_empty() {
            let mut latencies = self.latencies_ms.clone();
            latencies.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            percentiles.p50 = percentile(&latencies, 50.0);
            percentiles.p95 = percentile(&latencies, 95.0);
            percentiles.p99 = percentile(&latencies, 99.0);
        }

        let started_at_unix = self
            .started_at
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        ScenarioSummary {
            scenario: self.scenario,
            started_at_unix,
            total_batches: self.total_batches,
            total_operations: total_ops,
            total_duration_seconds: duration_secs,
            throughput_tps: throughput,
            latency_ms: percentiles,
            latency_samples: self.latencies_ms.len(),
        }
    }
}

fn percentile(sorted_latencies: &[f64], percentile: f64) -> f64 {
    if sorted_latencies.is_empty() {
        return 0.0;
    }
    let clamped = percentile.clamp(0.0, 100.0);
    let rank = clamped / 100.0 * (sorted_latencies.len() - 1) as f64;
    let lower_index = rank.floor() as usize;
    let upper_index = rank.ceil() as usize;
    if lower_index == upper_index {
        sorted_latencies[lower_index]
    } else {
        let lower = sorted_latencies[lower_index];
        let upper = sorted_latencies[upper_index];
        let weight = rank - rank.floor();
        lower + (upper - lower) * weight
    }
}

#[cfg(feature = "prometheus")]
fn spawn_prometheus_listener(
    port: u16,
) -> Result<metrics_exporter_prometheus::PrometheusHandle, Box<dyn Error>> {
    use metrics_exporter_prometheus::PrometheusBuilder;
    use metrics_util::MetricKindMask;
    use std::net::{Ipv6Addr, SocketAddr};
    use std::time::Duration;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;

    let (recorder, exporter) = {
        // PrometheusBuilder::build requires that we be within the tokio runtime context
        // but we don't need to actually invoke the runtime until we spawn the thread
        let _guard = rt.enter();
        PrometheusBuilder::new()
            .with_http_listener(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port))
            .idle_timeout(
                MetricKindMask::COUNTER | MetricKindMask::HISTOGRAM,
                Some(Duration::from_secs(10)),
            )
            .build()?
    };

    std::thread::Builder::new()
        .name("metrics-exporter-prometheus".to_owned())
        .spawn(move || rt.block_on(exporter))?;

    let handle = recorder.handle();

    metrics::set_global_recorder(recorder)?;

    Ok(handle)
}
