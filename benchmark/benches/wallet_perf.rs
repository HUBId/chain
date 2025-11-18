use std::sync::Arc;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, Criterion};
use firewood_benchmark::wallet_perf::{
    build_wallet, simulate_coin_selection, simulate_prover_jobs, simulate_sync, FeeEstimatorSim,
    ProverSimConfig, SimMempool, WalletPerfConfig,
};
use pprof::criterion::{Output, PProfProfiler};
use std::hint::black_box;

fn bench_sync(c: &mut Criterion) {
    let config = WalletPerfConfig::default();
    let wallet = Arc::new(build_wallet(&config));
    c.bench_function("wallet_sync_full_large", |b| {
        let wallet = Arc::clone(&wallet);
        b.iter(|| black_box(simulate_sync(&wallet, config.sync_batch)));
    });
}

fn bench_coin_selection(c: &mut Criterion) {
    let config = WalletPerfConfig::default();
    let wallet = Arc::new(build_wallet(&config));
    c.bench_function("wallet_coin_selection_large", |b| {
        let wallet = Arc::clone(&wallet);
        b.iter(|| {
            simulate_coin_selection(&wallet, config.selection_amount, config.min_confirmations)
        });
    });
}

fn bench_fee_estimator(c: &mut Criterion) {
    let config = WalletPerfConfig::default();
    let estimator = FeeEstimatorSim::new(Duration::from_secs(config.fee_cache_ttl_secs));
    let mempool = SimMempool::default();
    c.bench_function("wallet_fee_estimator_refresh", |b| {
        b.iter(|| black_box(estimator.resolve(&mempool)));
    });
}

fn bench_prover(c: &mut Criterion) {
    let config = WalletPerfConfig::default();
    let prover = ProverSimConfig::from(&config);
    c.bench_function("wallet_prover_mock_job", |b| {
        b.iter(|| black_box(simulate_prover_jobs(&prover)));
    });
}

fn build_criterion() -> Criterion {
    let mut crit = Criterion::default().configure_from_args();
    if std::env::var_os("WALLET_BENCH_FLAMEGRAPH").is_some() {
        crit = crit.with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)));
    }
    crit
}

criterion_group!(
    name = wallet_perf;
    config = build_criterion();
    targets = bench_sync, bench_coin_selection, bench_fee_estimator, bench_prover
);
criterion_main!(wallet_perf);
