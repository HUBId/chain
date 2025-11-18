# Wallet performance benchmarks

This document summarizes the large-wallet benchmarks that live under the `firewood-benchmark` crate.
They simulate common wallet operations (syncing many addresses and UTXOs, coin selection, fee
estimation, and prover workloads) so we can track throughput, add profiling hooks, and document
baseline expectations.

## Benchmark harness overview

* Simulation logic lives in `benchmark/src/wallet_perf.rs`. It builds deterministic large wallets,
  iterates over every address/UTXO during sync, models batched coin selection, memoizes fee
  estimates, and runs multi-threaded prover jobs with deterministic hashing. The default config uses
  4,096 addresses, six UTXOs each, coin selection targets of 2.5M sats, and a four-way prover with
  256 KiB witnesses. 【F:benchmark/src/wallet_perf.rs†L9-L299】
* Criterion harnesses sit in `benchmark/benches/wallet_perf.rs`. The four benches share a
  pre-generated wallet (where applicable), and the helper respects the `WALLET_BENCH_FLAMEGRAPH`
  environment variable to attach the `pprof` profiler. 【F:benchmark/benches/wallet_perf.rs†L1-L62】
* The crate enables a standalone bench target (`[[bench]] name = "wallet_perf"`) so `cargo bench`
  runs Criterion directly (`harness = false`). We pin Criterion to 0.5.1 to align with the profiler
  dependency. 【F:benchmark/Cargo.toml†L19-L75】

## Running the benches

The benches pull in most of the workspace, so the first build can take several minutes. Afterwards
runs are quick:

```bash
CARGO_CRITERION_DISABLE_PLOTTING=1 cargo bench -p firewood-benchmark --bench wallet_perf
```

* `--bench wallet_perf` selects the Criterion harness without forwarding stray filter arguments to
  the bench binary (which uses its own CLI).
* `CARGO_CRITERION_DISABLE_PLOTTING=1` suppresses gnuplot generation so the run works on bare
  builders.
* Results are stored under `target/criterion/<bench_name>` alongside the standard Criterion report
  SVGs and CSVs.

## Profiling and flamegraphs

To capture per-benchmark flamegraphs, keep the environment variable above and add
`WALLET_BENCH_FLAMEGRAPH=1` plus a profile window:

```bash
WALLET_BENCH_FLAMEGRAPH=1 CARGO_CRITERION_DISABLE_PLOTTING=1 \
  cargo bench -p firewood-benchmark --bench wallet_perf -- --profile-time 5
```

* Criterion will run each benchmark for an additional 5s under the `pprof` profiler.
* Flamegraphs land at `target/criterion/<bench_name>/profile/flamegraph.svg`. For example,
  `target/criterion/wallet_sync_full_large/profile/flamegraph.svg` is emitted after the run above.
* You can shorten the profiling pass by adding `--sample-size N` or `--measurement-time T` after the
  `--` separator.

## Baseline metrics (Default config)

| Benchmark | Description | Latest run (99% CI) |
| --- | --- | --- |
| `wallet_sync_full_large` | Scans 4,096 addresses (24.5k UTXOs) in batches of 64 with hashing and tracing spans. | 6.32–6.54 ms per full sync ⇒ ~640k addrs/sec and ~3.8M UTXOs/sec. 【597d49†L1-L4】 |
| `wallet_coin_selection_large` | Greedy selection over ~24k candidates targeting a 2.5M sat spend with min 2 confirmations. | 1.71–1.75 ms per selection. 【d33a3f†L1-L4】 |
| `wallet_fee_estimator_refresh` | Median fee calculation with cache invalidation and utilization-based adjustments. | 75.6–78.8 ns per refresh. 【85ee38†L1-L5】 |
| `wallet_prover_mock_job` | Four concurrent witness threads, 256 KiB buffers, four hashing rounds. | 22.6–24.6 ms per prover batch (~44 ms of total CPU at 4 jobs). 【ce488e†L1-L1】 |

Notes:

* Criterion flagged mild/high outliers on the sync and coin-selection benches because their inner
  loops are large; treat ±5% jitter as normal when comparing runs.
* The prover bench launches OS threads, so the median depends on CPU pinning; run on a quiet host to
  avoid interference.

## Regression guidance

1. **Record the command and git SHA** whenever you collect new numbers. That keeps the regression
   reports actionable.
2. **Compare the medians and deviations** from `target/criterion/*/report/index.html` when a change
   touches wallet code. A >10% swing on sync or coin selection is large enough to warrant a bisect.
3. **Inspect flamegraphs** (see above) when tracing indicates new hotspots. Look for unexpected
   allocations in `wallet.perf.sync_batch` spans or imbalanced workloads between prover threads.
4. **Document environmental changes** (CPU count, `CARGO_CRITERION_DISABLE_PLOTTING`, profiler window)
   to avoid false alarms.

## Tuning knobs and hardware assumptions

* `WalletPerfConfig` exposes everything needed to stress larger wallets: addresses, UTXOs/address,
  sync batch size, selection target, minimum confirmations, fee cache TTL, and prover job size.
  Update the config before constructing wallets to explore the blast radius of pending UTXOs or
  deeper confirmation requirements. 【F:benchmark/src/wallet_perf.rs†L9-L33】
* The prover simulator derives its settings from the config (jobs, iterations, witness size) so you
  can emulate bigger circuits by bumping `prover_iterations` or `prover_witness_bytes` without
  touching the bench harness. 【F:benchmark/src/wallet_perf.rs†L254-L300】
* CPU: the default prover bench assumes at least four cores. When profiling on smaller machines,
  lower `prover_jobs` or run with `taskset` to reduce noise.
* Memory: a full wallet build with the default config allocates ~25k UTXOs in RAM, well under 1 GiB.
  Increasing `addresses` × `utxos_per_address` scales linearly; adjust according to the host.

These harnesses and documents should make it easy to spot regressions, share reproducible benchmark
commands, and drill into profiles when a wallet change slows things down.
