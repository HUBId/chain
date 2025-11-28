# Simnet orchestrator

The `simnet` binary orchestrates RPP network simulations defined in RON scenario
files under `tools/simnet/scenarios/`. Use the `cargo xtask simnet` wrapper to
run the common presets locally and to mirror the scenarios exercised by CI.

## CLI presets

```
cargo xtask simnet --profile <name> [--artifacts-dir <path>] [--keep-alive] [--seed <u64>] [--allow-insufficient-resources]
cargo xtask simnet --scenario <path> [--artifacts-dir <path>] [--keep-alive] [--seed <u64>] [--allow-insufficient-resources]
```

Use `--profile` to load the canned simnet parameter sets that CI exercises; fall
back to `--scenario` for ad-hoc RON files.

### Available profiles

| Name | Scenario file | Description | Resource guidance (CPU / RAM) |
| --- | --- | --- | --- |
| `block-pipeline` | `tools/simnet/scenarios/ci_block_pipeline.ron` | Exercises the CI block pipeline harness. | `4` cores / `8 GiB` |
| `state-sync-guard` | `tools/simnet/scenarios/ci_state_sync_guard.ron` | Validates guard rails around state sync. | `8` cores / `16 GiB` |
| `quorum-stress` | `tools/simnet/scenarios/consensus_quorum_stress.ron` | Drives the consensus quorum stress drill. | `16` cores / `32 GiB` |
| `partition` | `tools/simnet/scenarios/snapshot_partition.ron` | Partitions validators while testing snapshot recovery. | `8` cores / `16 GiB` |
| `flood` (also `partitioned-flood`) | `tools/simnet/scenarios/partitioned_flood.ron` | Runs the partitioned flood drill using gossip templates. | `6` cores / `12 GiB` |
| `small-world` | `tools/simnet/scenarios/small_world_smoke.ron` | Executes the in-process small world smoke harness. | `4` cores / `8 GiB` |
| `canary-rolling` | `tools/simnet/scenarios/canary_rolling_restart.ron` | Simulates a canary rolling restart with zk proving/verification and wallet tracker coverage. | `12` cores / `24 GiB` |
| `reorg-stark` | `tools/simnet/scenarios/consensus_reorg_stark.ron` | Exercises the STARK backend reorg scenario. | `12` cores / `24 GiB` |
| `reorg-rpp-stark` | `tools/simnet/scenarios/consensus_reorg_rpp_stark.ron` | Exercises RPP-STARK fork-choice validation and recovery. | `12` cores / `24 GiB` |
| `epoch-drift` | `tools/simnet/scenarios/consensus_epoch_drift.ron` | Injects skewed latency and slow peers to fuzz epoch transitions and fork-choice stability. | `10` cores / `20 GiB` |
| `validator-set-rotation` | `tools/simnet/scenarios/validator_set_rotation.ron` | Restarts and rotates validators while checking timetoke alignment and finality continuity. | `12` cores / `24 GiB` |
| `uptime-soak` | `tools/simnet/scenarios/uptime_soak.ron` | Multi-hour soak with induced pauses to track uptime/finality health. | `12` cores / `24 GiB` |
| `wallet-rpc-failover` | `tools/simnet/scenarios/wallet_rpc_failover.ron` | Routes wallet RPC traffic through regional nodes while forcing prover/verifier failover and tracking uptime/latency. | `12` cores / `24 GiB` |

Pass a custom path to execute ad-hoc scenarios:

```
cargo xtask simnet --scenario tools/simnet/scenarios/ring_latency_profile.ron
```

Use `--artifacts-dir` to control where logs and outputs are written and
`--keep-alive` to leave the harness processes up for inspection. The
`--seed` flag (or `SIMNET_SEED` environment variable) overrides the RNG seed
used by both the p2p harness and the consensus load generator. CI defaults to
`0x53494d4e4554` when no seed is provided so runs remain reproducible; set
`SIMNET_SEED` to a different value locally when fuzzing is desired.

### Resource checks

Each scenario can advertise recommended CPU and memory needs through the
`resources` block in the RON file. Simnet logs the detected host totals and
refuses to start when the machine has fewer cores or less RAM than requested.
Pass `--allow-insufficient-resources` to bypass the guard rail when a
best-effort run is acceptable; a warning is emitted when the override is used.

## Scenario configuration

Simnet scenarios are RON files that point at p2p traffic profiles or
consensus load settings. The orchestrator enforces the following defaults and
validations before starting any processes:

- Global parameters: `duration_secs` defaults to `0`, and `artifacts_dir`
  defaults to `target/simnet/<scenario-slug>` when not provided.
- Process entries (`nodes`/`wallets`): `startup_timeout_ms` defaults to
  `30000` and must be positive. Relative `working_dir` values are resolved from
  the scenario file location, and labels must be non-empty.
- P2p section: `scenario_path` points to a TOML simulation profile consumed by
  `rpp-sim`. Simnet validates the profile up front, rejecting zero-peer
  topologies, degree values greater than or equal to the node count, and link
  loss rates outside the `0.0..=1.0` range.
- Traffic payloads: `[traffic.tx.payload]` exposes `min_bytes`/`max_bytes`
  bounds for gossip messages. The partitioned flood drills now pin the range in
  the TOML profiles so CI can alternate between small (KiB-scale) and large
  (tens-of-KiB) payload pressure without editing the RON wrapper.
- Latency profiles: add an optional `[latency_profile]` table to p2p TOML
  profiles to inject extra per-peer-class delay/jitter. Configure one or both
  of the `trusted`/`untrusted` entries (each supports `extra_delay_ms` and
  `jitter_ms`), and optionally a dedicated `seed`. When no seed is provided the
  profile inherits the simulation seed, so CI runs use the deterministic
  `SIMNET_SEED` default without extra wiring.
- Consensus section: defaults are `runs = 64`, `validators = 64`,
  `witness_commitments = 192`, and tamper `every_n = 8`. All consensus counts
  must be greater than zero.

Example latency profile snippet:

```
[latency_profile]
trusted = { extra_delay_ms = 6, jitter_ms = 3 }
untrusted = { extra_delay_ms = 32, jitter_ms = 12 }
```

## CI and nightly parity

The `cargo xtask test-simnet` entry point used in CI and nightly workflows calls
the same wrapper to run the canonical suite of profiles. When adding new
presets, update the table above so local runs and automation stay aligned.

### CI artifact layout and failure captures

Nightly and weekly CI jobs publish artefacts under `artifacts/simnet/<label>`
where `<label>` mirrors the feature/backend matrix (for example,
`prod-prover-stwo-backend-plonky3` or
`uptime-soak-prod-prover-stwo-backend-plonky3`). The archive inside the
directory keeps the same suffix, so extracting a single label is as simple as:

```
gh run download <run-id> --name simnet-prod-prover-stwo-backend-plonky3
tar -xzf artifacts/simnet/prod-prover-stwo-backend-plonky3/simnet-prod-prover-stwo-backend-plonky3.tar.gz
```

When a simnet job fails, CI now runs `scripts/ci/collect_test_artifacts.sh` and
uploads the redacted logs/metrics alongside the main archive. The failure
bundle mirrors the simnet target layout and captures consensus load traces,
prover/verifier logs, and timetoke telemetry (`telemetry/timetoke*.jsonl`) so
engineers can debug consensus/proving regressions without rerunning the
scenario locally.

## Inspecting per-peer traffic metrics

Simnet now records the total bytes in/out for every simulated peer, along with
its derived peer class (trusted/untrusted). Each harness run emits a `peer
traffic totals` log line per peer and persists the structured values in the
JSON summaries written under `target/simnet/<scenario>/summaries/*.json`.

- Use the analyzer helper to print the heaviest peers and enforce limits in the
  partition/flood drills:

  ```
  python3 scripts/analyze_simnet.py target/simnet/partitioned-flood/summaries/partitioned_flood.json \
    --peer-bytes-multiplier 4 --min-peer-bytes 1024
  ```

- Export the raw per-peer table for dashboards or spreadsheets with `jq`:

  ```
  jq -r '.peer_traffic[] | [.peer_id, .peer_class, .bytes_in, .bytes_out] | @csv' \
    target/simnet/partitioned-flood/summaries/partitioned_flood.json > peer_traffic.csv
  ```

The CI jobs bundle the `summaries/` directory (including the peer traffic block)
in their artifacts, so the same commands work on downloaded runs without
rerunning the scenarios locally.
