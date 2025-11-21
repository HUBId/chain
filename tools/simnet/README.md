# Simnet orchestrator

The `simnet` binary orchestrates RPP network simulations defined in RON scenario
files under `tools/simnet/scenarios/`. Use the `cargo xtask simnet` wrapper to
run the common presets locally and to mirror the scenarios exercised by CI.

## CLI presets

```
cargo xtask simnet --scenario <name|path> [--artifacts-dir <path>] [--keep-alive]
```

### Available scenarios

| Name | Scenario file | Description |
| --- | --- | --- |
| `block-pipeline` | `tools/simnet/scenarios/ci_block_pipeline.ron` | Exercises the CI block pipeline harness. |
| `state-sync-guard` | `tools/simnet/scenarios/ci_state_sync_guard.ron` | Validates guard rails around state sync. |
| `quorum-stress` | `tools/simnet/scenarios/consensus_quorum_stress.ron` | Drives the consensus quorum stress drill. |
| `partition` | `tools/simnet/scenarios/snapshot_partition.ron` | Partitions validators while testing snapshot recovery. |
| `partitioned-flood` | `tools/simnet/scenarios/partitioned_flood.ron` | Runs the partitioned flood drill using gossip templates. |
| `small-world` | `tools/simnet/scenarios/small_world_smoke.ron` | Executes the in-process small world smoke harness. |
| `reorg-stark` | `tools/simnet/scenarios/consensus_reorg_stark.ron` | Exercises the STARK backend reorg scenario. |

Pass a custom path to execute ad-hoc scenarios:

```
cargo xtask simnet --scenario tools/simnet/scenarios/ring_latency_profile.ron
```

Use `--artifacts-dir` to control where logs and outputs are written and
`--keep-alive` to leave the harness processes up for inspection.

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
- Consensus section: defaults are `runs = 64`, `validators = 64`,
  `witness_commitments = 192`, and tamper `every_n = 8`. All consensus counts
  must be greater than zero.

## CI and nightly parity

The `cargo xtask test-simnet` entry point used in CI and nightly workflows calls
the same wrapper to run the canonical suite of scenarios. When adding new
presets, update the table above so local runs and automation stay aligned.
