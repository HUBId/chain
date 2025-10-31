# Simnet Harness

The simnet harness orchestrates nodes, wallets, and P2P simulations from a
single RON scenario file. It lives under [`tools/simnet`](../../tools/simnet)
and reuses the existing [`rpp-sim`](../../rpp/sim) harness for P2P topologies.

## Running a scenario

```bash
cargo run -p simnet -- --scenario tools/simnet/scenarios/small_world_smoke.ron \
  --artifacts-dir target/simnet/small-world-smoke
```

Each scenario defines the processes that should be spawned, the environment to
inject, and the P2P test to execute. Logs are collected under the chosen
artifacts directory in `logs/`, and the P2P summary is stored as JSON in the
`summaries/` subdirectory.

Scenario files use a JSON subset stored with the `.ron` extension for
consistency with the existing simulation assets. They support the following
keys:

- `name`: Human readable identifier, also used for default artifact paths.
- `env`: Optional key-value map applied to every spawned process.
- `nodes` / `wallets`: Lists of process descriptors (command, args, environment,
  optional working directory, and an optional log pattern that marks the process
  as ready).
- `p2p`: Optional configuration pointing at an existing TOML scenario from
  `rpp/sim`. The runner keeps the orchestrated processes alive while the harness
  executes and writes the resulting summary to disk.

## Analyzing results

`scripts/analyze_simnet.py` consumes one or more summary JSON files and prints a
compact report with propagation percentiles and, when available, multiprocess
comparisons:

```bash
python3 scripts/analyze_simnet.py target/simnet/small-world-smoke/summaries/small_world_smoke.json
```

The script exits non-zero if any propagation p95 exceeds the configured
threshold (default: 500 ms), allowing CI jobs to flag regressions automatically.

## Continuous integration

`.github/workflows/nightly.yml` runs both bundled scenarios every night. Each
matrix entry calls the simnet tool, analyzes the resulting metrics, and uploads
the artifacts. The workflow can also be triggered manually via the
`workflow_dispatch` hook.
