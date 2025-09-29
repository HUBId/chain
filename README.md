# DVN Digital Value Network

A experimental implementation of an blockchain with fixed size (RPP Recursive Pruning Proof) and reputation system (ZSI Zero-Knowledge Sovereign Identity)

It integrates:

- **Stwo** for Blake2-based hashing and Merkle root construction.
- **Malachite** for high precision arithmetic in stake-weighted consensus.
- **Firewood** as the append-only storage stack with integrated WAL, Merkle commitments, and pruning proofs.

## Features

- Deterministic stake-weighted proposer selection backed by Malachite `Natural` arithmetic plus Poseidon-based VRF proofs for validator fairness.
- Firewood-backed storage with append-only WAL, column families, and pruning proofs for blocks, accounts, and metadata.
- Ed25519 transaction signing and verification with Stwo hashing for all payload commitments.
- HTTP/JSON API powered by Axum for transaction submission and state inspection.
- Configurable block cadence, mempool sizing, and genesis allocation via TOML configuration.
- Iterative rollout controls with feature gates and telemetry sampling for staged deployments.

## Build Requirements

This workspace is pinned to `nightly-2024-06-20` via `rust-toolchain.toml`. Install the matching toolchain along with the bundled `rustfmt` and `clippy` components before building locally to ensure consistent formatting and lint coverage.

## Getting Started

### Prerequisites

Ensure Rust (1.79+) is installed. Firewood sources (KV engine, WAL, pruner) are built automatically by Cargo during the first compile.

### Build & Test

Use the helper scripts to keep build and test invocations consistent across
the workspace.

```bash
# Build the default debug artifacts
scripts/build.sh

# Build in release mode
scripts/build.sh --release

# Build the minimal feature surface (disables default features)
scripts/build.sh --feature-set minimal
```

Run targeted test suites via `scripts/test.sh` – it enforces `-D warnings` and
supports backend-specific feature matrices.

```bash
# Run unit and integration tests (default behaviour)
scripts/test.sh

# Run only the integration tests using the Plonky3 backend
scripts/test.sh --integration --backend plonky3

# Execute documentation tests with the release profile
scripts/test.sh --doc --release
```

### Simulation smoke tests

The libp2p simulation harness lives in `rpp/sim`. Its deterministic smoke test
is ignored by default and exercised in CI via `cargo test -p rpp-sim -- --ignored`.

* Set `RPP_SIM_STATIC_KEY_SEED` to reuse deterministic libp2p identities for
  every node. CI uses `ci-smoke` while the nightly workflow uses
  `nightly-smoke`.
* `RPP_SIM_REQUIRE_DETERMINISTIC=0` skips the strict summary equality check
  (use `1` locally when investigating reproducibility regressions).

#### Adjusting propagation corridors

Propagation time corridors are asserted in
`rpp/sim/tests/sim_smoke.rs`. To tune them:

1. Run the simulation locally, e.g.
   `RPP_SIM_STATIC_KEY_SEED=local cargo test -p rpp-sim -- --ignored --nocapture`.
2. Inspect the generated `target/sim-smoke/summary.json` (or the nightly output
   under `target/sim-smoke/nightly-summary.json`) to collect the observed
   percentile values.
3. Update the `p50_ms`/`p95_ms` corridors in the assertion to match the new
   bounds and commit the changes alongside an explanation of the shift.

### Generate configuration and keys

```bash
# Create default configuration templates
cargo run -- generate-config --path config/node.toml
cargo run -- generate-wallet-config --path config/wallet.toml

# Generate new Ed25519 + VRF keypairs for the node
cargo run -- keygen --path keys/node.toml --vrf-path keys/vrf.toml
```

### Run storage migrations

```bash
# Preview the changes without writing to disk
cargo run -- migrate --config config/node.toml --dry-run

# Apply the migrations and write the upgraded schema
cargo run -- migrate --config config/node.toml
```

### Launch the node

```bash
cargo run -- start --mode node --node-config config/node.toml
```

The node opens a Firewood store under the configured `data_dir` (creating `db`, `wal`, and pruning checkpoints), starts block production, and exposes an HTTP API (default `127.0.0.1:7070`).
Firewood automatically prunes historical state once checkpoints are verified, keeping the working set lean while preserving proofs.

### Modern quickstart workflows

**Use curated runtime profiles**

```bash
# Launch a node using the bundled profile (resolves config paths automatically)
cargo run -- start --profile node

# Spawn a validator-oriented runtime (node + wallet + validator daemons)
cargo run -- start --profile validator
```

**Select proof backends**

```bash
# Run with the default STWO backend
cargo run -- start --mode node --node-config config/node.toml

# Switch to the experimental Plonky3 backend
cargo run --no-default-features --features backend-plonky3 -- start --mode node --node-config config/node.toml
```

**Toggle rollout feature gates**

```toml
# config/node.toml
[rollout.feature_gates]
pruning = true
recursive_proofs = true
reconstruction = true
consensus_enforcement = true
```

After adjusting gates, restart the node and inspect `GET /status/rollout` to confirm the active feature set.

## HTTP API

- `GET /health` – Node status and identity address.
- `GET /blocks/latest` – Returns the most recent sealed block.
- `GET /blocks/{height}` – Fetch a specific block by height.
- `GET /accounts/{address}` – Inspect account balance, nonce, and stake.
- `POST /transactions` – Submit a signed transaction (JSON body matching `SignedTransaction`).
- `GET /status/node` – Runtime snapshot with mempool occupancy and the latest VRF selection metrics.

## Configuration Highlights

`config/node.toml` includes:

- `data_dir`: persistent storage directory (Firewood stores KV pages in `data_dir/db` plus `data_dir/wal`).
- `key_path`: location of the node's Ed25519 keypair file.
- `p2p_key_path`: persistent libp2p Ed25519 identity used for Noise handshakes.
- `vrf_key_path`: path to the node's Poseidon VRF keypair (auto-created on first launch).
- `snapshot_dir`: directory where reconstructed state snapshots are materialized.
- `proof_cache_dir`: location for cached recursive/STARK proof blobs.
- `rpc_listen`: HTTP API address.
- `block_time_ms`: block production interval in milliseconds.
- `max_block_transactions` / `mempool_limit`: throughput tuning knobs.
- `epoch_length` / `target_validator_count`: consensus epoch duration and desired validator set size driving VRF thresholds.
- `max_proof_size_bytes`: upper bound accepted for proof artifacts during deployment.
- `rollout.release_channel`: deployment channel (`development`, `testnet`, `canary`, `mainnet`) reflected in node status.
- `rollout.feature_gates`: toggles for pruning, recursive proofs, reconstruction, and consensus enforcement.
- `rollout.telemetry`: enable periodic telemetry snapshots and configure the sampling cadence.
- `genesis.accounts`: initial allocations with balances and stakes.

### Rollout & Telemetry

- `GET /status/rollout` – Inspect the current rollout channel, enabled feature gates, and telemetry runtime state.
- When telemetry is enabled, the node periodically emits JSON snapshots with node, consensus, mempool, and VRF selection metrics to the log (and tags the configured endpoint for external scrapers).

## Development Notes

- Run `cargo run -- migrate` when deploying a new binary against an existing data directory to ensure the Firewood schema is upgraded in-place.
- Firewood compilation (KV core, pruning engine) happens on the first build; subsequent builds reuse the generated artifacts.
- Run `cargo fmt` to keep formatting consistent.
- Consensus selection logic lives in `rpp/consensus/src/lib.rs`, while ledger state management sits in `rpp/storage/ledger.rs`.

Enjoy experimenting with the Digital Value Network!
