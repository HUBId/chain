# DVN Digital Value Network

A experimental implementation of an blockchain with fixed size (RPP Recursive Pruning Proof) and reputation system (ZSI Zero-Knowledge Sovereign Identity)

It integrates:

- **Stwo** for Blake2-based hashing and Merkle root construction.
- **Malachite** for high precision arithmetic in stake-weighted consensus.
- **RocksDB** as the persistent storage engine for blocks, accounts, and chain metadata.

## Features

- Deterministic stake-weighted proposer selection backed by Malachite `Natural` arithmetic plus Poseidon-based VRF proofs for validator fairness.
- RocksDB-backed storage with column families for blocks, accounts, and metadata.
- Ed25519 transaction signing and verification with Stwo hashing for all payload commitments.
- HTTP/JSON API powered by Axum for transaction submission and state inspection.
- Configurable block cadence, mempool sizing, and genesis allocation via TOML configuration.
- Iterative rollout controls with feature gates and telemetry sampling for staged deployments.

## Getting Started

### Prerequisites

Ensure Rust (1.79+) is installed. All external dependencies (RocksDB sources, etc.) are fetched and built by Cargo automatically.

### Build & Test

```bash
cargo test
```

### Generate configuration and keys

```bash
# Create a default configuration file
cargo run -- generate-config --path config/node.toml

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
cargo run -- start --config config/node.toml
```

The node will open a RocksDB instance under the configured `data_dir`, start block production, and expose an HTTP API (default `127.0.0.1:7070`).

## HTTP API

- `GET /health` – Node status and identity address.
- `GET /blocks/latest` – Returns the most recent sealed block.
- `GET /blocks/{height}` – Fetch a specific block by height.
- `GET /accounts/{address}` – Inspect account balance, nonce, and stake.
- `POST /transactions` – Submit a signed transaction (JSON body matching `SignedTransaction`).
- `GET /status/node` – Runtime snapshot with mempool occupancy and the latest VRF selection metrics.

## Configuration Highlights

`config/node.toml` includes:

- `data_dir`: persistent storage directory (RocksDB is stored in `data_dir/db`).
- `key_path`: location of the node's Ed25519 keypair file.
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

- Run `cargo run -- migrate` when deploying a new binary against an existing data directory to ensure the RocksDB schema is upgraded in-place.

- Run `cargo fmt` to keep formatting consistent.
- The RocksDB build may take a few minutes the first time. Subsequent builds reuse the compiled artifacts.
- Consensus selection and Merkle commitments are unit test friendly and live in `src/consensus.rs` and `src/ledger.rs` respectively.

Enjoy experimenting with the Digital Value Network!
