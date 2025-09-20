# DVN Digital Value Network

A production-focused implementation of an blockchain with fixed size (RPP Recursive Pruning Proof) and reputation system (ZSI Zero-Knowledge Sovereign Identity)

It integrates:

- **Stwo** for Blake2-based hashing and Merkle root construction.
- **Malachite** for high precision arithmetic in stake-weighted consensus.
- **RocksDB** as the persistent storage engine for blocks, accounts, and chain metadata.

## Features

- Deterministic stake-weighted proposer selection backed by Malachite `Natural` arithmetic.
- RocksDB-backed storage with column families for blocks, accounts, and metadata.
- Ed25519 transaction signing and verification with Stwo hashing for all payload commitments.
- HTTP/JSON API powered by Axum for transaction submission and state inspection.
- Configurable block cadence, mempool sizing, and genesis allocation via TOML configuration.

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

# Generate a new Ed25519 keypair for the node
cargo run -- keygen --path keys/node.toml
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

## Configuration Highlights

`config/node.toml` includes:

- `data_dir`: persistent storage directory (RocksDB is stored in `data_dir/db`).
- `key_path`: location of the node's Ed25519 keypair file.
- `rpc_listen`: HTTP API address.
- `block_time_ms`: block production interval in milliseconds.
- `max_block_transactions` / `mempool_limit`: throughput tuning knobs.
- `genesis.accounts`: initial allocations with balances and stakes.

## Development Notes

- Run `cargo fmt` to keep formatting consistent.
- The RocksDB build may take a few minutes the first time. Subsequent builds reuse the compiled artifacts.
- Consensus selection and Merkle commitments are unit test friendly and live in `src/consensus.rs` and `src/ledger.rs` respectively.

Enjoy experimenting with the Digital Value Network!
