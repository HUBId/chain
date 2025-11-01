# Ztate

Ztate is the reference implementation of the RPP blockchain stack. It packages the
runtime node, consensus engine, libp2p networking, proof system, wallet
orchestrator, and Firewood-backed storage that together power the network.
Storage, proofs, and networking crates live in this repository so operators and
developers can build, run, and extend the chain end-to-end.

## Key capabilities

- **Runtime execution pipeline** – The node coordinates transaction, identity,
vote, uptime, witness, and VRF queues, persists finalized state through
`StateLifecycle`, and exposes handles for gossip and proof verification.【F:rpp/runtime/node.rs†L760-L796】【F:rpp/runtime/node.rs†L5938-L6011】
- **Wallet orchestration** – The wallet process boots embedded nodes on demand,
subscribes to gossip feeds, and drives Electrs integration so operators get a
unified control plane for proofs and telemetry.【F:rpp/wallet/ui/wallet.rs†L1067-L1197】【F:rpp/wallet/src/vendor/electrs/init.rs†L28-L152】
- **Proof construction and verification** – STWO-based provers derive witnesses
for identity, transaction, state, pruning, uptime, and consensus pipelines while
the runtime reuses the same lifecycle APIs for verification.【F:rpp/proofs/stwo/prover/mod.rs†L408-L519】【F:rpp/storage/state/lifecycle.rs†L13-L86】
- **Malachite BFT consensus** – The consensus layer implements VRF-based
validator selection, leader bonuses, witness coordination, and evidence-driven
slashing as described in the Malachite architecture plan.【F:rpp/consensus/src/state.rs†L948-L1199】【F:docs/malachite_bft_architecture.md†L9-L116】
- **Gossip backbone** – Canonical libp2p topics under `/rpp/gossip/*` deliver
blocks, votes, proof bundles, VRF submissions, and snapshot sync to the runtime
queues.【F:rpp/p2p/src/topics.rs†L6-L85】【F:rpp/runtime/node.rs†L2544-L2680】
- **Operational documentation** – Operator guides, runbooks, and interface
specifications ship with the repository for easy reference.【F:docs/README.md†L1-L18】【F:docs/interfaces/spec.md†L1-L133】

## Repository layout

| Path | Description |
| --- | --- |
| `rpp/node` | Executable entry points (`rpp-node`, `wallet`, `hybrid`, `validator`) and runtime wiring.【F:rpp/node/Cargo.toml†L1-L41】 |
| `rpp/runtime` | Core node pipeline, state lifecycle, and gossip integration.【F:rpp/runtime/node.rs†L760-L796】【F:rpp/runtime/node.rs†L2544-L2680】 |
| `rpp/consensus` | Malachite BFT consensus engine, reputation, rewards, and evidence handling.【F:rpp/consensus/src/state.rs†L948-L1199】 |
| `rpp/p2p` | libp2p networking stack, gossip topics, and admission heuristics.【F:rpp/p2p/src/topics.rs†L6-L85】 |
| `rpp/proofs` | STWO proof builders and verification traits consumed by runtime and wallet.【F:rpp/proofs/stwo/prover/mod.rs†L408-L519】 |
| `rpp/storage` | Firewood-backed ledger, pruning receipts, and state transition APIs.【F:rpp/storage/state/lifecycle.rs†L13-L86】 |
| `rpp/wallet` | CLI/UI orchestrator, embedded runtime management, and Electrs adapters.【F:rpp/wallet/ui/wallet.rs†L1067-L1197】 |
| `prover/` | Nightly-only prover workspace containing the STWO backend.【F:docs/development_guide.md†L8-L17】 |
| `storage-firewood/` | Firewood database bindings used by the runtime state lifecycle.【F:rpp/runtime/node.rs†L5938-L6011】 |
| `docs/` | Architecture references, operator guides, interface schemas, and blueprints.【F:docs/README.md†L1-L18】 |
| `config/` | Sample node and wallet configurations for local deployments.【F:config/node.toml†L1-L84】【F:config/wallet.toml†L1-L55】 |
| `scripts/` | Helper scripts for smoke tests and launching node, wallet, and hybrid modes.【F:scripts/run_node_mode.sh†L10-L57】【F:scripts/run_wallet_mode.sh†L10-L54】【F:scripts/run_hybrid_mode.sh†L10-L66】 |

## Prerequisites

Ensure the following tools are installed before building:

- [Rust toolchain](https://doc.rust-lang.org/cargo/getting-started/installation.html) with the pinned stable (`1.79.0`) and
optional nightly (`nightly-2025-07-14`) toolchains.【F:Makefile†L1-L23】
- [`protoc`](https://grpc.io/docs/protoc-installation/) for generated protobuf
interfaces used by RPC and networking layers.【F:README.docker.md†L15-L35】
- [`make`](https://www.gnu.org/software/make/#download) or your platform’s build-essential package to run helper targets.【F:Makefile†L1-L23】

## Building the workspace

The top-level `Makefile` pins the required toolchains and excludes nightly-only
crates when building in stable mode.【F:Makefile†L1-L23】 Use the following targets:

```sh
make build:stable    # cargo +1.79.0 build --workspace (excludes prover crates)
make test:stable     # cargo +1.79.0 test --workspace (excludes prover crates)
make build:nightly   # cargo +nightly-2025-07-14 build --manifest-path prover/Cargo.toml
make test:nightly    # cargo +nightly-2025-07-14 test  --manifest-path prover/Cargo.toml
```

Nightly toolchains are only needed when modifying the prover workspace.
Additional development workflow details live in [`docs/development_guide.md`](./docs/development_guide.md).

## Running a local node

1. Build the node binary with `cargo +1.79.0 build -p rpp-node --release`.
2. Copy `config/node.toml` and adjust keys, networking, and gossip settings as
needed.【F:config/node.toml†L1-L84】
3. Launch the node directly or through the helper script:
   ```sh
   target/release/rpp-node --config my-node.toml
   ```
   or
   ```sh
   scripts/run_node_mode.sh --config my-node.toml
   ```
4. Monitor health endpoints exposed by the node or the helper script’s readiness
logs.【F:scripts/run_node_mode.sh†L10-L57】

`config/hybrid.toml` and `scripts/run_hybrid_mode.sh` start a combined node and
wallet process, while `scripts/run_wallet_mode.sh` launches the wallet-only
pipeline.【F:scripts/run_hybrid_mode.sh†L10-L66】【F:scripts/run_wallet_mode.sh†L10-L54】

## Wallet and Electrs integration

The sample wallet configuration at `config/wallet.toml` describes RPC, embedded
node options, and Electrs feature gates. Enabling runtime or tracker features
creates Firewood and index directories automatically and hooks into gossip topics
for block and telemetry updates.【F:config/wallet.toml†L1-L55】【F:rpp/wallet/src/vendor/electrs/init.rs†L28-L152】 Use the wallet
script to boot the pipeline:

```sh
scripts/run_wallet_mode.sh --config my-wallet.toml
```

Once running, the wallet streams orchestrator dashboards, witness gossip, and
tracker status into the UI.【F:rpp/wallet/ui/wallet.rs†L945-L1197】

## Documentation and support

Comprehensive operator runbooks, telemetry guides, architecture diagrams, and
interface specifications are published under `docs/`. Start with the operator
guidebook in [`docs/README.md`](docs/README.md), then dive into specialized
sections such as consensus, pruning, runtime, or telemetry as needed.【F:docs/README.md†L1-L18】【F:docs/malachite_bft_architecture.md†L9-L116】

For development questions see [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
project changelog (`CHANGELOG.md`). Security-sensitive reports should follow the
[`SECURITY.md`](SECURITY.md) process.

## License

The project is distributed under the Avalanche ecosystem license; see
[`LICENSE.md`](LICENSE.md) for details.
