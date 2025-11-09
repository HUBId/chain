# ztate

> ✅ **Production Plonky3 backend**
>
> The vendor Plonky3 prover/verifier has graduated to the production profile.
> Runtime snapshots under `/status/node` expose prover and verifier health, and
> release tooling rejects artefacts that ship forbidden mock features so the
> signed bundles always include one of the supported production backends.【F:rpp/runtime/node.rs†L4862-L4894】【F:rpp/proofs/plonky3/prover/mod.rs†L19-L520】【F:scripts/verify_release_features.sh†L1-L146】

ztate is the reference implementation of the RPP blockchain stack. It packages the
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

## Proof of Lottery (POL)

Die RPP Blockchain verwendet kein Proof of Stake (PoS) und kein Proof of Work (PoW).
Stattdessen basiert ihr Konsens- und Belohnungssystem auf einem neuartigen Mechanismus namens Proof of Lottery (POL).

Proof of Lottery (POL) beschreibt die Art, wie in der RPP Blockchain Validatoren und Teilnehmer über eine verifizierbare Zufallsauswahl (VRF) in Kombination mit BFT-Finalität, Reputation, Zero-Knowledge Sovereign Identity (ZSI), TimeToken und dem internen Coin-Reward-Verteilungsprozess bestimmt werden.

In jeder Konsens-Runde (BFT-Round) werden Knoten über die VRF-Selektion zufällig bestimmt, um am Block-Finalisierungsprozess teilzunehmen.
Diese Auswahl ist überprüfbar, transparent und nicht kapitalgebunden.
Der Block-Reward (Coin-Reward) wird anschließend im BFT-Konsens zufällig und fair unter den korrekt teilnehmenden Nodes verteilt.

Das Zusammenspiel aus

Reputation System (RPP RS) – bewertet kontinuierliche, ehrliche Teilnahme,

TimeToken – belegt die Betriebszeit (Uptime) und aktive Beteiligung,

ZSI – stellt sybil-resistente Identität sicher,

VRF – liefert den verifizierbaren Zufall für die Auswahl, und

BFT CoinReward-Verteilung – sorgt für die gleichmäßige Belohnung der Beteiligten,

bildet gemeinsam den Mechanismus des Proof of Lottery.

POL ist damit ein reputations-, identitäts- und zufallsbasiertes Auswahlverfahren, das
– ohne Mining, ohne Stake, ohne Energieverbrauch –
eine faire, überprüfbare und finalisierende Blockerzeugung ermöglicht.

Alle für POL relevanten Komponenten sind in der RPP-Blockchain bereits integriert:
die VRF-Selektion im Konsensmodul,
das RPP Reputation System (RPP RS),
die TimeToken-Logik für Uptime-Proofs,
das ZSI-System für Identität,
sowie der Random-BFT-Konsens zur Finalität.

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
make vendor-plonky3  # python3 scripts/vendor_plonky3/refresh.py (refreshes the Plonky3 mirror)
```

Nightly toolchains are only needed when modifying the prover workspace.
The `vendor-plonky3` target regenerates the offline mirror under
`third_party/plonky3/`, including the `config.toml` snippet that can be exported
via `CARGO_CONFIG` to route Plonky3 crates to the mirror during
`scripts/build.sh --backend plonky3` runs.【F:scripts/build.sh†L15-L55】【F:Makefile†L9-L27】
Additional development workflow details live in [`docs/development_guide.md`](./docs/development_guide.md).

## Running a local node

1. Build the node binary with `cargo +1.79.0 build -p rpp-node --release --no-default-features --features prod,prover-stwo` (or swap in `prover-stwo-simd` on hosts that support the SIMD-accelerated prover backend).
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
logs. When the node RPC runs behind an authenticated gateway, set
`RPP_NODE_RPC_AUTH_TOKEN` (for `Authorization: Bearer …`) or provide additional
newline-separated headers via `RPP_NODE_HEALTH_HEADERS` so the readiness probes
include the required metadata.【F:scripts/run_node_mode.sh†L10-L64】 Wallet
pipelines accept the analogous `RPP_WALLET_RPC_AUTH_TOKEN` and
`RPP_WALLET_HEALTH_HEADERS` variables for their health checks.【F:scripts/run_wallet_mode.sh†L1-L63】

`config/hybrid.toml` and `scripts/run_hybrid_mode.sh` start a combined node and
wallet process, while `scripts/run_wallet_mode.sh` launches the wallet-only
pipeline.【F:scripts/run_hybrid_mode.sh†L10-L66】【F:scripts/run_wallet_mode.sh†L10-L54】
Validator and hybrid modes require the STWO prover backend and abort during
startup when the corresponding feature (`prover-stwo` or `prover-stwo-simd`) is
missing.

The Plonky3 backend now mirrors the STWO production pipeline. Build or check
the crate with `--features backend-plonky3` (optionally paired with `dev`) to
exercise the vendor prover end-to-end. Compile-time guards still refuse to pair
the backend with the deterministic mock prover so production artefacts contain
only real provers, and the feature-matrix tests keep that restriction enforced
during CI.【F:rpp/node/src/feature_guard.rs†L1-L7】【F:rpp/node/Cargo.toml†L9-L21】【F:scripts/test.sh†L38-L47】【F:tests/feature_guard.rs†L1-L52】 Runtime launch
helpers continue to emit explicit warnings and backout guidance when the prover
feature set is misconfigured so operators can recover quickly during staged or
production rollouts.【F:scripts/lib/rpp-node-mode-common.sh†L1-L36】

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
guidebook in [`docs/README.md`](docs/README.md), review the [`rpp-node`
operator guide](docs/rpp_node_operator_guide.md) for CLI-focused workflows, and
then dive into specialized sections such as consensus, pruning, runtime, or
telemetry as needed.【F:docs/README.md†L1-L18】【F:docs/rpp_node_operator_guide.md†L1-L88】【F:docs/malachite_bft_architecture.md†L9-L116】

For development questions see [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
project changelog (`CHANGELOG.md`). Security-sensitive reports should follow the
[`SECURITY.md`](SECURITY.md) process.

## License

The project is distributed under the Avalanche ecosystem license; see
[`LICENSE.md`](LICENSE.md) for details.
