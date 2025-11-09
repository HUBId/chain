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

The RPP Blockchain introduces a novel consensus and participation mechanism called Proof of Lottery (POL).
Unlike Proof of Work (PoW) or Proof of Stake (PoS), POL does not depend on computational effort or capital weight.
Instead, it is built on verifiable randomness, reputation, and identity integrity.

### Overview

Proof of Lottery defines how validator participation and reward eligibility are determined in the RPP Blockchain.
Each consensus round begins with a [verifiable random selection (VRF)](./docs/poseidon_vrf.md) that draws participants from the network based on their reputation score.
This reputation score is derived from two measurable components:

- [TimeToken](./docs/consensus/timetoke.md) – representing continuous uptime and verifiable node availability, accumulated through periodic uptime proofs.
- [Tier System](./docs/network/admission.md) – defining dynamic reputation levels that reflect long-term reliability, contribution, and honesty.

Together, these form the [RPP Reputation System (RPP-RS)](./docs/consensus/uptime_proofs.md#reputation-integration), which quantifies trust and network participation without any capital staking or mining.

### Core Principles

**Verifiable Randomness (VRF):**
Each node participates in a lottery using a [verifiable random function (VRF)](./docs/poseidon_vrf.md).
The output determines whether it is selected for the current consensus round.
The probability of selection is weighted by the node’s reputation tier and [TimeToken](./docs/consensus/timetoke.md) balance.

**Sybil Resistance (ZSI):**
The [Zero-Knowledge Sovereign Identity (ZSI)](./docs/wallet/zsi.md) framework ensures that each participant represents a unique, verifiable entity without exposing personal data.
This guarantees that reputation cannot be multiplied through multiple pseudonymous nodes.

**Reputation-Weighted Fairness:**
Every node has a chance to be selected, but higher reputation tiers — earned through consistent uptime and correct participation — have proportionally higher selection probability.
This creates a fair and self-balancing ecosystem where reliability, not wealth or computing power, drives influence.

**Energy-Efficient Finality:**
Once a validator set is selected through the lottery, consensus proceeds via the [BFT](./docs/consensus/malachite.md) layer.
Blocks reach instant finality without resource-intensive work or stake validation.

**Reward Distribution:**
Rewards are distributed among participants of each finalized round based on successful validation and uptime proofs.
The reward mechanism is directly tied to verifiable participation, ensuring long-term network stability.

### Design Outcome

POL achieves the same core goals as traditional consensus systems — fairness, security, and decentralization — while eliminating capital bias and energy waste.
It enables verifiable participation driven by contribution and reputation rather than wealth or computational power.

In summary:

Proof of Lottery (POL) = Verifiable Random Selection ([VRF](./docs/poseidon_vrf.md))
weighted by Reputation ([TimeToken](./docs/consensus/timetoke.md) + [Tier System](./docs/network/admission.md))
secured through [ZSI](./docs/wallet/zsi.md) identity
finalized by [BFT](./docs/consensus/malachite.md) consensus.

This mechanism defines how the RPP Blockchain continuously rewards honest behavior, uptime, and contribution — providing a transparent, fair, and sustainable foundation for decentralized consensus.

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

## Docker smoke test

The repository ships a `docker-compose.yml` that wires the node, validator UI,
simnet orchestrator, and the Firewood CLI. Copy the sample environment and spin
up the stack in detached mode:

```sh
cp .env.example .env
docker compose up -d
```

The compose definitions enable container health checks by default. Probe the
exposed endpoints once the build completes:

```sh
# Node RPC health【F:rpp/node/Dockerfile†L86-L124】
curl -f http://127.0.0.1:${RPP_NODE_RPC_PORT}/health/ready

# Simnet orchestrator health server (enabled via SIMNET_HEALTH_ADDR)【F:tools/simnet/README.docker.md†L42-L57】
curl -f http://127.0.0.1:${SIMNET_HEALTH_PORT}/health/live

# Validator UI healthz endpoint served by NGINX【F:validator-ui/README.md†L20-L33】
curl -f http://127.0.0.1:${VALIDATOR_UI_PORT}/healthz

# Optional Firewood CLI health server (requires the tooling profile)【F:fwdctl/README.md†L27-L40】
docker compose --profile tooling up -d fwdctl
curl -f http://127.0.0.1:${FWDCTL_HEALTH_PORT}/health/ready
```

Shut everything down with `docker compose down` after the smoke test. The
`tooling` profile keeps the `fwdctl` loop out of the default stack while still
providing an always-on health endpoint for ad-hoc Firewood experiments.

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
