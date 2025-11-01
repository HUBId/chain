# Validator Quickstart

This guide walks new operators through provisioning a validator node, wiring the
configuration, and enabling telemetry so observability dashboards light up on
the first boot. Pair it with the [Validator Troubleshooting](./validator_troubleshooting.md)
runbook for remediation steps and with the
[Deployment & Observability Playbook](./deployment_observability.md) for
ongoing operations.

## 1. Install Dependencies

The validator binary ships with the repository. Install the following toolchain
components on the host that will compile or update the node:

1. **Rust toolchain.** Install the pinned stable channel from
   [`rust-toolchain.toml`](../rust-toolchain.toml) by running
   `rustup toolchain install $(grep '^channel' rust-toolchain.toml | cut -d'"' -f2)`.
   The CI release workflow verifies this channel end-to-end, so matching it
   locally prevents feature drift.
2. **Build essentials.** Ensure `clang`, `cmake`, and your platform's build
   tools (such as `build-essential` on Debian/Ubuntu) are present. They are
   required for the VRF backend and RocksDB bindings compiled during `cargo
   build`.
3. **Protocol buffers.** Install `protoc` so the RPC and telemetry payloads can
   be generated. Refer to the [official installation instructions](https://grpc.io/docs/protoc-installation/).
4. **Node secrets.** Provision a validator key, libp2p key, and VRF key and
   store them in `config/keys/`. The quickstart assumes the default paths from
   `config/node.toml` (`key_path`, `p2p_key_path`, and `vrf_key_path`).

## 2. Fetch and Build the Node

```sh
# Clone and enter the repository
git clone https://github.com/ava-labs/chain.git
cd chain

# Verify the toolchain pin and compile the node
rustup show active-toolchain
cargo build --release -p rpp-node --no-default-features --features prod,prover-stwo
# If your hardware supports STWO's SIMD backend, swap `prover-stwo` with
# `prover-stwo-simd` to enable the accelerated proving pipeline.
```

Validator and hybrid launches must include the STWO prover backend. The runtime
aborts during startup if the binary was compiled without `prover-stwo` (or the
SIMD variant), emitting a bootstrap error that echoes the required `cargo
build -p rpp-node --release --no-default-features --features prod,prover-stwo`
command so proving keys are always available for block production and uptime
proofs.【F:rpp/node/src/lib.rs†L506-L512】 The resulting binary lives at
`target/release/rpp-node`. Keep the repository cloned on the host so future
upgrades can pull new releases without rebuilding from scratch.

## 3. Configure validator, wallet, and hybrid templates

Copy the shipping configuration files and adjust them for your deployment.
Validator operators should edit both `config/validator.toml` and
`config/wallet.toml` so the node and wallet runtimes launch with consistent
paths, secrets, and telemetry defaults, while hybrid installs start from
`config/hybrid.toml` plus `config/wallet.toml`.【F:config/validator.toml†L1-L59】【F:config/wallet.toml†L1-L33】【F:config/hybrid.toml†L1-L59】

Runtime launchers resolve configuration in three tiers: explicit CLI flags
(`--config`, `--wallet-config`), then the `RPP_CONFIG` environment variable, and
finally the mode's template (for example `config/validator.toml` or
`config/hybrid.toml`).【F:rpp/node/src/lib.rs†L993-L1040】【F:rpp/runtime/mod.rs†L42-L58】 This
mirrors the behaviour of the legacy scripts while giving operators a single
override point per deployment.

The example below highlights the node-specific fields new operators typically
customise:

```toml
# Copy to /etc/rpp/node.toml or similar and adjust secrets and paths
include = "./config/node.toml"

data_dir = "/var/lib/rpp"
snapshot_dir = "/var/lib/rpp/snapshots"
proof_cache_dir = "/var/lib/rpp/proofs"
mempool_limit = 16384

[network.rpc]
listen = "0.0.0.0:7070"

[network.limits.per_ip_token_bucket]
replenish_per_minute = 900

[rollout]
release_channel = "testnet"

[rollout.feature_gates]
pruning = true
recursive_proofs = true
reconstruction = true
consensus_enforcement = true
malachite_consensus = false
witness_network = false

[rollout.telemetry]
enabled = true
endpoint = "https://telemetry.example.com:4317"
http_endpoint = "https://telemetry.example.com/v1/metrics"
trace_max_queue_size = 4096
trace_max_export_batch_size = 1024
trace_sample_ratio = 0.5
warn_on_drop = true
sample_interval_secs = 15

[rollout.telemetry.grpc_tls]
ca_certificate = "/etc/rpp/telemetry/collector-ca.pem"

[rollout.telemetry.http_tls]
ca_certificate = "/etc/rpp/telemetry/collector-ca.pem"

[p2p]
bootstrap_peers = ["/dns/bootnode.example.com/tcp/7600/p2p/12D3Koo..."]
heartbeat_interval_ms = 3000
gossip_rate_limit_per_sec = 256

[reputation.tier_thresholds]
tier2_min_uptime_hours = 48
```

After adjusting the node template, apply the same review to your wallet file.
Validator and hybrid profiles reuse the node key material and enable telemetry
for the embedded Electrs services, so double-check gossip endpoints and the
tracker/metrics bindings before pushing the bundle to production.【F:rpp/runtime/config.rs†L1249-L1313】

Key tips while editing the configuration:

- **Feature gates:** All runtime feature toggles share the
  `rollout.feature_gates` map. Keep optional backends like `malachite_consensus`
  and `witness_network` disabled until their circuits are deployed, but leave
  the base proof and pruning gates enabled so block production succeeds.
- **Telemetry (node runtime):** Enabling `rollout.telemetry.enabled` without
  providing an OTLP endpoint keeps telemetry in structured logs. Set both
  `endpoint` (for gRPC traces) and `http_endpoint` (for OTLP/HTTP metrics) or
  pass the corresponding CLI flags so exporters connect to your collector.
  Tune `trace_max_queue_size`/`trace_max_export_batch_size` to match the
  collector's throughput and adjust `trace_sample_ratio` if you only need a
  fraction of spans. When `warn_on_drop` is true, the node emits warnings if the
  queue overflows so you can react before data is lost. TLS credentials go in
  the nested `grpc_tls` and `http_tls` tables; at minimum set
  `ca_certificate` to trust your collector's certificates. A shorter
  `sample_interval_secs` increases metric freshness at the cost of more network
  traffic.【F:rpp/runtime/config.rs†L1632-L1721】【F:rpp/runtime/telemetry/exporter.rs†L21-L210】
- **Telemetry (wallet runtime):** Hybrid and validator wallets enable telemetry
  caches and tracker emission by default. When running the wallet runtime in
  isolation, either keep the defaults or point `electrs.cache.telemetry` and
  `electrs.tracker.telemetry_endpoint` at your collector to preserve the same
  visibility level.【F:config/wallet.toml†L9-L31】【F:rpp/runtime/config.rs†L1269-L1313】
- **Telemetry resource tags:** Validator and hybrid pipelines now emit unified
  OpenTelemetry resources on startup so collectors can group spans and metrics by
  runtime. Expect attributes such as `service.name=rpp`,
  `service.component=rpp-node`, `rpp.mode=<mode>`, rollout release channel, and
  the resolved configuration source/path when a template or environment override
  is used.【F:rpp/node/src/lib.rs†L1633-L1674】 Pair these with the
  [Deployment & Observability Playbook](./deployment_observability.md) and
  [Observability Runbook](./runbooks/observability.md) to confirm collectors and
  dashboards see the enriched labels.
- **Snapshots and proofs:** Place `snapshot_dir` and `proof_cache_dir` on fast,
  persistent storage. Missing snapshots force peers to re-sync from genesis and
  slow down validator recovery after restarts.
- **RPC throttling:** Raise `network.limits.per_ip_token_bucket.replenish_per_minute` cautiously and monitor the
  `/status/mempool` telemetry to ensure external users cannot exhaust CPU with
  bursts of submission attempts.

## 4. Launch the Validator or Hybrid runtime

Create a systemd service, Kubernetes deployment, or supervise the binary with
`tmux` during testing. Launch validator mode with both configuration files so
the node and wallet components come up together:

```sh
RUST_LOG=info ./target/release/rpp-node validator \
  --config /etc/rpp/validator.toml \
  --wallet-config /etc/rpp/wallet.toml \
  --telemetry-endpoint https://telemetry.example.com:4317 \
  --telemetry-sample-interval 15
```

When developing locally you can target the dedicated binaries registered in
`Cargo.toml` and avoid juggling subcommands:

```sh
cargo run --release --bin validator -- \
  --config config/validator.toml \
  --wallet-config config/wallet.toml \
  --dry-run
```

Hybrid deployments that expose wallet functionality alongside a validator can
swap the `validator` mode for `hybrid` and point at the hybrid profile instead.
Both the multiplexed binary and the dedicated wrapper are supported:

```sh
# Production launch
RUST_LOG=info ./target/release/rpp-node hybrid \
  --config /etc/rpp/hybrid.toml \
  --wallet-config /etc/rpp/wallet.toml \
  --telemetry-endpoint https://telemetry.example.com:4317

# Local smoke-test
cargo run --release --bin hybrid -- \
  --config config/hybrid.toml \
  --wallet-config config/wallet.toml \
  --dry-run
```

Add `--dry-run` to validate configuration, secrets, and port bindings without
handing control to the long-running runtime. The CLI exits after pipeline
bootstrap completes, making it safe for CI and change-management gates.【F:rpp/node/src/lib.rs†L232-L314】

The CLI also supports `--log-json`, RPC overrides, and other telemetry
shortcuts when you need to override defaults at launch time.【F:rpp/node/src/lib.rs†L35-L111】

Verify the node has joined the gossip network via `/p2p/peers` (and
`/p2p/peers/self` for the local identity) and confirm the release channel,
feature-gate state, and telemetry health via `/status/rollout`. The
[Deployment & Observability Playbook](./deployment_observability.md) lists the
dashboards and alerts operators should wire up immediately after bootstrap.

### Validator endpoint quick-reference

| Endpoint | Purpose | Notes |
| --- | --- | --- |
| `GET /p2p/peers` | Lists connected peers and their libp2p identities. | Combine with `GET /p2p/peers/self` to validate the local peer ID and advertised addresses. |
| `GET /snapshots/plan` | Shows the snapshot heights and digests this validator is ready to serve. | Use to confirm fresh snapshots are published after pruning. |
| `GET /snapshots/jobs` | Displays active snapshot ingestion or export jobs. | Helpful during rebuilds to watch chunking progress. |
| `GET /state-sync/session` | Returns the active state-sync session including chunk totals, served indexes, verification stage, progress log, and last error. | Useful when diagnosing catch-up or reconstruction issues; requires an `Authorization` header when RPC auth is enabled. |

## 5. Keep the Node Healthy

- **Back up secrets:** Store encrypted copies of validator, libp2p, and VRF keys
  off the host. Without them the node cannot rejoin the set after hardware
  failure.
- **Use the validator tooling:** The `rpp-node validator` CLI rotates VRF keys,
  exports backups, validates secrets/telemetry via `validator setup`, and
  manages uptime proofs through `validator uptime submit`/`validator uptime status`
  without restarting the process. Pair the CLI with the `/state-sync/session` RPC
  endpoint (bearer token required when RPC auth is enabled) and related `/state-sync`
  routes to stream light-client heads and download snapshot chunks using
  tools like `curl` or `wget`. See [Validator Tooling](./validator_tooling.md)
  for detailed workflows.【F:rpp/node/src/main.rs†L92-L409】【F:rpp/node/src/lib.rs†L90-L357】【F:docs/validator_tooling.md†L1-L140】
- **Rotate snapshots:** Periodically prune old `snapshot_dir` entries only after
  confirming peers have advanced beyond the retained height. Keep multiple
  recent snapshots so new nodes can sync quickly.
- **Watch telemetry:** Inspect `telemetry.handshake`, `telemetry.rollout`, and
  `telemetry.vrf_metrics` logs for early warnings about misconfigured peers or
  failing VRF submissions.
- **Review release notes:** Each release documents configuration changes,
  feature-gate defaults, and migration steps in [`RELEASE_NOTES.md`](../RELEASE_NOTES.md).
  Apply them before upgrading binaries.

Next steps: practise failure recovery with the
[Validator Troubleshooting](./validator_troubleshooting.md) guide so you can
respond quickly when alerts fire.
