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
git clone https://github.com/ava-labs/firewood.git
cd firewood

# Verify the toolchain pin and compile the node
rustup show active-toolchain
cargo build --release -p rpp-node
```

The resulting binary lives at `target/release/rpp-node`. Keep the repository
cloned on the host so future upgrades can pull new releases.

## 3. Configure validator, wallet, and hybrid templates

Copy the shipping configuration files and adjust them for your deployment.
Validator operators should edit both `config/validator.toml` and
`config/wallet.toml` so the node and wallet runtimes launch with consistent
paths, secrets, and telemetry defaults, while hybrid installs start from
`config/hybrid.toml` plus `config/wallet.toml`.【F:config/validator.toml†L1-L59】【F:config/wallet.toml†L1-L33】【F:config/hybrid.toml†L1-L59】

The example below highlights the node-specific fields new operators typically
customise:

```toml
# Copy to /etc/rpp/node.toml or similar and adjust secrets and paths
include = "./config/node.toml"

data_dir = "/var/lib/rpp"
snapshot_dir = "/var/lib/rpp/snapshots"
proof_cache_dir = "/var/lib/rpp/proofs"
rpc_listen = "0.0.0.0:7070"
rpc_requests_per_minute = 900
mempool_limit = 16384

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
sample_interval_secs = 15

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
  providing an `endpoint` keeps telemetry in structured logs. Set `endpoint`
  (or pass `--telemetry-endpoint` to the binary) to push snapshots to your
  collector. A shorter `sample_interval_secs` increases metric freshness at the
  cost of more network traffic.【F:config/validator.toml†L45-L59】【F:rpp/node/src/lib.rs†L35-L111】
- **Telemetry (wallet runtime):** Hybrid and validator wallets enable telemetry
  caches and tracker emission by default. When running the wallet runtime in
  isolation, either keep the defaults or point `electrs.cache.telemetry` and
  `electrs.tracker.telemetry_endpoint` at your collector to preserve the same
  visibility level.【F:config/wallet.toml†L9-L31】【F:rpp/runtime/config.rs†L1269-L1313】
- **Snapshots and proofs:** Place `snapshot_dir` and `proof_cache_dir` on fast,
  persistent storage. Missing snapshots force peers to re-sync from genesis and
  slow down validator recovery after restarts.
- **RPC throttling:** Raise `rpc_requests_per_minute` cautiously and monitor the
  `/status/mempool` telemetry to ensure external users cannot exhaust CPU with
  bursts of submission attempts.

## 4. Launch the Validator or Hybrid runtime

Create a systemd service, Kubernetes deployment, or supervise the binary with
`tmux` during testing. Launch validator mode with both configuration files so
the node and wallet components come up together:

```sh
RUST_LOG=info ./target/release/rpp-node \
  --mode validator \
  --config /etc/rpp/validator.toml \
  --wallet-config /etc/rpp/wallet.toml \
  --telemetry-endpoint https://telemetry.example.com:4317 \
  --telemetry-sample-interval 15
```

Hybrid deployments that expose wallet functionality alongside a validator can
swap `--mode hybrid` and point at the hybrid profile instead:

```sh
RUST_LOG=info ./target/release/rpp-node \
  --mode hybrid \
  --config /etc/rpp/hybrid.toml \
  --wallet-config /etc/rpp/wallet.toml \
  --telemetry-endpoint https://telemetry.example.com:4317
```

The CLI also supports `--log-json`, RPC overrides, and other telemetry
shortcuts when you need to override defaults at launch time.【F:rpp/node/src/lib.rs†L35-L111】

Verify the node has joined the gossip network via `/status/p2p` and confirm the
release channel, feature-gate state, and telemetry health via
`/status/rollout`. The [Deployment & Observability Playbook](./deployment_observability.md)
lists the dashboards and alerts operators should wire up immediately after
bootstrap.

## 5. Keep the Node Healthy

- **Back up secrets:** Store encrypted copies of validator, libp2p, and VRF keys
  off the host. Without them the node cannot rejoin the set after hardware
  failure.
- **Use the validator tooling:** The `rpp-node validator` CLI rotates VRF keys,
  exports backups, and exposes telemetry snapshots without restarting the
  process. See [Validator Tooling](./validator_tooling.md) for detailed
  workflows.【F:rpp/node/src/main.rs†L92-L203】【F:docs/validator_tooling.md†L1-L83】
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
