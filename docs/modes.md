# Runtime modes overview

Operators can choose between dedicated node, wallet, hybrid, and validator runtime profiles. This
guide summarises how each mode is assembled, which binaries invoke it, and what to expect from the
network interfaces and observability hooks. For configuration precedence and templates, refer to
[configuration](configuration.md) and the operator [checklist](checklists/operator.md).

## Quick reference

| Mode | Pipelines | Commands | Config sources | Telemetry defaults | Default listeners | Health probes | Startup markers | Exit codes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Node | Pipeline orchestrator drives ingest/observe/gossip/pruning loops.【F:rpp/runtime/orchestration.rs†L517-L608】 | `rpp-node node`, `cargo run --bin node`, or `scripts/run_node_mode.sh` invoke the `node` [[bin]] (the helper waits for health probes before handing back control).【F:rpp/node/src/main.rs†L31-L135】【F:rpp/node/Cargo.toml†L41-L54】【F:scripts/run_node_mode.sh†L31-L69】 | CLI path → `RPP_CONFIG` → mode default template.【F:rpp/node/src/lib.rs†L993-L1043】 | Telemetry disabled until configured; sampling 30s when enabled.【F:rpp/runtime/config.rs†L894-L907】【F:rpp/runtime/config.rs†L1057-L1088】 | RPC `127.0.0.1:7070`, P2P `/ip4/0.0.0.0/tcp/7600`.【F:rpp/runtime/config.rs†L1057-L1088】【F:config/node.toml†L15-L37】 | `/health`, `/health/live`, `/health/ready`.【F:rpp/rpc/api.rs†L974-L1145】 | `node runtime started`, `pipeline orchestrator started`, `rpc endpoint configured`.【F:rpp/node/src/lib.rs†L442-L552】 | 0 success, 2 config, 3 startup, 4 runtime.【F:rpp/node/src/main.rs†L18-L24】【F:rpp/node/src/lib.rs†L48-L120】 |
| Wallet | Wallet runtime only; no node orchestrator spawned.【F:rpp/node/src/lib.rs†L505-L557】 | `rpp-node wallet`, `cargo run --bin wallet`, or `scripts/run_wallet_mode.sh` invoke the `wallet` [[bin]] and perform readiness checks automatically.【F:rpp/node/src/main.rs†L35-L136】【F:rpp/node/Cargo.toml†L45-L48】【F:scripts/run_wallet_mode.sh†L31-L67】 | Same precedence, wallet template falls back when CLI/env omitted.【F:rpp/node/src/lib.rs†L1000-L1043】【F:config/wallet.toml†L1-L27】 | RPC at 9090 with telemetry off; embedded gossip disabled unless configured.【F:rpp/runtime/config.rs†L1435-L1513】【F:config/wallet.toml†L1-L27】 | Wallet RPC `127.0.0.1:9090`; optional gossip endpoints list.【F:rpp/runtime/config.rs†L1435-L1513】 | RPC exposes `/wallet/*` plus health endpoints via the shared router.【F:rpp/rpc/api.rs†L984-L1067】 | `wallet runtime initialised`, `rpc endpoint configured` (wallet).【F:rpp/node/src/lib.rs†L521-L553】 | Same exit codes as node CLI.【F:rpp/node/src/main.rs†L18-L24】【F:rpp/node/src/lib.rs†L48-L120】 |
| Hybrid | Node + wallet share the orchestrator; ensures listener parity and starts gossip task.【F:rpp/runtime/orchestration.rs†L517-L608】【F:rpp/node/src/lib.rs†L494-L557】【F:rpp/node/src/lib.rs†L722-L775】 | `rpp-node hybrid`, `cargo run --bin hybrid`, or `scripts/run_hybrid_mode.sh` start the combined runtime and verify health endpoints before returning control.【F:rpp/node/src/main.rs†L36-L136】【F:rpp/node/Cargo.toml†L49-L52】【F:scripts/run_hybrid_mode.sh†L34-L74】 | Loads `config/hybrid.toml`/`config/wallet.toml` unless overridden.【F:rpp/runtime/mod.rs†L44-L47】【F:rpp/node/src/lib.rs†L993-L1043】【F:config/hybrid.toml†L1-L59】 | Telemetry enabled, sampling every 30 s by default; wallet electrs tracker/metrics enabled in profile.【F:rpp/runtime/config.rs†L894-L907】【F:rpp/runtime/config.rs†L1494-L1513】 | Shared RPC `127.0.0.1:7070` (enforced), P2P `/ip4/0.0.0.0/tcp/7600`, wallet gossip endpoints prefilled.【F:config/hybrid.toml†L18-L47】【F:rpp/node/src/lib.rs†L722-L775】 | Health readiness requires node, wallet, and orchestrator to be live.【F:rpp/rpc/api.rs†L1132-L1145】 | Node + wallet markers plus telemetry banner (`telemetry endpoints configured`).【F:rpp/node/src/lib.rs†L442-L552】 | Same exit codes as other modes.【F:rpp/node/src/main.rs†L18-L24】【F:rpp/node/src/lib.rs†L48-L120】 |
| Validator | Hybrid stack plus validator-only CLI (VRF + telemetry helpers). Orchestrator required for readiness.【F:rpp/node/src/main.rs†L48-L178】【F:rpp/runtime/orchestration.rs†L517-L608】【F:rpp/rpc/api.rs†L1132-L1145】 | `rpp-node validator`, `cargo run --bin validator` run validator runtime; subcommands provide VRF/telemetry tooling.【F:rpp/node/src/main.rs†L38-L178】【F:rpp/node/Cargo.toml†L53-L55】 | Uses `config/validator.toml` and wallet profile; CLI may still override via precedence chain.【F:rpp/runtime/mod.rs†L44-L47】【F:rpp/node/src/lib.rs†L993-L1043】【F:config/validator.toml†L1-L60】 | Telemetry forced on with 15 s sampling; Electrs tracker telemetry and validator-specific metrics endpoints enabled.【F:rpp/runtime/config.rs†L904-L912】【F:rpp/runtime/config.rs†L1516-L1520】 | RPC `127.0.0.1:7070`, P2P `/ip4/0.0.0.0/tcp/7600`, Electrs tracker `127.0.0.1:9250`, metrics `127.0.0.1:9350`.【F:config/validator.toml†L18-L37】【F:rpp/runtime/config.rs†L1516-L1520】 | Same router; readiness additionally checks orchestrator.【F:rpp/rpc/api.rs†L1132-L1145】 | Node/hybrid markers plus VRF tooling messages when invoked.【F:rpp/node/src/lib.rs†L442-L552】【F:rpp/node/src/main.rs†L167-L178】 | Same exit codes as other modes.【F:rpp/node/src/main.rs†L18-L24】【F:rpp/node/src/lib.rs†L48-L120】 |

## Mode details

### Node runtime

* **Primary pipelines:** The node runtime constructs a `PipelineOrchestrator` that spawns ingest,
  observe, gossip, and pruning loops to advance ledger state and publish telemetry.【F:rpp/runtime/orchestration.rs†L517-L608】 The
  orchestrator begins once `NodeHandle::start` succeeds, emitting `node runtime started` and
  `pipeline orchestrator started` markers to the logs.【F:rpp/node/src/lib.rs†L442-L503】
* **Commands:** Invoke with `rpp-node node` or `cargo run --bin node`, both of which route to the
  `RootCommand::Node` arm in `main.rs` and the `node` binary declared in the manifest.【F:rpp/node/src/main.rs†L31-L136】【F:rpp/node/Cargo.toml†L41-L54】
* **Configuration:** Node configs load from the command line path, then the `RPP_CONFIG` environment
  variable, and finally the mode-specific default such as `config/node.toml`. The resolved bundle
  also loads the adjacent `malachite.toml` and validates schema versions before applying CLI
  overrides for data/telemetry fields.【F:rpp/node/src/lib.rs†L304-L357】【F:rpp/node/src/lib.rs†L993-L1080】【F:rpp/runtime/config.rs†L915-L1049】【F:rpp/runtime/config.rs†L180-L210】
* **Telemetry:** Defaults disable telemetry; hybrid/validator profiles enable it, but operators can
  set endpoints or toggle the CLI flags to override sample intervals and authentication tokens.【F:rpp/runtime/config.rs†L894-L907】【F:rpp/node/src/lib.rs†L1045-L1079】
* **Interfaces:** The runtime listens on `127.0.0.1:7070` for RPC and publishes the configured P2P
  multiaddr (default `/ip4/0.0.0.0/tcp/7600`). Health, readiness, and liveness probes are exposed at
  `/health`, `/health/live`, and `/health/ready` for automation.【F:rpp/runtime/config.rs†L1057-L1088】【F:rpp/rpc/api.rs†L974-L1145】
* **Shutdown and exits:** Graceful shutdown produces `node runtime exited cleanly`; error cases are
  encoded as configuration/startup/runtime exit codes 2/3/4 respectively.【F:rpp/node/src/lib.rs†L884-L895】【F:rpp/node/src/lib.rs†L48-L120】
* **Helper script:** `scripts/run_node_mode.sh` launches the CLI with the stock template, polls `/health/live` and `/health/ready`, and forwards the runtime's exit codes (0 success, 2 configuration, 3 startup, 4 runtime) to automation.【F:scripts/run_node_mode.sh†L19-L74】【F:rpp/node/src/main.rs†L18-L24】

### Wallet runtime

* **Primary pipelines:** Wallet-only deployments skip the node orchestrator; instead they mount the
  wallet service, initialise storage, and log `wallet runtime initialised` once keys and directories
  are ready.【F:rpp/node/src/lib.rs†L505-L553】
* **Commands:** Invoke with `rpp-node wallet` or `cargo run --bin wallet`. Both share the same exit
  semantics as other modes.【F:rpp/node/src/main.rs†L35-L136】【F:rpp/node/Cargo.toml†L45-L48】【F:rpp/node/src/lib.rs†L48-L120】
* **Configuration:** Wallet configs follow the same precedence chain (CLI → `RPP_CONFIG` → template)
  and validate gossip endpoints when the embedded node is disabled. The stock template listens on
  `127.0.0.1:9090` and disables Electrs integrations by default.【F:rpp/node/src/lib.rs†L960-L1043】【F:rpp/runtime/config.rs†L1435-L1513】【F:config/wallet.toml†L1-L27】
* **Telemetry & gossip:** Telemetry is off until explicitly enabled. Operators can point the wallet
  at remote gossip peers or enable the embedded node; hybrid/validator profiles flip these defaults
  automatically.【F:rpp/runtime/config.rs†L1494-L1513】
* **Interfaces and probes:** Wallet endpoints share the same RPC router, so `/health/*` is available
  alongside `/wallet/*` APIs for UI integrations.【F:rpp/rpc/api.rs†L984-L1067】
* **Helper script:** `scripts/run_wallet_mode.sh` wraps the CLI defaults, waits for `/health/live` and `/health/ready`, and exits with the runtime's status code for orchestration pipelines.【F:scripts/run_wallet_mode.sh†L19-L70】【F:rpp/node/src/main.rs†L18-L24】

### Hybrid runtime

* **Primary pipelines:** Hybrid mode starts the node orchestrator and wallet service together. The
  runtime asserts that the wallet RPC listener matches the node RPC port and that the wallet does not
  collide with the P2P port before booting both stacks.【F:rpp/runtime/orchestration.rs†L517-L608】【F:rpp/node/src/lib.rs†L494-L557】【F:rpp/node/src/lib.rs†L722-L775】
* **Commands:** Run via `rpp-node hybrid` or `cargo run --bin hybrid`. The manifest points both to
  the `hybrid` binary.【F:rpp/node/src/main.rs†L36-L136】【F:rpp/node/Cargo.toml†L49-L52】
* **Configuration:** Defaults derive from `config/hybrid.toml` for the node half and the standard
  wallet profile, unless overridden by CLI flags or `RPP_CONFIG`. Hybrid templates enable telemetry,
  tighten P2P heartbeat intervals, and pre-configure wallet Electrs metrics/gossip endpoints.【F:rpp/runtime/mod.rs†L44-L47】【F:rpp/node/src/lib.rs†L993-L1043】【F:config/hybrid.toml†L1-L59】【F:rpp/runtime/config.rs†L1494-L1513】
* **Telemetry & observability:** Expect the telemetry banner `telemetry endpoints configured` (or
  `telemetry enabled without explicit endpoint`) during startup if the template-provided options are
  left in place.【F:rpp/node/src/lib.rs†L442-L481】
* **Interfaces and probes:** Hybrid runs RPC on `127.0.0.1:7070`, P2P on `/ip4/0.0.0.0/tcp/7600`, and
  wallet gossip on `/ip4/127.0.0.1/tcp/7600`. Readiness requires the node, wallet, and orchestrator to
  be healthy, which is reflected by `/health/ready`.【F:config/hybrid.toml†L18-L47】【F:rpp/rpc/api.rs†L1132-L1145】
* **Helper script:** `scripts/run_hybrid_mode.sh` applies the hybrid and wallet templates, verifies the readiness probes, and propagates the runtime exit codes so CI or supervisors can react to configuration or startup failures.【F:scripts/run_hybrid_mode.sh†L21-L77】【F:rpp/node/src/main.rs†L18-L24】

### Validator runtime

* **Primary pipelines:** Validator mode layers validator tooling atop the hybrid runtime. It still
  launches the orchestrator, node, and wallet, and readiness additionally checks that the pipeline
  orchestrator is active.【F:rpp/node/src/main.rs†L48-L178】【F:rpp/runtime/orchestration.rs†L517-L608】【F:rpp/rpc/api.rs†L1132-L1145】
* **Commands:** Run `rpp-node validator` (or `cargo run --bin validator`) for the runtime, or append
  subcommands such as `validator vrf rotate`, `validator setup`, and `validator telemetry`/
  `validator uptime` for key management, preflight checks, and RPC diagnostics.【F:rpp/node/src/main.rs†L48-L409】【F:rpp/node/Cargo.toml†L53-L55】
* **Configuration:** Validator nodes default to `config/validator.toml` with telemetry enabled,
  faster P2P heartbeats, and testnet rollout channel. Wallet defaults enable Electrs runtime, tracker,
  and telemetry endpoints tailored to validator operations.【F:rpp/runtime/mod.rs†L44-L47】【F:rpp/node/src/lib.rs†L993-L1043】【F:config/validator.toml†L1-L60】【F:rpp/runtime/config.rs†L1516-L1520】
* **Telemetry & interfaces:** Expect telemetry sampling every 15 s, Electrs tracker on
  `127.0.0.1:9250`, and metrics on `127.0.0.1:9350`. VRF tooling logs include backend/identifier
  markers when invoked.【F:rpp/runtime/config.rs†L904-L912】【F:rpp/runtime/config.rs†L1516-L1520】【F:rpp/node/src/main.rs†L167-L178】
* **Operational cues:** Startup mirrors hybrid mode with additional validator-specific log lines; the
  same exit codes apply for automation.【F:rpp/node/src/lib.rs†L442-L552】【F:rpp/node/src/main.rs†L18-L24】

