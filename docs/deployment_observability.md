# Deployment & Observability Playbook

This playbook translates the blueprint's phase 8 requirements into actionable
runbooks for bringing the STWO/Plonky3 chain online and keeping it observable in
production. Pair it with the [Validator Quickstart](./validator_quickstart.md)
for provisioning steps, the [Validator Troubleshooting](./validator_troubleshooting.md)
runbook for incident response, and the
[`rpp-node` operator guide](./rpp_node_operator_guide.md) for authentication,
throttling, and recovery procedures that apply to operator-driven RPC
workflows. The new telemetry stack ships with dedicated
[incident runbooks](./runbooks/observability.md) and
[dashboard blueprints](./dashboards/README.md); reference them when wiring the
collector and during on-call response.

## Runtime Modes & Telemetry Matrix

The runtime ships four execution profiles that dictate which subsystems and
telemetry surfaces are enabled. Each profile can be selected via the `--mode`
CLI flag or a runtime profile file and maps to default configuration templates
for the node and wallet components.【F:rpp/runtime/mod.rs†L8-L56】

| Mode        | Includes | Default configs | Telemetry footprint |
|-------------|----------|-----------------|---------------------|
| `node`      | Node only | `config/node.toml` | Exposes node RPC, consensus, storage, and proof metrics; wallet signals remain disabled.【F:rpp/runtime/mod.rs†L33-L54】【F:rpp/runtime/telemetry/metrics.rs†L94-L205】 |
| `wallet`    | Wallet only | `config/wallet.toml` | Emits wallet RPC latency/throughput metrics and pipeline counters without node consensus data.【F:rpp/runtime/mod.rs†L20-L54】【F:rpp/runtime/telemetry/metrics.rs†L115-L139】【F:rpp/runtime/orchestration.rs†L359-L706】 |
| `hybrid`    | Node + wallet | `config/hybrid.toml`/`config/wallet.toml` | Aggregates both node and wallet telemetry, suitable for light validators or staging rigs.【F:rpp/runtime/mod.rs†L19-L54】【F:rpp/runtime/node.rs†L3932-L4017】 |
| `validator` | Node + wallet + orchestrator | `config/validator.toml`/`config/wallet.toml` | Enables full validator visibility (consensus, proof generation, wallet pipeline) and should back production dashboards.【F:rpp/runtime/mod.rs†L13-L54】【F:rpp/runtime/telemetry/metrics.rs†L94-L205】【F:rpp/runtime/orchestration.rs†L359-L940】 |

## Telemetry Configuration Controls

### Structured logging & resource metadata

Every runtime boots a structured JSON log layer that injects the runtime mode,
configuration source, and a stable instance identifier alongside standard log
fields. The layer also stamps each record with OpenTelemetry service metadata so
log aggregation can correlate log lines with spans and metrics in the same
resource graph.【F:rpp/node/src/lib.rs†L1134-L1315】【F:rpp/node/src/lib.rs†L1353-L1392】 The
OTLP resource itself includes `service.name=rpp`,
`service.component=rpp-node`, the resolved runtime mode, configuration source,
instance id, configuration schema version, and rollout telemetry sampling
flags.【F:rpp/node/src/lib.rs†L1179-L1195】【F:rpp/node/src/lib.rs†L1633-L1664】

### Runtime modes & telemetry activation

Telemetry enablement follows the selected runtime mode: node, wallet, hybrid,
and validator profiles drive which subsystems start and which signals they
emit.【F:rpp/runtime/mod.rs†L8-L56】 At startup the node emits explicit markers for
each pipeline—`"node runtime started"`, `"pipeline orchestrator started"`, and
`"wallet runtime initialised"`—and records whether telemetry exporters were
configured, leaving a paper trail for readiness automation and runbooks.【F:rpp/node/src/lib.rs†L421-L521】【F:rpp/node/src/lib.rs†L523-L538】 The tracing
initialiser mirrors those attributes inside a `node.telemetry.init` span so
collectors and dashboards can confirm that OTLP was enabled (and which
endpoints were used) for the active runtime mode.【F:rpp/node/src/lib.rs†L1134-L1259】

### OTLP exporter configuration

`[rollout.telemetry]` in `node.toml` is the canonical source of truth. It
validates endpoints, buffer sizing, sampling ratios, TLS bundles, and drop
warnings before the runtime attempts to start exporters.【F:config/node.toml†L43-L54】【F:rpp/runtime/config.rs†L1736-L1809】 The new exporter builder derives both
gRPC and HTTP endpoints, normalises Bearer tokens, and reuses TLS assets across
metrics and traces so operators only need to supply a single credential
bundle.【F:rpp/runtime/telemetry/exporter.rs†L18-L133】【F:rpp/runtime/telemetry/exporter.rs†L162-L218】 Metrics exporters require the HTTP endpoint; when it is
missing or telemetry is disabled the runtime keeps the instruments but reports
the degradation through the `telemetry` log target instead of silently
dropping data.【F:rpp/runtime/telemetry/metrics.rs†L31-L70】

Tracing uses bounded queues whose sizes, batch policies, and sampling ratios are
fully configurable; the builder applies the validated queue settings and picks a
sampler that honours the requested ratio (including explicit on/off
states).【F:rpp/runtime/telemetry/exporter.rs†L90-L120】 The runtime advertises the
resolved OTLP and metrics endpoints in both logs and the `node.telemetry.init`
span so operators can verify that overrides or configuration profiles took
effect.【F:rpp/node/src/lib.rs†L1134-L1259】

### Startup probes & health endpoints

Expose `/health/live` for liveness and `/health/ready` for readiness in your
orchestrator; both endpoints are served by the RPC layer and reflect the active
runtime pipelines (node, wallet, orchestrator). The legacy `/health` endpoint is
preserved for smoke tests but does not expose failure states, so migrate
automation to the new probes where possible.【F:rpp/rpc/api.rs†L512-L583】

## Port & Endpoint Usage

Validate connectivity before promoting builds:

- **Node RPC.** Defaults to `127.0.0.1:7070`; expose this port through your
  ingress when external operators require access.【F:config/node.toml†L3-L23】
- **P2P gossip.** Listens on `/ip4/0.0.0.0/tcp/7600` and must be reachable by
  other validators; security groups should allow inbound TCP 7600.【F:config/node.toml†L25-L35】
- **Wallet RPC.** Standalone wallets bind `127.0.0.1:9090`; hybrid/validator
  profiles inherit the same default unless overridden in `wallet.toml`.【F:config/wallet.toml†L1-L18】
- **Telemetry OTLP.** Configure HTTPS endpoints for both metrics (`http_endpoint`)
  and traces (`endpoint`); missing URLs leave the exporter in log-only mode and
  surface warnings on startup.【F:rpp/runtime/telemetry/metrics.rs†L41-L48】

## Buffer & Backpressure Tuning

The OTLP exporters use bounded queues; overflows emit `telemetry` warnings when
`warn_on_drop` is enabled. Tune these parameters to match collector capacity and
network conditions:

- `trace_max_queue_size` and `trace_max_export_batch_size` govern the tracing
  batcher. Ensure the batch size never exceeds the queue size; validation
  enforces this constraint.【F:rpp/runtime/config.rs†L1736-L1765】
- `trace_sample_ratio` determines how many spans reach the exporter and is
  clamped between 0.0 and 1.0.【F:rpp/runtime/config.rs†L1761-L1775】
- `timeout_ms` and `retry_max` affect the OTLP client's resilience during
  collector outages; increase them when the pipeline traverses slow networks or
  distant collectors.【F:rpp/runtime/config.rs†L1738-L1746】【F:rpp/runtime/telemetry/exporter.rs†L68-L117】
- Keep `warn_on_drop = true` so queue pressure is surfaced via logs; the runtime
  emits warnings whenever metrics export is disabled or drops begin.【F:rpp/runtime/config.rs†L1748-L1775】【F:rpp/runtime/telemetry/metrics.rs†L41-L48】

## Release Channels & Feature Gating

1. **Promote builds through rollout channels.** Nodes advertise their rollout
   channel at start-up, so stage binaries through `development → testnet →
   canary → mainnet` and use the status endpoint to confirm the active channel
   after deployment.【F:rpp/runtime/node.rs†L4817-L4827】【F:README.md†L60-L95】
2. **Toggle blueprint capabilities with feature gates.** Keep pruning,
   recursive proofs, reconstruction, and consensus enforcement disabled until
   the deployment reaches the appropriate phase; these gates are controlled by
   the shared `rollout.feature_gates` map in node configuration.【F:config/node.toml†L29-L33】
3. **Protect RPC and proof limits.** Bound incoming proof artifacts with the
   `max_proof_size_bytes` limit and size mempool/identity queues to match the
   target environment before opening endpoints to the public.【F:config/node.toml†L3-L13】

## Node Configuration Checklist

1. **Persist data & proofs.** Mount persistent volumes for `data_dir`,
   `snapshot_dir`, and `proof_cache_dir` so reconstruction snapshots and cached
   recursive proofs survive restarts.【F:config/node.toml†L3-L7】
2. **Distribute genesis state.** Ensure the same genesis accounts, balances,
   and stakes are shipped to every validator; mismatches will prevent
    state-transition proofs from verifying.【F:config/node.toml†L45-L51】
3. **Calibrate reputation tiers.** Tune `reputation.tier_thresholds` to match
   the promotion/demotion policy for your environment; higher values slow tier
   ascension while lower values welcome new validators faster.【F:config/node.toml†L39-L43】【F:rpp/runtime/config.rs†L40-L204】
4. **Run storage migrations prior to rollout.** Execute the storage migration
   tooling documented in [MIGRATION.md](../MIGRATION.md) against production data
   before switching binaries to guarantee the RocksDB schema matches the proof
   bundle format.【F:README.md†L96-L107】
5. **Throttle gossip explicitly.** Adjust `p2p.gossip_rate_limit_per_sec` to cap
   how many messages a peer may forward every second and set
   `p2p.replay_window_size` to the number of recent digests tracked by the
   replay protector. Higher limits improve throughput but reduce abuse
   protection; lower limits penalise bursty peers sooner. The runtime clamps
   both fields to be greater than zero and applies them when constructing the
   libp2p `RateLimiter` and `ReplayProtector`.【F:config/node.toml†L26-L33】【F:rpp/runtime/config.rs†L20-L87】【F:rpp/runtime/node_runtime/network.rs†L19-L126】【F:rpp/p2p/src/swarm.rs†L482-L726】

## Mempool Retention & Operations

1. **Understand queue boundaries.** Transaction, identity, and consensus vote
   submissions are buffered in per-type `VecDeque`s that are re-created empty on
   every node startup, so no pending items survive a restart.【F:rpp/runtime/node.rs†L489-L506】
   Each queue enforces `mempool_limit`; once the limit is reached new entries
   are rejected rather than evicting older ones, and duplicate submissions are
   ignored.【F:rpp/runtime/node.rs†L1743-L1755】【F:rpp/runtime/node.rs†L1839-L1858】【F:rpp/runtime/node.rs†L1879-L1888】
   Configuration validation also prevents operators from setting this limit to
   zero.【F:rpp/runtime/config.rs†L170-L181】
2. **FIFO draining during block production.** When a validator assembles a
   block, the runtime pulls transactions and identities from the front of their
   queues up to the configured per-block caps, guaranteeing oldest-first
   inclusion and leaving any overflow for future blocks.【F:rpp/runtime/node.rs†L2533-L2556】
   Votes are drained for the targeted height/hash whenever a round is finalised,
   ensuring only matching votes are removed and later rounds retain their queued
   messages.【F:rpp/runtime/node.rs†L2418-L2431】【F:rpp/runtime/node.rs†L2639-L2670】【F:rpp/runtime/node.rs†L2855-L2879】
3. **Tune queue depth deliberately.** Size `mempool_limit` relative to
   `max_block_transactions` and `max_block_identity_registrations` so that the
   node can absorb expected bursts without hitting the hard rejection path. The
   default limit of 8,192 works well for moderate throughput but validators can
   scale it up (at the cost of more RAM) or down (for constrained hardware) via
   `node.toml`; the loader validates and persists the change automatically.【F:config/node.toml†L3-L23】【F:rpp/runtime/config.rs†L40-L228】
   Because vote queues share the same limit, environments with large validator
   sets should reserve headroom for vote storms triggered by round restarts.
   Operators can also rebalance inclusion pressure between backlog age and fee
   contribution by adjusting the `queue_weights.priority`/`queue_weights.fee`
   sliders (which must sum to 1.0) and monitoring the exposed weights via the
   mempool status RPC; in bursty workloads a 60/40 split keeps latency in check
   while still rewarding high-fee submissions.【F:config/node.toml†L17-L23】【F:rpp/runtime/config.rs†L207-L256】【F:rpp/runtime/node.rs†L124-L140】【F:rpp/rpc/api.rs†L515-L563】【F:rpp/rpc/api.rs†L840-L880】
4. **Gate features to match readiness.** Recursive-proof verification for
   transactions and identities, and consensus enforcement for votes, are guarded
   by rollout feature flags. Disable them in lower environments when proofs are
   not yet available to avoid systematic rejections; re-enable as soon as the
   production circuits are validated.【F:config/node.toml†L29-L33】【F:rpp/runtime/node.rs†L1718-L1761】【F:rpp/runtime/node.rs†L1862-L1888】
5. **Monitor `/status/mempool`.** The RPC surface exposes a structured view of
   queued entries—including hashes, senders, and queue sizes—via the
   `/status/mempool` endpoint. Use it for dashboards and alerts that detect when
   queues approach the configured limit, or when identities and votes stop being
   drained.【F:rpp/rpc/api.rs†L510-L536】【F:rpp/runtime/node.rs†L2160-L2230】

Operators should combine these controls with routine snapshots of queue depth so
they can resize the mempool proactively and diagnose stuck items before they
threaten block production.

## Telemetry & Metrics

### Metric surfaces

- **Node runtime.** `RuntimeMetrics` exposes consensus, storage, networking,
  and reputation signals across histograms and counters. Operators should wire
  `rpp.runtime.consensus.*`, `rpp.runtime.storage.*`,
  `rpp.runtime.rpc.*`, and `rpp.runtime.reputation.penalties` into dashboards to
  observe block production, WAL pressure, RPC health, and slashing
  outcomes.【F:rpp/runtime/telemetry/metrics.rs†L63-L205】【F:rpp/runtime/telemetry/metrics.rs†L214-L319】
- **Proof systems.** Proof generation and verification telemetry is partitioned
  by backend so production STWO, experimental Plonky3, and mock flows can be
  monitored separately. Alert on spikes in `rpp.runtime.proof.*` and
  `rpp_stark_*` metrics to catch failing provers or verifier regressions before
  they impact consensus.【F:rpp/runtime/telemetry/metrics.rs†L360-L453】
- **Pipeline orchestrator.** Wallet pipelines emit latency histograms, error and
  gossip counters, leader rotation totals, active flow gauges, and per-stage
  telemetry summaries that can be streamed via the RPC surface for
  dashboards.【F:rpp/runtime/orchestration.rs†L300-L391】【F:rpp/runtime/orchestration.rs†L393-L460】【F:rpp/runtime/orchestration.rs†L716-L758】

### Allowed labels & cardinality controls

- Runtime metrics rely on enumerated label sets—`ConsensusStage`,
  `WalletRpcMethod`, `RpcMethod`, `RpcResult`, `WalFlushOutcome`, and proof
  enums—to bound label cardinality and keep collectors efficient. These enums
  drive the `MetricLabel` trait helpers that inject exactly one string label per
  dimension.【F:rpp/runtime/telemetry/metrics.rs†L560-L749】【F:rpp/runtime/telemetry/metrics.rs†L884-L969】
- Dynamic attributes are deliberately scoped: consensus round metrics only attach
  `height`, `round`, and (when relevant) a leader string; failed vote counters
  expose a bounded `reason`, and reputation penalties label events with a single
  operator-provided tag. Treat these values as safe for cardinality-based
  alerting but continue to monitor for unexpected strings in the structured log
  feed.【F:rpp/runtime/telemetry/metrics.rs†L214-L319】【F:rpp/runtime/telemetry/metrics.rs†L320-L359】
- Pipeline metrics reuse fixed label keys (`stage`, `reason`, `outcome`,
  `source`) when emitting counters and histograms so dashboards can pivot by
  stage without unbounded fan-out.【F:rpp/runtime/orchestration.rs†L320-L385】

### Baseline dashboards & runbooks

- The dashboard blueprints under `docs/dashboards/` map each metric to Grafana
  panels and include coverage for consensus, wallet, storage, and proof
  telemetry. Use them as the starting point when wiring collectors to your
  visualisation stack.【F:docs/dashboards/README.md†L1-L52】
- Pair dashboards with the observability runbook, which documents how to respond
  to exporter degradation, stalled blocks, and WAL issues using the metrics and
  spans described above.【F:docs/runbooks/observability.md†L1-L100】

## Health Probes

1. **Expose HTTP probes to your orchestrator.** Route Kubernetes or Nomad
   liveness checks to `/health/live` and readiness checks to `/health/ready`;
   liveness calls hit `NodeHandle::node_status` so they fail once the runtime
   stops, while readiness reflects the active runtime mode (node, wallet,
   orchestrator).【F:rpp/rpc/api.rs†L512-L558】
2. **Retain `/health` for legacy smoke tests.** The existing endpoint still
   returns the runtime role and address but does not surface failure states, so
   migrate automation to the explicit probe paths to catch startup and shutdown
   transitions.【F:rpp/rpc/api.rs†L559-L583】

## Observability Dashboards

1. **Rollout status.** Dashboards should surface `release_channel`, feature
   gate toggles, and telemetry runtime status from the `/status/rollout` API so
   operators can validate staged rollouts at a glance.【F:README.md†L60-L95】
2. **Proof pipeline health.** Alert when telemetry snapshots stall (no new
   height) or when proof cache utilization exceeds capacity, since recursive
   proofs are required for block production.【F:rpp/node/src/pipeline/mod.rs†L73-L104】【F:rpp/node/src/lib.rs†L743-L818】
3. **Verifier health.** Track `verifier_metrics.per_backend` counts and
   cumulative durations to catch spikes in rejection rates or verification
   latency regressions; notify operators when any backend reports sustained
   failures or multi-second runtimes.【F:rpp/runtime/node.rs†L220-L238】【F:rpp/proofs/proof_system/mod.rs†L150-L260】
4. **Consensus availability.** Track uptime/consensus proof counts per block in
   telemetry to ensure validators continue submitting the expected auxiliary
   proofs; deviations indicate failing wallets or byzantine participants.【F:rpp/runtime/node.rs†L535-L610】
5. **Pipeline latency & error budget.** Import
   `docs/observability/pipeline_grafana.json` to chart stage percentile
   latency, gossip failures, and leader rotations directly from the Prometheus
   metrics exposed by the orchestrator.【F:docs/observability/pipeline_grafana.json†L1-L52】

## Deployment Guardrails

1. **Blueprint parity validation.** Before enabling new channels, verify wallets
   and nodes agree on the `ProofSystemKind` and that verifier registries accept
   the proofs being generated; mismatches block block import.【F:rpp/proofs/proof_system/mod.rs†L1-L118】
2. **Smoke tests after rollout.** Submit a transaction, run identity genesis,
   and confirm the recursive proof commitment advances to detect circuit or
   witness regressions immediately after deployment.【F:rpp/proofs/stwo/prover/mod.rs†L200-L460】【F:prover/prover_stwo_backend/src/official/verifier/mod.rs†L243-L377】
3. **Telemetry regression alerts.** Fail the deployment if telemetry snapshots
   stop at the prior height or if encoded payloads cannot be emitted; both
   symptoms surface via the telemetry loop warnings.【F:rpp/runtime/node_runtime/node.rs†L2082-L2116】
4. **Stage the storage recovery plan.** Keep the Firewood recovery runbook
   handy so operators can replay WALs, restore snapshots, and verify pruning
   checkpoints when a node requires manual repair.【F:docs/storage_recovery.md†L1-L53】

## Reputation & Slashing Audit Trails

1. **Collect signed JSONL exports.** The runtime now persists
   `/audits/reputation/*.jsonl` and `/audits/slashing/*.jsonl` files beneath the
   node `data_dir`, rotating them every 24 hours and retaining the newest 30
   files per stream. Each record includes a deterministic `evidence_hash` and an
   Ed25519 `signature` produced with the node keypair so operators can prove the
   node’s view of any reputation change or slashing decision.【F:rpp/runtime/node.rs†L608-L763】【F:rpp/storage/ledger.rs†L88-L131】【F:rpp/storage/ledger.rs†L390-L436】
2. **Provide on-demand access.** Two new RPC endpoints expose the most recent
   records without requiring direct filesystem access:
   `/observability/audits/reputation?limit=N` and
   `/observability/audits/slashing?limit=N`. Both default to the latest 200
   events (capped at 1,000) and return the signed payloads as delivered in the
   export stream.【F:rpp/rpc/api.rs†L1088-L1135】
3. **Meet compliance retention targets.** Downstream archival systems should
   ingest the JSONL exports before the node prunes older files. Because each
   entry carries the node signature and a reproducible evidence hash,
   environments that require non-repudiation can verify authenticity without
   re-deriving state from block data.【F:rpp/runtime/node.rs†L330-L370】【F:rpp/runtime/node.rs†L3830-L3890】

## State-Sync Interfaces

1. **Subscribe to light-client heads via SSE.** The `/state-sync/head/stream`
   endpoint upgrades to Server-Sent Events once authentication succeeds,
   returning the current light-client head and subsequent updates. Heartbeat
   comments (`:hb`) are emitted every 10 seconds; clients should treat a missing
   heartbeat as a cue to reconnect with exponential backoff.
2. **Fetch state snapshots chunk-by-chunk.** The `/state-sync/chunk/:id`
   endpoint emits JSON metadata alongside a base64 payload and SHA-256 checksum
   for the requested chunk. It validates the requested index against the active
   state-sync session and returns `400` for out-of-range values, `404` when a
   chunk is missing, or `503` while no session is available. The legacy
   `/state-sync/chunk?index=` route remains available for older clients.

With these guardrails, operators can ship the blueprint implementation safely
and maintain real-time visibility into proof generation, verification, and
network health.
