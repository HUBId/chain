# Deployment & Observability Playbook

This playbook translates the blueprint's phase 8 requirements into actionable
runbooks for bringing the STWO/Plonky3 chain online and keeping it observable in
production. Pair it with the [Validator Quickstart](./validator_quickstart.md)
for provisioning steps, the [Validator Troubleshooting](./validator_troubleshooting.md)
runbook for incident response, and the
[RPC CLI Operator Guide](./rpc_cli_operator_guide.md) for authentication,
throttling, and recovery procedures that apply to operator-driven RPC
workflows.

## Release Channels & Feature Gating

1. **Promote builds through rollout channels.** Nodes advertise their rollout
   channel at start-up, so stage binaries through `development → testnet →
   canary → mainnet` and use the status endpoint to confirm the active channel
   after deployment.【F:src/node.rs†L455-L467】【F:README.md†L60-L95】
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
4. **Run storage migrations prior to rollout.** Execute `cargo run -- migrate`
   against production data before switching binaries to guarantee the RocksDB
   schema matches the proof bundle format.【F:README.md†L96-L107】
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

1. **Enable telemetry sampling.** Flip `rollout.telemetry.enabled`, tune the
   sampling interval, and adjust `trace_sample_ratio` if you only need a subset
   of spans for long-term storage. Increase the queue and batch sizes when the
   collector runs behind to avoid drops.【F:rpp/runtime/config.rs†L1632-L1707】
2. **Stream snapshots to your collector.** Set both OTLP endpoints
   (`endpoint` for gRPC traces and `http_endpoint` for metrics) and, if needed,
   point `grpc_tls`/`http_tls` at your collector CA to enforce TLS. The runtime
   spawns bounded exporters that warn when items are dropped so you can expand
   capacity before losing visibility.【F:rpp/runtime/telemetry/exporter.rs†L21-L210】【F:rpp/runtime/telemetry/metrics.rs†L30-L58】
3. **Scrape structured logs.** Configure log aggregation to capture the
   `telemetry` target; payloads contain release channel, active feature gates,
   and health snapshots for dashboards, including the live `timetoke_params`
   (minimum window, accrual cap, decay cadence) for uptime tuning.【F:rpp/runtime/node.rs†L208-L214】【F:rpp/runtime/node.rs†L1207-L1218】
4. **Subscribe to timetoke deltas.** The meta gossip channel now publishes
   `meta_timetoke` payloads alongside snapshot topics so operators can audit the
   recorded balances and their commitment root in near real time; forward these
   JSON blobs to monitoring backends that compare the advertised root with local
   ledger state.【F:rpp/runtime/node.rs†L3548-L3577】【F:rpp/runtime/node_runtime/node.rs†L154-L192】
5. **Track VRF participation.** The node status snapshot includes `vrf_metrics`
   with submission counts, accepted validators, rejection totals, and fallback
   usage so dashboards can alert on declining VRF participation or repeated
   fallback elections.【F:src/node.rs†L57-L125】【F:src/node.rs†L815-L836】
6. **Monitor handshake telemetry.** Each libp2p Noise handshake now emits
   `telemetry.handshake` events with the remote agent string, tier, and ZSI. A
   matching warning is logged on signature or VRF validation failures so that
   operators can detect nodes announcing inconsistent VRF payloads or stale
   metadata during admission.【F:rpp/p2p/src/swarm.rs†L248-L316】
7. **Forward tracing spans to OTLP.** Enabling `rollout.telemetry.endpoint`
   (or the `--telemetry-endpoint` CLI override) wires a gRPC OTLP exporter into
   the tracing subscriber; optional secrets can be supplied via
   `telemetry_auth_token` or the environment variables
   `RPP_NODE_OTLP_AUTH_TOKEN`, `RPP_NODE_OTLP_TIMEOUT_MS`, and
   `RPP_NODE_OTLP_ENDPOINT`. Gossip, consensus, and proof paths now emit spans
   that ship to the configured collector, and
   `scripts/smoke_otlp_export.sh --mode validator --binary ./target/release/rpp-node`
   spins up a local OpenTelemetry Collector to verify that the selected runtime
   exported the expected signal (defaulting to `node.telemetry.init`). Pass
   `--mode hybrid` or `--mode wallet` to exercise the other binaries and
   `--expect` when you need to assert on a different span name.【F:rpp/node/src/lib.rs†L35-L111】【F:rpp/runtime/node.rs†L610-L963】【F:rpp/runtime/node_runtime/node.rs†L836-L1356】【F:scripts/smoke_otlp_export.sh†L1-L190】【F:scripts/otel-collector-config.yaml†L1-L19】
8. **Maintain wallet telemetry parity.** Hybrid and validator profiles enable
   Electrs cache and tracker telemetry so wallet consumers inherit the same
   visibility targets as the node runtime. When the wallet runs standalone,
   update `electrs.cache.telemetry` and
   `electrs.tracker.telemetry_endpoint` to keep forwarding the same signals the
   validator dashboards expect.【F:config/wallet.toml†L9-L31】【F:rpp/runtime/config.rs†L1269-L1313】
9. **Track pipeline health metrics.** The orchestrator exports
   `pipeline_stage_latency_ms`, `pipeline_errors_total`,
   `pipeline_gossip_events_total`, and
   `pipeline_leader_rotations_total` while exposing an aggregated
   `/wallet/pipeline/telemetry` snapshot for dashboards. Run
   `scripts/ci/pipeline_observability.sh` alongside deployments to smoke-test
   the telemetry feed.【F:rpp/runtime/orchestration.rs†L160-L287】【F:rpp/runtime/orchestration.rs†L747-L940】【F:rpp/rpc/api.rs†L1833-L1876】【F:scripts/ci/pipeline_observability.sh†L1-L9】

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
   proofs are required for block production.【F:src/node.rs†L489-L517】【F:src/node.rs†L823-L827】
3. **Verifier health.** Track `verifier_metrics.per_backend` counts and
   cumulative durations to catch spikes in rejection rates or verification
   latency regressions; notify operators when any backend reports sustained
   failures or multi-second runtimes.【F:rpp/runtime/node.rs†L220-L238】【F:rpp/proofs/proof_system/mod.rs†L150-L260】
4. **Consensus availability.** Track uptime/consensus proof counts per block in
   telemetry to ensure validators continue submitting the expected auxiliary
   proofs; deviations indicate failing wallets or byzantine participants.【F:src/node.rs†L489-L517】
5. **Pipeline latency & error budget.** Import
   `docs/observability/pipeline_grafana.json` to chart stage percentile
   latency, gossip failures, and leader rotations directly from the Prometheus
   metrics exposed by the orchestrator.【F:docs/observability/pipeline_grafana.json†L1-L52】

## Deployment Guardrails

1. **Blueprint parity validation.** Before enabling new channels, verify wallets
   and nodes agree on the `ProofSystemKind` and that verifier registries accept
   the proofs being generated; mismatches block block import.【F:src/proof_system/mod.rs†L1-L130】
2. **Smoke tests after rollout.** Submit a transaction, run identity genesis,
   and confirm the recursive proof commitment advances to detect circuit or
   witness regressions immediately after deployment.【F:src/stwo/prover/mod.rs†L210-L448】【F:src/stwo/verifier/mod.rs†L249-L360】
3. **Telemetry regression alerts.** Fail the deployment if telemetry snapshots
   stop at the prior height or if encoded payloads cannot be emitted; both
   symptoms surface via the telemetry loop warnings.【F:src/node.rs†L478-L517】
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
