# Deployment & Observability Playbook

This playbook translates the blueprint's phase 8 requirements into actionable
runbooks for bringing the STWO/Plonky3 chain online and keeping it observable in
production.

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

1. **Enable telemetry sampling.** Flip `rollout.telemetry.enabled` and tune the
   sampling interval to emit snapshots with node, consensus, and mempool
   metrics.【F:config/node.toml†L35-L37】【F:src/config.rs†L141-L171】
2. **Stream snapshots to your collector.** Set `rollout.telemetry.endpoint`
   (empty means log-only) and confirm the async telemetry task is running; the
   node spawns a background loop that periodically publishes encoded telemetry
   payloads and tracks the last height observed.【F:src/node.rs†L455-L517】
3. **Scrape structured logs.** Configure log aggregation to capture the
   `telemetry` target; payloads contain release channel, active feature gates,
   and health snapshots for dashboards, including the live `timetoke_params`
   (minimum window, accrual cap, decay cadence) for uptime tuning.【F:rpp/runtime/node.rs†L208-L214】【F:rpp/runtime/node.rs†L1207-L1218】
4. **Track VRF participation.** The node status snapshot includes `vrf_metrics`
   with submission counts, accepted validators, rejection totals, and fallback
   usage so dashboards can alert on declining VRF participation or repeated
   fallback elections.【F:src/node.rs†L57-L125】【F:src/node.rs†L815-L836】

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
3. **Consensus availability.** Track uptime/consensus proof counts per block in
   telemetry to ensure validators continue submitting the expected auxiliary
   proofs; deviations indicate failing wallets or byzantine participants.【F:src/node.rs†L489-L517】

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

With these guardrails, operators can ship the blueprint implementation safely
and maintain real-time visibility into proof generation, verification, and
network health.
