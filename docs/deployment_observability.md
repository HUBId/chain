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

## Observability Dashboards

1. **Rollout status.** Dashboards should surface `release_channel`, feature
   gate toggles, and telemetry runtime status from the `/status/rollout` API so
   operators can validate staged rollouts at a glance.【F:README.md†L60-L95】
2. **Proof pipeline health.** Alert when telemetry snapshots stall (no new
   height) or when proof cache utilization exceeds capacity, since recursive
   proofs are required for block production.【F:src/node.rs†L489-L517】【F:src/node.rs†L823-L827】
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

With these guardrails, operators can ship the blueprint implementation safely
and maintain real-time visibility into proof generation, verification, and
network health.
