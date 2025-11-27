# Pruning runbook

Use this playbook when pruning automation needs to be adjusted or invoked manually. It covers
feature gate toggles, runtime overrides, ad-hoc snapshot jobs, and how to confirm the receipts
returned by the service. Pair it with the [startup](startup.md),
[observability](observability.md), and [pruning operations](pruning_operations.md) runbooks for
post-change validation and ongoing monitoring.【F:rpp/node/src/telemetry/pruning.rs†L25-L116】

## 1. Enable or pause the pruning service

1. **Verify feature gates.** Ensure the node configuration keeps the pruning gate enabled and the
   pruning service unpaused. Operators typically edit `config/node.toml` (or the derived runtime
   config) to confirm:
   - `rollout.feature_gates.pruning = true`
   - `[pruning].emergency_pause = false`
   - Set cadence/retention defaults that match the deployment policy (`cadence_secs`,
     `retention_depth`).【F:config/node.toml†L23-L29】【F:config/node.toml†L73-L79】
2. **Pause or resume without redeploying.** When invoking the runtime from the CLI, use the
   pruning overrides to momentarily pause or resume automation:
   - Pause on startup: `rpp-node node --pruning-pause`
   - Resume on startup: `rpp-node node --pruning-resume`
   These flags map to the pruning overrides exposed by the runtime (`--pruning-cadence-secs` and
   `--pruning-retention-depth` are also available).【F:rpp/node/src/config.rs†L3-L50】
3. **Confirm state.** After the node is up, list the active feature gates in the logs and query the
   pruning service status stream to verify `paused=false`. The worker logs
   `"pruning service started"` with the active cadence, pause flag, and retention depth on boot, so
   operators should see the updated values immediately.【F:rpp/node/src/services/pruning.rs†L100-L158】【F:rpp/node/src/services/pruning.rs†L139-L145】

## 2. Adjust cadence and retention

1. **Update configuration defaults** when the policy changes. Modify `[pruning].cadence_secs` and
   `[pruning].retention_depth` in the node configuration and redeploy the runtime to persist the
   new baseline.【F:config/node.toml†L23-L29】
2. **Apply temporary overrides** via the CLI in emergency responses:
   - `cargo run -p rpp-chain -- validator --pruning-cadence-secs <seconds>`
   - `cargo run -p rpp-chain -- validator --pruning-retention-depth <blocks>`
   These flags take effect before the runtime spawns background services. Requests with zero values
   are rejected and the runtime keeps the previous settings, so double-check inputs before
   restarting.【F:rpp/node/src/config.rs†L5-L49】【F:rpp/node/src/lib.rs†L1408-L1423】
3. **Validate the new schedule.** Tail the pruning service logs for the next scheduled run to ensure
   the cadence matches expectations, and confirm the service retained the overrides by calling the
   job-status endpoint (see §4).【F:rpp/node/src/services/pruning.rs†L100-L176】【F:rpp/node/src/services/pruning.rs†L314-L320】

## 3. Trigger on-demand pruning work

1. **Snapshot rebuild (full rescan).** Issue a POST to the RPC endpoint to enqueue a rebuild of the
   persisted snapshot set. Export the bearer token from the operator guide’s configuration-managed
   secret (preferred) or the CLI helper into `RPP_RPC_TOKEN`, then include it in the request:
   ```bash
   curl -sS -X POST \
     -H "Authorization: Bearer $RPP_RPC_TOKEN" \
     http://<rpc-host>:<port>/snapshots/rebuild
   ```
   The handler requires the pruning service to be configured; otherwise it returns `503` with an
   error explaining that pruning is unavailable.【F:rpp/rpc/api.rs†L1250-L1253】【F:rpp/rpc/tests/pruning.rs†L91-L138】
2. **Snapshot capture (single run).** Trigger an immediate pruning job without clearing history.
   Use the same bearer token requirements as above:
   ```bash
   curl -sS -X POST \
     -H "Authorization: Bearer $RPP_RPC_TOKEN" \
     http://<rpc-host>:<port>/snapshots/snapshot
   ```
   Both RPCs enqueue work through the pruning service handle, which validates the request and
   returns a receipt. Calls that pass validation respond with `accepted=true`; invalid cadence or
   retention overrides surface as `400 Bad Request` with details propagated from the service.
   【F:rpp/node/src/services/pruning.rs†L259-L303】
3. **Cancel gracefully.** If a rebuild or snapshot run needs to stop mid-flight, call the new
   cancellation endpoint instead of killing the node:
   ```bash
   rpp-node validator snapshot cancel-pruning --config config/validator.toml
   ```
   or send `POST /snapshots/cancel` with the bearer token to receive a cancellation receipt.
   The worker logs the request, bumps `rpp.node.pruning.cancellations_total`, and marks the
   cycle as `result="cancelled"` while keeping persisted plans intact for the next run.【F:rpp/chain-cli/src/lib.rs†L255-L265】【F:rpp/rpc/src/routes/state.rs†L1-L26】【F:rpp/node/src/services/pruning.rs†L321-L370】【F:rpp/node/src/telemetry/pruning.rs†L25-L124】
3. **Authenticated tooling.** Automation or wrapper CLIs must include the RPC bearer token described
   in the [`rpp-node` operator guide](../rpp_node_operator_guide.md) so that the POST requests above pass
   gateway authentication and rate limiting. Reuse the guide’s credential rotation and diagnostics
   steps if the calls return `401` or `429`.【F:docs/rpp_node_operator_guide.md†L1-L88】

## 4. Interpret receipts and watch job status

1. **Receipt fields.** Both snapshot endpoints return JSON payloads containing `accepted` and an
   optional `detail`. A rejected receipt always includes a descriptive `detail` string (for example,
   cadence too small) so operators can triage without opening logs.【F:rpp/storage/pruner/receipt.rs†L5-L37】【F:rpp/storage/pruner/receipt.rs†L41-L70】
2. **Check active work.** Poll `GET /snapshots/jobs` to inspect the most recent `PruningJobStatus`.
   This endpoint mirrors the pruning status watch inside the runtime, exposing persisted paths,
   missing heights, and other diagnostics used by the worker loop.【F:rpp/rpc/api.rs†L1250-L1253】【F:rpp/runtime/node.rs†L3200-L3219】
3. **Validate distribution.** When consumers report stale state-sync data, trigger `POST /p2p/snapshots`
   against an affected node to start a snapshot stream from a healthy peer and monitor the returned
   session via `GET /p2p/snapshots/<session>` until `verified=true` or an error is reported.【F:rpp/rpc/src/routes/p2p.rs†L16-L102】【F:docs/network/snapshots.md†L24-L120】 Resume attempts that fall behind the
   latest acknowledgement or skip ahead of the advertised totals return `500` responses containing the
   `SnapshotVerification` reason; treat them as configuration drift between peers and restart from the
   most recent offsets before escalating.【F:docs/network/snapshots.md†L24-L44】
4. **Cross-check telemetry.** When a job runs, the worker updates internal watchers and emits the
   status to the snapshots gossip topic. Confirm that downstream consumers (dashboards, recovery
   tooling) ingest the plan before closing the incident.【F:rpp/node/src/services/pruning.rs†L305-L320】【F:rpp/runtime/node.rs†L3200-L3219】
5. **Track long-running jobs.** Use the pruning observability dashboard to check
   `rpp.node.pruning.keys_processed` against `missing_heights` and watch
   `rpp.node.pruning.time_remaining_ms` for a rising completion estimate. If the
   estimated time exceeds the cadence window or `failures_total` increments with
   `error="storage"`, escalate using the stalled/slow alerts documented in the
   observability guide.【F:rpp/node/src/telemetry/pruning.rs†L31-L97】
   The ETA reported in CLI health checks and `time_remaining_ms` comes from the
   most recent pruning cycle: the worker divides the last cycle duration by the
   number of proofs written to determine per-key throughput, multiplies that
   pace by the remaining backlog (`missing_heights - stored_proofs`), and drops
   the estimate when no proofs were produced so dashboards do not render stale
   values.【F:rpp/node/src/services/pruning.rs†L135-L191】【F:rpp/runtime/node.rs†L720-L789】【F:rpp/node/src/telemetry/pruning.rs†L102-L180】

## 5. Post-change verification

1. Confirm disk usage stabilizes in the pruning snapshot and proof directories after the job
   completes.
2. Record the receipt details and job-status output in the shift hand-off log for traceability.
3. If the service reports repeated failures, escalate using the observability runbook and collect the
   relevant logs and receipts for investigation.
