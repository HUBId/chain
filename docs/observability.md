# Observability Chaos Drills

## OTLP exporter failure drill

The `telemetry_otlp_exporter_failures_surface_alerts` integration test launches a
validator node with telemetry enabled, forces both the OTLP/HTTP metric exporter
and the OTLP/gRPC span exporter to fail during initialisation, and verifies that
runtime behaviour degrades gracefully instead of aborting the process.

### Failure injection

The drill points both exporters at local endpoints and configures their TLS
material to reference directories rather than readable files. The configuration
passes validation but the exporters fail while loading their certificates. The
runtime now detects this condition, switches the exporters into a local-only
mode, and keeps the node running.【F:tests/observability_otlp_failures.rs†L24-L109】

### Operator signals

When the failure is detected the node emits structured telemetry warnings for
both sinks and records a counter per exporter:

- Logs: `failed to initialise OTLP metric exporter; metrics will only be logged
  locally` and `failed to initialise OTLP span exporter; traces will not be
  exported`. Both events carry the `telemetry` target alongside `sink` and
  `phase` attributes.【F:rpp/node/src/lib.rs†L193-L207】【F:rpp/node/src/lib.rs†L256-L267】
- Metric: `telemetry_otlp_failures_total{sink="metrics",phase="init"}` and
  `telemetry_otlp_failures_total{sink="traces",phase="init"}` increment once per
  exporter failure.【F:rpp/node/src/lib.rs†L88-L91】【F:tests/observability_otlp_failures.rs†L111-L132】

Nodes configured with `rollout.telemetry.failover_enabled = true` also record a
secondary series whenever the runtime falls back from the primary OTLP
endpoints to the configured secondary ones. Both exporters emit
`telemetry_otlp_failures_total{phase="init_failover"}` when they retry with the
secondary endpoints so dashboards and alerts can distinguish between an outright
failure and a successful failover.【F:rpp/node/src/lib.rs†L1650-L1711】【F:tests/observability_otlp_failures.rs†L109-L212】
Startup validation enforces that failover deployments provide secondary OTLP
endpoints and a non-empty `auth_token` for the backup collector; missing fields
produce configuration exit code `2` so operators can correct the credentials
before the node starts processing traffic.【F:rpp/runtime/config.rs†L3885-L3937】【F:tests/node_lifecycle/startup_errors.rs†L75-L139】

The Prometheus scrape contains both series, allowing dashboards and automated
checks to confirm that exporter failures have been observed.

### Proof-verification log fields

Consensus validation and STARK verification logs now share a common set of
labels so operators and tooling can pivot between successes and failures:

- `peer_id`: libp2p peer that delivered the block or proof bundle ("unknown"
  when the source is not networked, such as locally generated proofs).
- `height` / `slot`: consensus height and round/slot associated with the
  verification attempt. These fields remain present even when the values are
  unknown, simplifying log parsing.
- `backend`: proof system used for verification (for example `rpp-stark` or
  `stwo`).
- `proof_id`: stable identifier for the proof under test (block hash for
  consensus proofs, transaction or request hash for other circuits).
- `circuit`: circuit family being checked (`state`, `pruning`, `recursive`,
  `consensus`, or other verification circuits such as `transaction`).

Both success and failure events emit the full field set on the `proofs` and
`telemetry` targets so dashboards and log pipelines can filter consistently
across backend types.

### Alerting and recovery

The nightly workflow runs the chaos drill without blocking mainline merges and
publishes a warning alert (`OtlpExporterFailure`) whenever the counter increases
within a 15-minute window.【F:.github/workflows/nightly.yml†L1-L47】【F:docs/observability/alerts/telemetry.yaml†L1-L32】
Operators should investigate the structured logs to determine whether TLS
material, endpoint reachability, or collector availability triggered the issue.
Once the exporter configuration is corrected and a successful initialisation
occurs, the counter remains flat and the alert automatically clears.

### Chaos artifacts

The telemetry chaos harness writes every run to a timestamped directory under
`rpp/chain/artifacts/telemetry-chaos/<epoch-seconds>` (override with the
`TELEMETRY_CHAOS_ARTIFACT_DIR` environment variable).【F:tests/observability_otlp_failures.rs†L24-L176】
Each directory contains:

- `node.log`: combined stdout and stderr from the chaos node.【F:tests/observability_otlp_failures.rs†L99-L134】【F:tests/observability_otlp_failures.rs†L178-L216】
- `metrics.prom`: the Prometheus scrape retrieved after the exporters fail to
  start.【F:tests/observability_otlp_failures.rs†L59-L93】【F:tests/observability_otlp_failures.rs†L218-L248】
- `metrics_after_failover.prom`: the follow-up scrape collected after the
  runtime switches to the secondary endpoints, showing that failover counters
  stop incrementing once the secondary backend is in use.【F:tests/observability_otlp_failures.rs†L218-L280】
- `alert_payload.json`: the synthetic Alertmanager payload that summarises the
  firing `OtlpExporterFailure` alert for the captured metrics and records the
  resolved state once the secondary backend is healthy.【F:tests/observability_otlp_failures.rs†L136-L176】【F:tests/observability_otlp_failures.rs†L248-L276】

Retention: the harness keeps the latest 10 runs and prunes older ones after
each invocation. Override this limit with `TELEMETRY_CHAOS_MAX_RUNS=<count>` if
you need a larger local window.【F:tests/observability_otlp_failures.rs†L805-L897】 GitHub Actions
artifacts are stored for 10 days to mirror the on-disk retention window.【F:.github/workflows/nightly.yml†L95-L119】

Manual cleanup: remove all cached runs with `rm -rf rpp/chain/artifacts/telemetry-chaos`
or delete specific timestamped directories to reclaim space.

You can inspect the latest chaos output locally with:

```bash
ls rpp/chain/artifacts/telemetry-chaos
tail -n 50 rpp/chain/artifacts/telemetry-chaos/<run>/node.log
grep telemetry_otlp_failures_total rpp/chain/artifacts/telemetry-chaos/<run>/metrics.prom
jq . rpp/chain/artifacts/telemetry-chaos/<run>/alert_payload.json
```

CI automatically uploads the `telemetry-chaos` artifact bundle for every chaos
test invocation so responders can download and review the run without
reproducing it locally, even when the test succeeds.【F:.github/workflows/nightly.yml†L92-L112】

## OTLP exporter timeout and backpressure drill

The `telemetry_otlp_timeouts_backoff_and_buffer` chaos test holds both the
OTLP/HTTP and OTLP/gRPC collectors in a stalled state, forcing exporter
requests to time out until the collectors become responsive again. The
runtime’s global telemetry error handler logs every export error and uses the
OTLP client backoff to avoid hammering an unhealthy collector.【F:rpp/node/src/lib.rs†L80-L106】

- Logs: during the blackout the node emits `telemetry exporter error; will
  retry with exponential backoff`, confirming exporters are buffering and
  backing off instead of dropping the runtime.【F:tests/observability_otlp_failures.rs†L90-L181】
- Recovery: once the collectors start responding, the test waits for successful
  OTLP/HTTP and OTLP/gRPC exports and captures the Prometheus scrape alongside
  the alert payload used in the chaos artifact bundle.【F:tests/observability_otlp_failures.rs†L183-L263】

The nightly chaos workflow executes the entire OTLP failure suite (initial
startup failures, failover, and timeout recovery) so regressions in telemetry
backpressure or alerting surface without blocking day-to-day development.

## Consensus chaos drills

Nightly simnet jobs now run a consensus chaos preset (`consensus-chaos`) that
introduces leader delays, gossip drops, and temporary validator isolation. To
exercise the drill locally, call `cargo xtask test-simnet` or run a single
scenario via `cargo xtask simnet --profile consensus-chaos`. Artifacts live
under `target/simnet/consensus-chaos` and include:

- `summaries/consensus_chaos.json` and `summaries/consensus_chaos.csv` for
  propagation, recovery, and fault timelines.
- `summaries/chaos_alert.json`, a synthetic Alertmanager payload that flips to
  `status=firing` when propagation p95 exceeds the default 500 ms ceiling or
  when no resume events are recorded after a partition.
- `logs/` for node-level stdout/stderr during the chaos phases.

Operators should expect at least one `partition_start`/`partition_end` pair in
the summary faults list and resume latencies below 5 s. Nightly runs under both
Plonky3 and RPP-STARK feature sets; if the alert stub reports `status=firing`,
pull the corresponding `consensus-chaos` artifact bundle from the Actions run
and inspect resume timings and peer traffic skew before clearing the alert.

## Telemetry schema allowlist

Runtime metrics exported by the node are validated against an allowlist stored
at `telemetry/schema.yaml`. The schema enumerates every metric name and the set
of labels it may emit. `cargo xtask test-observability` (and the
`observability-metrics` CI workflow) run the `telemetry_schema` check to ensure
that the recorded metrics continue to match the schema. Any instrumentation
change that introduces a new metric or label must update the schema file in the
same pull request. Schema updates require review from the Observability/SRE
owners to confirm the new telemetry surfaces align with the documented
cardinality guarantees.

## Dashboard review and update process

Grafana dashboards are treated as versioned artifacts. Each export listed in
`docs/performance_dashboards.json` records the expected Grafana `version`, a
human-readable `version_tag`, and the SHA-256 checksum of the committed JSON.
CI reruns `scripts/verify_dashboard_manifest.py` to compare those expectations
against the repository and fails if any export changes without a manifest
update.

When you refresh a dashboard:

1. Pull the latest export from Grafana with `tools/perf_dashboard_check.sh --write`
   (requires `PERF_GRAFANA_URL` and `PERF_GRAFANA_API_KEY`).
2. Bump the corresponding `version_tag` in `docs/performance_dashboards.json`
   to match the Grafana revision or change ticket, and update the `sha256`
   field to the checksum of the new export.
3. Run `python3 scripts/verify_dashboard_manifest.py` to confirm the manifest
   matches the refreshed files and commit the manifest and JSON together.

## Telemetry alert response procedures

On-call engineers manage production telemetry alerts through Alertmanager and
PagerDuty. The steps below apply to every alert sourced from the
`telemetry` namespace (including dashboards fed by
`docs/observability/alerts/*.yaml`). Keep this runbook pinned in your
PagerDuty service notes so the workflow stays front-of-mind during incident
handoff.

### Acknowledge (within 5 minutes)

1. Respond to the PagerDuty notification and acknowledge the incident within
   **five minutes** of the initial page. Acknowledgement pauses additional
   notifications for the current assignee while signalling to the team that the
   alert is being investigated.
2. Open the linked Alertmanager event from the PagerDuty incident or navigate to
   the `/#/alerts` view filtered by the firing alert name. Confirm that the
   labels identify the correct cluster or workload before taking mitigation
   steps.
3. Document the acknowledgement time and initial hypothesis in the PagerDuty
   incident timeline to maintain an audit trail for later review.

### Silence (when suppression is warranted)

Silences are coordinated through Alertmanager and must always include a PagerDuty
note so secondary responders understand the blast radius.

1. Validate that the alert is a known noisy condition (for example, during a
   controlled maintenance window) and that telemetry health can be monitored via
   alternate signals.
2. From Alertmanager, create a silence scoped to the precise label set (cluster,
   job, and alert name). Limit the duration to the smallest reasonable window—by
   default no longer than **30 minutes**—and record the maintenance reference or
   change ticket ID in the comment field.
3. Post the silence summary, expiry time, and change reference in the PagerDuty
   incident notes before closing or reassigning the incident.

### Escalate (if unresolved after 15 minutes)

If you have not identified a viable mitigation within **15 minutes** of the
initial page, escalate to the next rotation in PagerDuty and notify the security
liaison on-call:

1. Use the PagerDuty "Escalate Incident" action to page the secondary SRE or
   team lead. Include a brief status update covering hypotheses tested, graphs
   reviewed, and any silences applied.
2. Mention `@security-duty` in the incident Slack bridge (or follow the contact
   instructions in [`SECURITY.md`](../SECURITY.md)) when telemetry signals could
   indicate abuse, compromised secrets, or data exfiltration.
3. Continue triage alongside the escalated responder until the alert clears or a
   mitigation is in place, then schedule a follow-up in the shared incident log
   for retrospective review.

For additional operator context and security reporting flows, see the
[operator guide](./operator-guide.md#telemetry-alert-handoff) and the
[security policy](../SECURITY.md#incident-coordination-and-telemetry-escalation).
