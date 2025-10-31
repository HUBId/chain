# Observability runbook

Use this runbook to diagnose gaps in telemetry, metrics, and health reporting. Pair it with the
[startup](startup.md) and [configuration](../configuration.md) guides when remediation requires
configuration changes.

| Symptom | Check | Action |
| --- | --- | --- |
| OTLP backend shows no traces or metrics | Inspect startup logs for `telemetry disabled` or `telemetry enabled without explicit endpoint` to confirm whether telemetry was activated.【F:rpp/node/src/lib.rs†L442-L481】 | Enable `rollout.telemetry.endpoint` (and optional HTTP mirror) in the active config or pass `--telemetry-endpoint` on the CLI; hybrid/validator templates ship with telemetry enabled for convenience.【F:rpp/runtime/config.rs†L894-L907】【F:config/hybrid.toml†L41-L46】【F:config/validator.toml†L41-L45】【F:rpp/node/src/lib.rs†L143-L208】 |
| `/observability` dashboards lack pipeline data | Call `/wallet/pipeline/telemetry` or `/p2p/peers` on the RPC service to confirm the orchestrator is publishing snapshots.【F:rpp/rpc/api.rs†L984-L1067】【F:rpp/runtime/orchestration.rs†L611-L615】 | If the summary is empty, ensure the node runtime is running (see startup runbook) and that the pipeline orchestrator logged `pipeline orchestrator started`. Restart after resolving config or network issues and review the [pipeline telemetry dashboards](../observability/pipeline.md) for stalled phases.【F:rpp/node/src/lib.rs†L494-L552】 |
| `pipeline_submissions_total` metrics report many `reason="tier_requirement"` rejections | Review the labelled counter from the metrics backend; the orchestrator records tier and gossip errors when rejecting workflows.【F:rpp/runtime/orchestration.rs†L623-L704】 | Investigate the submitting account’s reputation tier via `/wallet/reputation/:address` or adjust the workflow policy; see [modes](../modes.md) for role-specific submission expectations.【F:rpp/rpc/api.rs†L984-L1059】 |
| Slashing dashboards show `kind=censorship` oder `kind=inactivity` Ausschläge | Prüfe `rpp.node.slashing.events_total` und `queue_segments` nach Validator-IDs mit gehäuften Meldungen; korreliere mit `consensus`-Logs für `registered censorship trigger` bzw. `registered inactivity trigger`.【F:rpp/node/src/telemetry/slashing.rs†L59-L93】【F:rpp/consensus/src/state.rs†L1000-L1199】 | Abgleich mit den in `consensus.config` gesetzten Grenzwerten (`censorship_vote_threshold`, `censorship_proof_threshold`, `inactivity_threshold`) und Validator-Runbooks; wiederholte Treffer deuten auf blockierte Votes/Proofs oder dauerhaftes Fernbleiben hin. Fordere betroffene Operatoren zur Netzwerkanalyse auf und evaluiere Slashing-/Ersatzmaßnahmen anhand der Testfälle.【F:tests/consensus/censorship_inactivity.rs†L1-L260】 |

## Telemetry exporter checklist

1. Confirm `rollout.telemetry` is enabled and points to a valid HTTP/OTLP endpoint; validation rejects
   empty, scheme-less, or unauthenticated URIs.【F:rpp/runtime/config.rs†L1729-L1779】
2. Verify CLI overrides (`--telemetry-endpoint`, `--telemetry-auth-token`, `--telemetry-sample-interval`)
   are correct; these flags replace file-based settings when present.【F:rpp/node/src/lib.rs†L143-L208】【F:rpp/node/src/lib.rs†L1045-L1080】
3. If metrics still fail to export, increase `trace_max_queue_size` or
   `trace_max_export_batch_size` to reduce drop pressure on the OpenTelemetry batcher before restarting.
   Validation enforces sane, non-zero limits.【F:rpp/runtime/config.rs†L1729-L1779】

## Pipeline dashboards

* The orchestrator publishes telemetry summaries and dashboard streams that back `/wallet/pipeline/*`
  endpoints; lack of updates usually indicates the node runtime never started or shut down unexpectedly.
  Look for `node runtime started` and `pipeline orchestrator started` markers, then inspect shutdown
  logs for cancellations.【F:rpp/runtime/orchestration.rs†L611-L615】【F:rpp/node/src/lib.rs†L442-L557】
* Metrics counters such as `pipeline_submissions_total` emit reasons (`tier_requirement`,
  `gossip_publish`, etc.) when workflows are rejected, making it easier to correlate RPC clients with
  policy failures.【F:rpp/runtime/orchestration.rs†L623-L704】
* Stage-level latency, throughput, and Firewood commit heights are documented in
  [pipeline telemetry dashboards](../observability/pipeline.md); consult them when diagnosing gaps
  between wallet intake, proof validation, BFT finality, and storage commits.

If health probes fail, jump to the [startup runbook](startup.md); persistent issues should be logged
for follow-up in the [operator checklist](../checklists/operator.md).

