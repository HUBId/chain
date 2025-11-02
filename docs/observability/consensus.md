# Consensus observability

This guide documents the Grafana panels and alerting recommendations that ship with
`docs/dashboards/consensus_grafana.json`. Use it to validate VRF/quorum proof pipelines during
Phase‑2 acceptance and to keep operational runbooks aligned with the exported metrics.

## Panels

### VRF verification latency
* **Metric:** `consensus_vrf_verification_time_ms`
* **Breakdown:** `result` (`success`/`failure`), optional `reason` label for failures.
* **Targets:** p95 ≤ 25 ms in production; investigate if the histogram count for `result="failure"`
  increases over multiple intervals.
* **Alert:** trigger a warning when p95 exceeds 50 ms for five consecutive minutes; escalate when the
  failure ratio (`sum by (result)(increase(consensus_vrf_verification_time_ms_count[5m]))`) shows more
  than two failed verifications.

### Quorum verification outcomes
* **Metric:** `consensus_quorum_verifications_total`
* **Breakdown:** `result` (`success`, `failure`) with `reason` label for failing cases.
* **Targets:** zero failures during normal operations; a single failure should automatically trigger a
  pager alert because it indicates tampered consensus artefacts or a configuration drift.
* **Alert:** configure Grafana to raise a critical alert when `result="failure"` increments, and include
  the `reason` label in the notification payload for quick triage.

### Round health summary
* **Metric:** `rpp.runtime.consensus.round.quorum_latency`
* **Purpose:** correlates the VRF/quorum verification data with round-level latency. Use it alongside the
  existing `pipeline_consensus_finality.json` dashboards to determine whether a failed quorum impacts the
  overall block pipeline.

## Operational notes

1. Always capture Grafana screenshots for the VRF histogram and quorum counter when signing off Phase‑2
   acceptance; the [observability runbook](../runbooks/observability.md#phase-2-consensus-proof-audits)
   lists the required artefacts.
2. When failures appear, correlate them with `node.log` entries such as `invalid VRF proof`,
   `duplicate precommit detected`, or `consensus witness participants do not match commit set` to
   confirm the rejection reason.【F:rpp/runtime/types/block.rs†L2002-L2245】
3. The dashboards expect Prometheus labels `result` and `reason`; if they are missing, verify that the
   node runs a build containing the new telemetry instrumentation in `RuntimeMetrics`.【F:rpp/runtime/telemetry/metrics.rs†L60-L339】
4. Cross-check the collected evidence against the [Phase 2 Exit Criteria](../roadmap_implementation_plan.md#phase-2-exit-criteria-arbeitsstand)
   to ensure the recorded metrics and screenshots cover every audit requirement before sign-off.

## Alerting template

```yaml
- name: consensus-quorum-failures
  condition: sum(increase(consensus_quorum_verifications_total{result="failure"}[2m])) > 0
  summary: "Consensus quorum verification failed"
  description: |
    Validator {{ $labels.validator }} rejected a tampered consensus artefact
    (reason: {{ $labels.reason }}). Investigate node logs and rerun
    `cargo xtask test-consensus-manipulation` to confirm regression coverage.
  runbook_url: https://github.com/risc0/chain/blob/main/docs/runbooks/observability.md#phase-2-consensus-proof-audits
```

Update your alertmanager contacts to point at the validator on-call rotation before rolling the
changes into production.
