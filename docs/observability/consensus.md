# Consensus observability

This guide documents the Grafana panels and alerting recommendations that ship with
`docs/dashboards/consensus_grafana.json`. Use it to validate VRF/quorum proof pipelines during
Phase‑2 acceptance and to keep operational runbooks aligned with the exported metrics.

## Panels

### VRF verification latency
* **Metric:** `consensus_vrf_verification_time_ms`
* **Breakdown:** `result` (`success`/`failure`), optional `reason` label for failures.
* **Targets:** p95 ≤ 25 ms in production. Latency outliers almost always correlate with prover
  back pressure; investigate the prover logs when the histogram count for `result="failure"`
  grows over multiple intervals.
* **Alert:** trigger a warning when p95 exceeds 50 ms for five consecutive minutes and escalate to a
  pager when the failure ratio (`sum by (result)(increase(consensus_vrf_verification_time_ms_count[5m]))`)
  shows more than two failed verifications per interval.

### VRF verification outcomes
* **Metric:** `consensus_vrf_verifications_total`
* **Breakdown:** `result` (`success`, `failure`) with `reason` label for failing cases.
* **Targets:** ≥ 99.9 % of verifications should succeed over any 15‑minute window. A single failure
  often signals tampered metadata; create an incident if two or more failures occur within an hour.
* **Alert:** raise a critical alert when `sum by (reason)(increase(consensus_vrf_verifications_total{result="failure"}[5m]))`
  exceeds 0. Configure the alert to include the `reason` label to speed up triage.

### Quorum verification outcomes
* **Metric:** `consensus_quorum_verifications_total`
* **Breakdown:** `result` (`success`, `failure`) with `reason` label for failing cases.
* **Targets:** zero failures during normal operations. Two consecutive failures point to quorum
  tampering or validator drift and should immediately page the on-call engineer.
* **Alert:** configure Grafana to raise a critical alert when `result="failure"` increments and include
  the `reason` label in the notification payload for quick triage.

### Round health summary
* **Metric:** `rpp.runtime.consensus.round.quorum_latency`
* **Purpose:** correlates the VRF/quorum verification data with round-level latency. Use it alongside the
  existing `pipeline_consensus_finality.json` dashboards to determine whether a failed quorum impacts the
  overall block pipeline.

### Uptime/finality correlation
* **Dashboard:** `uptime_finality_correlation.json` overlays restart signals (changes in
  `process_start_time_seconds` and scrape downtime) with `finality_lag_slots`,
  `finalized_height_gap`, and chain growth to highlight whether restarts triggered
  or coincided with stalled finality.【F:docs/dashboards/uptime_finality_correlation.json†L1-L88】
* **Alert linkage:** the `ConsensusRestartFinalityCorrelation` rule fires when a
  process restart occurs within a fifteen-minute window of widening finality lag or
  height gaps, providing a paged signal to correlate the panels.【F:ops/alerts/consensus/finality.yaml†L35-L52】
* **Interpretation:** if restart spikes line up with increasing lag or height gaps,
  review the node logs for crash loops and confirm peer counts recover before
  expecting the finality series to return below their warning thresholds. Sustained
  block production (a flat or rising block-rate panel) with falling lag indicates
  the restart cleared the issue; otherwise, escalate to the failover playbook.

## Operational notes

1. Always capture Grafana screenshots for the VRF histogram and quorum counter when signing off Phase‑2
   acceptance; the [observability runbook](../runbooks/observability.md#phase-2-consensus-proof-audits)
   lists the required artefacts.
2. When failures appear, correlate them with `node.log` entries such as `invalid VRF proof`,
   `duplicate precommit detected`, or `consensus witness participants do not match commit set` to
   confirm the rejection reason.【F:rpp/runtime/types/block.rs†L2002-L2245】
3. The dashboards expect Prometheus labels `result` and `reason`; if they are missing, verify that the
   node runs a build containing the new telemetry instrumentation in `RuntimeMetrics`.【F:rpp/runtime/telemetry/metrics.rs†L60-L357】
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
