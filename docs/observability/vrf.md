# VRF Telemetry Dashboards & Alerts

## Overview
The Poseidon VRF pipeline publishes structured selection metrics for every
consensus round. These metrics complement the `/status/node` payload by making
pool health, acceptance ratios, and fallback behaviour observable through the
OTLP pipeline. This document describes the exported instruments, suggests
Grafana panels, and outlines baseline alert rules for validator operations.

## Metric Inventory
| Metric | Type | Description |
| --- | --- | --- |
| `rpp.crypto_vrf.selection.pool_entries` | Histogram (u64) | Submission pool size per selection. |
| `rpp.crypto_vrf.selection.target_validator_count` | Histogram (u64) | Target committee size configured for the epoch. |
| `rpp.crypto_vrf.selection.unique_addresses` | Histogram (u64) | Unique addresses encountered per pool snapshot. |
| `rpp.crypto_vrf.selection.participation_rate` | Histogram (f64) | Share of pool entries that cleared proof validation. |
| `rpp.crypto_vrf.selection.verified_total` | Counter (u64) | Verified submissions per round. |
| `rpp.crypto_vrf.selection.accepted_total` | Counter (u64) | Validators accepted below the epoch threshold. |
| `rpp.crypto_vrf.selection.rejected_total` | Counter (u64) | Submissions rejected after verification (including threshold misses). |
| `rpp.crypto_vrf.selection.fallback_total` | Counter (u64) | Rounds that required a fallback candidate. |
| `rpp.crypto_vrf.selection.latest_epoch` | Histogram (u64) | Epoch identifier associated with the latest metrics bundle. |
| `rpp.crypto_vrf.selection.latest_round` | Histogram (u64) | Consensus round reported with the selection audit trail. |
| `rpp.crypto_vrf.selection.threshold_transitions` | Counter (u64) | Epoch transitions that published a VRF threshold (tagged by value). |

All metrics are emitted synchronously when `select_validators` finishes and use
cumulative reporting so dashboards can render both instantaneous gauges and
long-term trend panels.

## Dashboard Blueprint
1. **Pool Health** – combine `pool_entries`, `unique_addresses`, and
   `participation_rate` in a single panel to track validator participation.
2. **Acceptance vs. Rejection** – stacked counters for
   `accepted_total` vs. `rejected_total` to highlight threshold tuning issues.
3. **Fallback Heatmap** – rate panel for `fallback_total` with epoch annotations
   to catch prolonged fallback reliance.
4. **Threshold Timeline** – table panel showing
   `threshold_transitions` grouped by the `threshold` attribute. This provides an
   audit trail when operators adjust threshold curves.

Dashboards should be published under `docs/dashboards/` when rendered. The JSON
export can be sourced directly from these metrics without additional transforms
because every instrument already normalises the units and tags.

## Alerting Guidance
Baseline alert rules derived from the default thresholds:

- **Participation Drop** – alert when the 15‑minute average of
  `participation_rate` falls below `min_participation_rate`.
- **Rejection Spike** – alert when the ratio of
  `rejected_total / verified_total` exceeds `max_rejection_rate` within a single
  epoch.
- **Fallback Saturation** – alert on a `fallback_total` rate higher than
  `max_fallback_ratio` per round.

Operators can adjust these limits through configuration (see below) and should
attach runbooks linking to the consensus troubleshooting guide.

## Configuration
Telemetry thresholds live under `[rollout.telemetry.vrf_thresholds]` in
`config/node.toml`. They are loaded by the runtime on startup and validated to
stay within `[0.0, 1.0]`. Override the defaults to match validator set size or
participation guarantees and re-deploy the node to apply the changes.
