# Security Risk Register

**Last reviewed:** 18 July 2026 by the security review board.

The table below summarises the currently open snapshot lifecycle risks and the
teams accountable for completing remediation. Each risk links to the
implementation task that tracks delivery work.

## Implemented controls

| Control | Impact addressed | Status | Control owner | Evidence |
| --- | --- | --- | --- | --- |
| Snapshot Manifest Verification | Prevents tampered manifests from being distributed and imported into state sync. | **Implemented — 24 July 2026.** Release builds sign and publish `snapshot-verify-report.json` plus hashes; CI gate `snapshot-verifier` and the Phase‑A evidence bundle capture reproducible smoke artefacts for auditors. | Tooling Team | [Phase‑A Acceptance Checklist — Snapshot provenance](../runbooks/phaseA_acceptance.md#snapshot-provenance)<br>[Threat Model — Phase A Review Summary](threat_model.md#phase-a-review-summary) |
| Audit Log WORM Export | Ensures admission audit events are immutably exported so tampering is detectable. | **Implemented — 24 July 2026.** Nightly `worm-export` job emits signed `worm-export-summary.json`, the bootstrap guard enforces WORM configuration at startup, and evidence bundles archive the exports for audit review. | Security Engineering | [Phase‑A Acceptance Checklist — WORM export audit trail](../runbooks/phaseA_acceptance.md#worm-export-audit-trail)<br>[Threat Model — Phase A Review Summary](threat_model.md#phase-a-review-summary) |
| Admission dual-control workflow | Removes single-operator admission changes by requiring operations to stage updates and security to approve them before the peerstore persists policies and audit entries. | **Implemented — 26 July 2026.** Pending queue, RPC guards, and peerstore enforcement persist both approvals, emit signed audit records, and export them to WORM storage; the `rpc-admission-audit` CI job runs the regression suite continuously. | Identity & Access | [Compliance Overview — Dual approval enforcement](../governance/compliance_overview.md#phase3-control-coverage)<br>[Admission Runbook — Dual-approval workflow](../runbooks/admission.md#dual-approval-workflow)<br>`rpc-admission-audit` job in [`ci.yml`](../../.github/workflows/ci.yml#L367-L376) |

## Phase C Review Summary

| Risiko | Status | Evidenz |
| --- | --- | --- |
| WORM-Retention Evidence Drift | **Geschlossen — 1 Aug 2026.** Phase‑C-Sign-off erfordert den aktuellen `worm-retention-report.json`, Gegenprobe via `cargo xtask worm-retention-check` und Incident-Log-Abschluss. | [Phase‑C Acceptance Checklist — Exit Criteria](../runbooks/phaseC_acceptance.md#exit-criteria) |
| Evidence-Bundle Lücken | **Geschlossen — 1 Aug 2026.** `phase3-evidence-<timestamp>` archiviert WORM-, Snapshot- und Chaos-Artefakte inklusive Manifest-Hash; Index-Einträge referenzieren die Ablageorte. | [Phase‑C Acceptance Checklist — Exit Criteria](../runbooks/phaseC_acceptance.md#exit-criteria)<br>[Evidence Bundle Index](../governance/evidence_bundle_index.md) |
| Chaos-Drill Nachweisführung | **Geschlossen — 1 Aug 2026.** Nightly `snapshot_partition_report.json` wird gegen Grafana-/Prometheus-Exports verifiziert und mit Recovery-Protokollen im Incident-Log dokumentiert, bevor das Audit-Ticket geschlossen wird. | [Phase‑C Acceptance Checklist — Exit Criteria](../runbooks/phaseC_acceptance.md#exit-criteria) |

| Risk | Impact | Mitigation Status | Remediation Owner | Tracking |
| --- | --- | --- | --- | --- |
| Snapshot replay defence coverage | Replayed manifests could poison state-sync and trigger consensus divergence. | Add-on manifest signature telemetry is blocked on replay simulation data; external verification CLI is scoped and tracked separately. | State Sync Guild | [ENG-921](../status/weekly.md#snapshot-replay-hardening) |
| External snapshot verification gap | Operators lack an offline tool to verify manifests before distribution, leaving replay detection dependent on online guards. | Release builds now emit `snapshot-verify-report.json` plus SHA256-Hash; dedicated offline tooling remains tracked separately. | Tooling Team | [ENG-1053](../status/weekly.md#external-snapshot-verification-eng-1053) |
| Resume validation gaps | Tampered partial downloads may bypass integrity checks and lead to corrupted node states. | Attestation hooks merged; chunk hash retry guardrails in QA ahead of staged rollout. | Recovery Working Group | [ENG-922](../status/weekly.md#resume-validation-guardrails) |
| Tier policy persistence drift | Unpersisted policy changes weaken witness tier isolation and allow bypass of rate controls. | Append-only log landed; policy snapshots and audit entries are now signed with the rotating admission key and operators can verify attestations via CLI. Dual-control workflow automation remains outstanding. | Network Operations | [ENG-923](../status/weekly.md#tier-policy-persistence) |
| Dual-control adoption (training & drills) | Without role training, operators may bypass or delay the staged workflow, weakening segregation of duties evidence. | Runbooks and API guards are live; schedule joint operations/security drills and archive sign-offs per training plan. | Identity & Access | [ENG-1051](../status/weekly.md#dual-control-automation-eng-1051) |
| Audit trail reconciliation debt | Missing audit events reduce forensic confidence during incident response. | Immutable storage replication blocked on storage API upgrade; reconciliation job staged for post-upgrade deployment. | Security Engineering | [ENG-924](../status/weekly.md#audit-trail-reconciliation) |
| WORM export coverage | Local append-only logs can still be modified on compromised hosts, eroding evidentiary integrity. | CI/Nightly smoke tests publish `worm-export-summary.json`; production object storage replication awaiting compliance sign-off. | Security Engineering | [ENG-1052](../status/weekly.md#worm-export-hardening-eng-1052) |

## Next Review
The security review board will revisit these items during the Phase 3 planning
checkpoint or earlier if blocking incidents are detected.
