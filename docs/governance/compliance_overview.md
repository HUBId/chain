# Compliance Overview

## Phase 3 Control Coverage

| Control | Implementation Status | Evidence |
| --- | --- | --- |
| **Policy backup retention** | ✅ Validator builds persist timestamped admission policy snapshots and prune them per retention policy. | Runtime configuration wires `network.admission.backup_dir` defaults and validation logic, and the peerstore writes and prunes backups with parity tests.【F:rpp/runtime/config.rs†L965-L1015】【F:rpp/runtime/node_runtime/network.rs†L146-L188】【F:rpp/p2p/src/peerstore.rs†L2095-L2239】 Operator runbook documents restore/verification workflow.【F:docs/runbooks/admission.md†L33-L88】 |
| **Dual approval enforcement** | ✅ Admission API rejects privileged policy updates without both operations and security approvals; CI guard keeps regression coverage active. | Runbook outlines the dual-approval payload and audit expectations.【F:docs/runbooks/admission.md†L5-L72】 Peerstore tests require both roles, and RPC routes enforce checks at the API layer.【F:rpp/p2p/src/peerstore.rs†L2057-L2109】【F:rpp/rpc/src/routes/p2p.rs†L126-L205】 Dedicated CI job runs the dual-approval regression suite on every push.【F:.github/workflows/ci.yml†L368-L398】 |
| **Snapshot manifest signatures & Timetoke SLOs** | ✅ Nightly `snapshot-health` und `report-timetoke-slo` veröffentlichen signierte Statusberichte; Alerts (`SnapshotManifestSignatureInvalid`, `SnapshotReplayStallCritical`, `SnapshotChecksumDrift`) verlinken Runbooks mit Eskalationspfad. | Teststrategie beschreibt Exit-Codes und Artefakte samt lokaler Reproduktion.【F:docs/test_validation_strategy.md†L128-L174】 Runbooks enthalten First-Action-Matrizen je Alert.【F:docs/runbooks/network_snapshot_failover.md†L73-L120】【F:docs/runbooks/timetoke_failover.md†L18-L67】 Prometheus-Regeln und Nightly-Workflows halten die Kontrollen aktiv.【F:docs/observability/alerts/snapshot_manifest.yaml†L1-L52】【F:docs/observability/alerts/snapshot_replay.yaml†L1-L35】【F:docs/observability/alerts/snapshot_checksum.yaml†L1-L34】【F:.github/workflows/nightly.yml†L29-L124】 |
| **Snapshot checksum validation** | ✅ Validator service resumes checksum scans after restart and exports observability hooks; integration workflow runs the restart regression. | Runtime settings keep the validator cadence active and service implementation performs restart validation.【F:rpp/runtime/config.rs†L1288-L1305】【F:rpp/node/src/services/snapshot_validator.rs†L74-L153】 Runbook covers the operational drill.【F:docs/runbooks/network_snapshot_failover.md†L20-L116】 CI `integration-workflows` matrix executes `snapshot_checksum_restart` via `cargo xtask test-integration`.【F:xtask/src/main.rs†L101-L128】【F:.github/workflows/ci.yml†L399-L423】 |

## Evidence Traceability
- Updated [Threat Model](../THREAT_MODEL.md) highlighting snapshot and audit log attack surfaces.
- [Security Risk Register](../security/register.md) entries for retention deviations and audit trail coverage.
- Phase 3 [Acceptance Checklist](../runbooks/phase3_acceptance.md) and [Weekly Status](../status/weekly.md#phase3-tracking-kalenderwoche-20-2026) reference this overview for auditor sign-off.

### Phase 3 Evidence Bundle
- `cargo xtask collect-phase3-evidence [--output-dir <path>]` erzeugt unter `target/compliance/phase3/<timestamp>/` eine Manifestdatei sowie das Archiv `phase3-evidence-<timestamp>.tar.gz`. Das Manifest dokumentiert pro Kategorie (Dashboards, Alerts, Audit-Logs, Policy-Backups, Manifest-Signaturen, Timetoke-SLO-Berichte, Checksum-Reports, CI-Logs) sowohl eingefügte Nachweise als auch fehlende Quellen.【F:xtask/src/main.rs†L1498-L1899】
- Der Nightly-Workflow veröffentlicht das Paket automatisch als GitHub-Actions-Artefakt (`phase3-evidence-<timestamp>`), sodass Auditor:innen die aktuelle Evidenz direkt abrufen können.【F:.github/workflows/nightly.yml†L79-L128】

## Outstanding Items
| Gap | Owner | Target Date | Notes |
| --- | --- | --- | --- |
| Off-site replication of policy backups to WORM storage | Storage SRE (L. Banerjee) | 2024-07-22 | Extends current disk retention to satisfy SOC 2 CC3.3. Pending vendor connector in backup automation. |
| Snapshot manifest signing key rotation | Release Engineering (D. Tran) | 2024-08-05 | Rotation-/Publikationsrichtlinie dokumentieren und im Evidence-Bundle referenzieren. |
| Witness approval service automation for dual control | Security Engineering (A. Ortega) | 2024-07-15 | Aligns with SOC 2 CC6.3. Integration tests on staging in progress; rollout requires updated IAM bindings. |
| Consolidated checksum drill evidence package | Compliance (M. Chen) | 2024-07-29 | Need to bundle restart logs, Grafana exports, and CI artifacts in GRC workspace for quarterly review. |

## Regulatory Follow-ups
- Map finalized snapshot retention runbooks to SOC 2 CC8.1 and CC7.2 once WORM export is operational.
- Update evidence package in the GRC tool after dual approval automation and checksum evidence bundle close, capturing sign-offs from Security Engineering and Compliance leadership.

