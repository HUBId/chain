# Wöchentlicher Statusbericht

## Phase 1 abgeschlossen (Kalenderwoche 37/2025)

**Zusammenfassung:** Die Blueprint-Phase 1 ist abgeschlossen. Die Plonky3-Strecke ist vollständig dokumentiert, Root-Guards überwachen Firewood-Snapshots und die CI-Gates spiegeln die komplette Backend-Matrix wider.

### Highlights
- **Plonky3-Arbeiten:** Phase 2 test evidence liegt im [Produktions-Testplan](../testing/plonky3_experimental_testplan.md#results), im [Leistungsreport](../performance/consensus_proofs.md) und im [Runbook](../runbooks/plonky3.md); Nightly-Stressläufe sichern p95-Prover/Verifier-Latenzen und Tamper-Rejections.【F:docs/testing/plonky3_experimental_testplan.md†L1-L120】【F:docs/performance/consensus_proofs.md†L1-L200】【F:docs/runbooks/plonky3.md†L1-L200】
- **Root-Guards:** Dashboards und Alerts für Trie-/Snapshot-Korruption sind aktiv, gestützt durch den [Firewood-Integrity-Guide](../observability/firewood_root_integrity.md) und die Regression [root_corruption.rs](../../tests/state_sync/root_corruption.rs).【F:docs/observability/firewood_root_integrity.md†L1-L52】【F:tests/state_sync/root_corruption.rs†L1-L53】
- **CI-Erweiterung:** `fmt`, `clippy` und `./scripts/test.sh --all` laufen verpflichtend; die Dokumentation weist auf lokale Reproduktionspfade hin ([CI/CD-Integration](../test_validation_strategy.md#4-cicd-integration)).【F:docs/test_validation_strategy.md†L41-L83】

### Nächste Schritte
- Phase 2-Backlog priorisieren (Focus: echte Plonky3-Artefakte, Root-Recovery-Automatisierung, CI-Matrix mit Vendor-Proofs).
- Operator-Briefing zu aktualisierten Dashboards und Eskalationspfaden vorbereiten.

## Phase 2 Fortschritt (Kalenderwoche 38/2025)

**Zusammenfassung:** VRF-/Quorum-Manipulationen lassen sich nun reproduzierbar testen und im Monitoring
nachverfolgen. Die Operator-Dokumentation enthält detaillierte Belege für Phase‑2-Audits. Alle
Nachweise sind in der [Phase‑2 Acceptance Checklist](../runbooks/phase2_acceptance.md) zusammengeführt.

### Highlights
- **Circuit Enforcement:** ENG‑742/ENG‑743 ausgeliefert – STWO rechnet VRF-Transkripte
  in der Konsensschaltung neu, faltet Poseidon-Bindings und erzwingt Quoren,
  während Plonky3 dasselbe Sanitizing/Replay im Backend widerspiegelt; die
  Tamper-Suites laufen in CI via `cargo xtask test-consensus-manipulation`.
  【F:prover/prover_stwo_backend/src/official/circuit/consensus.rs†L300-L586】【F:prover/plonky3_backend/src/circuits/consensus.rs†L520-L690】【F:tests/consensus/consensus_proof_tampering.rs†L100-L320】【F:xtask/src/main.rs†L78-L125】
- **Tamper-Tests:** `cargo xtask test-consensus-manipulation` läuft für STWO und Plonky3; die Cases in
  `tests/consensus/consensus_certificate_tampering.rs` sind als Abnahmebeleg dokumentiert.【F:xtask/src/main.rs†L1-L120】【F:tests/consensus/consensus_certificate_tampering.rs†L1-L160】
- **Observability:** Neues Dashboard `docs/dashboards/consensus_grafana.json` plus Handbuch
  `docs/observability/consensus.md` liefern Panels und Alert-Vorlagen für
  `consensus_vrf_verification_time_ms` und `consensus_quorum_verifications_total`.【F:docs/dashboards/consensus_grafana.json†L1-L200】【F:docs/observability/consensus.md†L1-L70】
- **Runbooks:** Operator Guide und Observability-Runbook beschreiben Simnet-Logs, RPC-Checks und
  Grafana-Screenshots für Phase‑2-Freigaben.【F:docs/rpp_node_operator_guide.md†L120-L174】【F:docs/runbooks/observability.md†L1-L120】
- **Regression-Orchestrierung:** Der neue Binary `tools/simnet/src/bin/regression.rs` fährt VRF-/Snapshot-/Gossip-Szenarien
  sequenziell, erzeugt JSON/HTML-Berichte und läuft in CI/Nightly als `simnet-regression`-Job.【F:tools/simnet/src/bin/regression.rs†L1-L240】【F:.github/workflows/ci.yml†L287-L303】【F:.github/workflows/nightly.yml†L186-L208】
- **Alert-Playbook:** Prometheus-Regeln unter `docs/observability/alerts/consensus_vrf.yaml` decken p95-VRF-Latenzen,
  Failure-Bursts und Quorum-Rejections ab; das Observability-Runbook dokumentiert Diagnose- und Eskalationsschritte.【F:docs/observability/alerts/consensus_vrf.yaml†L1-L47】【F:docs/runbooks/observability.md†L1-L160】
- **Release-Metadaten:** Die Release-Notizen enthalten nun automatisch extrahierte Proof-Metadaten (Circuit-IDs,
  Constraint-Zählungen, Backend-Support) und verlinken in Operator-Guides/ADRs für Audits.【F:docs/release_notes.md†L1-L160】【F:.github/workflows/release.yml†L1-L120】【F:docs/rpp_node_operator_guide.md†L120-L210】【F:docs/adr/0001_consensus_proofs.md†L1-L120】
- **Nightly Simnet:** Der Workflow [`nightly-simnet`](../.github/workflows/nightly.yml) fährt täglich `cargo xtask test-simnet`
  mit dem Produktions-Feature-Set, wertet alle Summaries via `scripts/analyze_simnet.py` aus und stellt die Artefakte im Actions-Tab bereit.
  Abweichungen bei VRF-/Quorum-Tamper führen zu roten Nightly-Statusmeldungen, die im
  [Validierungsplan](../test_validation_strategy.md#4-cicd-integration) dokumentiert sind.【F:.github/workflows/nightly.yml†L1-L86】【F:docs/test_validation_strategy.md†L41-L83】

### Ampelstatus
- **Tests:** 🟢 – Manipulations-Suite läuft nightly.
- **Monitoring:** 🟡 – Dashboards aktiv, Alerts in Rollout.
- **Operator Docs:** 🟢 – Phase‑2-Abschnitt veröffentlicht.

## Phase 2 Abnahme (Kalenderwoche 14/2026)

**Zusammenfassung:** Die drei verpflichtenden Test-Suites (`unit-suites`, `integration-workflows`, `simnet-smoke`) sind in CI grün und als Branch-Protection-Checks aktiviert. Nightly-Läufe bestätigen die Stabilität und stellen vollständige Simnet-Artefakte bereit.

### Highlights
- **Unit-Suites:** Die Matrix aus Default-, Produktions- und Plonky3-Läufen (`cargo xtask test-unit`) deckt deterministische Witness-/VRF-Checks ab und bildet den Statuscheck `unit-suites` für alle Branches.【F:.github/workflows/ci.yml†L185-L217】
- **Integrations-Workflows:** `cargo xtask test-integration` prüft Blockproduktion, Snapshot-/Light-Client-Sync und Manipulationsschutz als verpflichtenden Check `integration-workflows` auf denselben Feature-Kombinationen.【F:.github/workflows/ci.yml†L219-L251】
- **Simnet-Smoke:** `cargo xtask test-simnet` läuft als Pflichtgate `simnet-smoke`, deckt alle Szenarien ab und liefert Summaries für VRF-/Quorum-Stressfälle.【F:.github/workflows/ci.yml†L253-L285】
- **Nightly-Nachweis:** Der Workflow `nightly-simnet` fährt `cargo xtask test-all` sowie das dedizierte Simnet-Harness und lädt die Artefakte (`simnet-nightly`) für Auditor:innen hoch.【F:.github/workflows/nightly.yml†L88-L124】【F:.github/workflows/nightly.yml†L148-L183】

### Artefakte & Logs
- **CI-Artefakte:** Der `simnet-regression` Upload aus dem CI-Workflow bündelt JSON-/CSV-Summaries aller Simnet-Läufe zur Nachvollziehbarkeit.【F:.github/workflows/ci.yml†L287-L303】
- **Nightly-Artefakte:** Das Paket `simnet-nightly` enthält vollständige Nightly-Summaries (`ci_block_pipeline`, `ci_state_sync_guard`, `consensus_quorum_stress`) inklusive Analyseresultaten.【F:.github/workflows/nightly.yml†L148-L183】
- **Matrix-Protokolle:** Die Step-Logs in `unit-suites`, `integration-workflows` und `simnet-smoke` dokumentieren Laufzeiten (~12/18/22 Minuten) und werden für Reviews im Actions-Tab archiviert.【F:.github/workflows/ci.yml†L185-L285】
- **Snapshot-Verifier:** [CI-Artefakt `snapshot-verifier`](https://github.com/<org>/<repo>/actions/runs/<run-id>#artifact) stellt `snapshot-verify-report.json` + `.sha256` für den Merge-Run bereit; die Hashes fließen in die Release-Freigaben ein.【F:.github/workflows/ci.yml†L360-L397】
- **WORM-Export Smoke:** [CI-Protokoll `worm-export-smoke`](https://github.com/<org>/<repo>/actions/runs/<run-id>#summary-logs) dokumentiert die WORM-Export-Prüfung und enthält das Artefaktpaket `worm-export-smoke.zip` mit Export-Summary und Checksummen.【F:.github/workflows/nightly.yml†L1-L24】
- **Threat-Model Review:** [Review-Artefakt `threat-model-review`](https://github.com/<org>/<repo>/actions/runs/<run-id>#artifact) bündelt die Protokolle aus dem Security-Workflow und verweist auf das aktualisierte Threat-Model-Addendum.【F:docs/security/threat_model.md†L1-L120】

## Phase 2 abgeschlossen (Kalenderwoche 15/2026)

**Zusammenfassung:** Phase 2 ist abgeschlossen. Die Proof-Erweiterungen aus ENG‑742/ENG‑743 laufen für STWO und Plonky3 in Produktion, die Pflicht-Test-Suites sichern jede Pipeline-Änderung ab und die Observability-Assets (Dashboards, Alerts, Runbooks) sind für On-Call verfügbar.

### Highlights
- **Proof-Erweiterungen:** VRF-/Quorum-Recomputation ist in beiden Backends ausgeliefert; Tamper-Tests und die `proof-metadata`-Generierung belegen stabile Constraint-Layouts.【F:prover/prover_stwo_backend/src/official/circuit/consensus.rs†L300-L586】【F:prover/plonky3_backend/src/circuits/consensus.rs†L520-L690】【F:docs/release_notes.md†L1-L80】
- **Test-Suites:** `unit-suites`, `integration-workflows` und `simnet-smoke` sind als Branch-Protection aktiv; das Nightly-Harness (`cargo xtask test-all`) verifiziert die Matrix kontinuierlich.【F:.github/workflows/ci.yml†L185-L303】【F:.github/workflows/nightly.yml†L88-L183】
- **Observability:** Dashboard, Alerts und Runbooks für VRF-/Quorum-Kennzahlen sind vollständig dokumentiert und verlinkt; Operator:innen besitzen das Phase‑2-Playbook.【F:docs/dashboards/consensus_grafana.json†L1-L200】【F:docs/observability/consensus.md†L1-L70】【F:docs/runbooks/observability.md†L1-L160】

- **Phase 3 Acceptance Tracking:** Fortschritt und Nachweise (Snapshot-SLIs, Admission-Persistenz, Timetoke-Replay, Observability-Drills) werden in der [Phase‑3 Acceptance Checklist](../runbooks/phase3_acceptance.md) dokumentiert.

### Nächste Schritte – Phase 3 Preview
- Netzwerk/Snapshot-Verteilung härten (siehe Abschnitt 4.3 „Snapshot-Sync & Telemetrie“ im Implementierungsplan und `SnapshotsBehaviour`).
- Tier-Admission-Härtung und Witness-Kanäle vorziehen (Abschnitt 4.2 und 6.4/6.5 des Implementierungsplans).
- Firewood↔Proof-Verzahnung und Snapshot-Rebuild-Service aus Abschnitt 2 vorbereiten, um Witness-Gossip und State-Sync zu koppeln.

## Phase 3 Tracking (Kalenderwoche 20/2026)

Dieser Abschnitt dient als fortlaufende Vorlage für Phase‑3-Updates. Neue Einträge werden jeweils unter den bestehenden Tabellen ergänzt; erledigte Artefakte bleiben zur Nachverfolgung bestehen, offene Punkte verweisen auf Owner, Backlog-Items oder Checklisten.

Die [Compliance Overview](../governance/compliance_overview.md) listet Phase‑3-Kontrollen, Evidenzlinks und Restarbeiten, damit Audits denselben Informationsstand wie das Programmteam besitzen.

### Artefaktstatus

| Kategorie | Deliverable | Status | Nachweise / Links |
| --- | --- | --- | --- |
| Runbooks | Failover-Runbook verlinkt Snapshot- und Admission-Drills in On-Call-Dokumentation. | ✅ produktiv | [`docs/runbooks/network_snapshot_failover.md`](../runbooks/network_snapshot_failover.md), [`docs/runbooks/observability.md`](../runbooks/observability.md)【F:docs/runbooks/network_snapshot_failover.md†L1-L176】【F:docs/runbooks/observability.md†L1-L120】 |
| Metriken & Tests | Snapshot-/Timetoke-Metriken exportiert und via `cargo xtask test-observability` sowie `snapshot_timetoke_metrics.rs` abgesichert. | ✅ produktiv | [`rpp/p2p/src/behaviour/snapshots.rs`](../../rpp/p2p/src/behaviour/snapshots.rs), [`tests/observability/snapshot_timetoke_metrics.rs`](../../tests/observability/snapshot_timetoke_metrics.rs)【F:rpp/p2p/src/behaviour/snapshots.rs†L462-L518】【F:tests/observability/snapshot_timetoke_metrics.rs†L70-L206】 |
| CI-Jobs | `simnet-regression`, `snapshot-verifier` und `worm-export-smoke` veröffentlichen reproduzierbare Artefakte (Snapshot-Reports, WORM-Summary) und halten die Nightly-Gates (`nightly-simnet`, `worm-export`). | ✅ aktiv | [`ci.yml` snapshot-verifier/worm-export](../../.github/workflows/ci.yml#L360-L397), [`nightly.yml` worm-export Job](../../.github/workflows/nightly.yml#L1-L24)【F:.github/workflows/ci.yml†L360-L397】【F:.github/workflows/nightly.yml†L1-L24】 |
| Compliance Evidence | Nightly-Artefakt `phase3-evidence-<timestamp>` bündelt Dashboards, Alerts, Audit-Logs, Policy-Backups, WORM-Exports, Checksum-Reports und CI-Logs inklusive Manifest. | ✅ aktiv | Nightly-Job [`phase3-evidence`](../../.github/workflows/nightly.yml#L79-L128) generiert das Paket via `cargo xtask collect-phase3-evidence`; das Manifest und die Speicherpfade für Snapshot- und WORM-Nachweise sind im [`Evidence Bundle Index`](../governance/evidence_bundle_index.md) dokumentiert.【F:.github/workflows/nightly.yml†L79-L128】【F:xtask/src/main.rs†L1498-L1852】【F:docs/governance/evidence_bundle_index.md†L1-L85】 |

### Offene Restarbeiten

| Fokus | Deliverable | Offene Schritte | Referenz |
| --- | --- | --- | --- |
| Snapshot-SLIs | Baselines & Replay-Belege finalisieren (Panels archivieren, Replay-Schutz protokollieren). | Dashboard-Exports einsammeln, RPC-/P2P-Logs dem Audit-Archiv hinzufügen. | [Phase‑3 Acceptance Checklist – Snapshot-SLIs & Replay](../runbooks/phase3_acceptance.md#snapshot-slis--replay-evidenz)【F:docs/runbooks/phase3_acceptance.md†L8-L33】 |
| Timetoke | Timetoke-SLO-Bericht und Replay-Validator-Artefakte vollständig anhängen. | Nightly-Artefakte annotieren, Replay-Failure-Cases sammeln. | [Phase‑3 Acceptance Checklist – Timetoke](../runbooks/phase3_acceptance.md#timetoke-snapshot-roundtrip)【F:docs/runbooks/phase3_acceptance.md†L34-L61】 |
| Tier Admission | Allow-/Blocklist-Dumps versionieren, RPC-Roundtrip-Logs sichern. | Peerstore-Reload-Protokolle und RPC-Audit-Logs exportieren. | [Phase‑3 Acceptance Checklist – Tier-Admission Persistenz & Audit](../runbooks/phase3_acceptance.md#tier-admission-persistenz--audit)【F:docs/runbooks/phase3_acceptance.md†L36-L49】 |
| Observability | Alert-Drills & Grafana-Exporte versionieren, Screenshots zu On-Call-Handbook hinzufügen. | Prometheus-Testläufe dokumentieren, Grafana-Screenshots verlinken. | [Phase‑3 Acceptance Checklist – Observability Dashboards & Alerts](../runbooks/phase3_acceptance.md#observability-dashboards--alerts)【F:docs/runbooks/phase3_acceptance.md†L62-L79】 |

## Phase 3 Abschluss (Kalenderwoche 25/2026)

**Zusammenfassung:** Phase 3 schließt den Networking-Schwerpunkt ab: Admission-Control speichert Allow-/Blocklisten persistent, protokolliert Audit-Trails, erlaubt Dual-Control-Updates via RPC und exportiert Snapshot-SLIs, die Runbook, Dashboard und Alerts konsolidieren.【F:rpp/p2p/src/peerstore.rs†L1180-L1299】【F:rpp/p2p/src/peerstore.rs†L1795-L1828】【F:rpp/rpc/src/routes/p2p.rs†L232-L379】【F:rpp/p2p/src/behaviour/snapshots.rs†L462-L518】【F:tests/observability/snapshot_timetoke_metrics.rs†L70-L180】【F:docs/runbooks/network_snapshot_failover.md†L1-L176】【F:docs/dashboards/pipeline_overview.json†L200-L260】【F:docs/observability/alerts/snapshot_stream.yaml†L1-L66】

### Highlights
- **Persistente Policies & Audit:** `Peerstore::update_admission_policies` schreibt Allow-/Blocklisten auf Disk, hängt Audit-Events an das JSONL-Log an und Tests prüfen den Dual-Control-Pfad inklusive Reload.【F:rpp/p2p/src/peerstore.rs†L1180-L1299】【F:rpp/p2p/src/peerstore.rs†L1795-L1828】
- **RPC-Audit & Governance:** Die neuen `/p2p/admission/*`-Endpunkte erzwingen Rollen-Approvals, erlauben Policy-Reviews und liefern das Audit-Log für Operator:innen.【F:rpp/rpc/src/routes/p2p.rs†L232-L379】
- **Stream-Metriken & Observability:** `SnapshotsBehaviour` exportiert `snapshot_bytes_sent_total` und `snapshot_stream_lag_seconds`, die durch die Observability-Test-Suite validiert und in Runbook, Dashboard und Alert-Regeln verankert sind.【F:rpp/p2p/src/behaviour/snapshots.rs†L462-L518】【F:tests/observability/snapshot_timetoke_metrics.rs†L70-L180】【F:docs/runbooks/network_snapshot_failover.md†L1-L176】【F:docs/dashboards/pipeline_overview.json†L200-L260】【F:docs/observability/alerts/snapshot_stream.yaml†L1-L66】

### Ampelstatus
- **Tests:** 🟢 – Snapshot-Lag- und Byte-Counter-Validierung läuft in `cargo xtask test-observability` stabil.【F:tests/observability/snapshot_timetoke_metrics.rs†L70-L180】
- **Monitoring:** 🟢 – Dashboard und Alerts für Snapshot-Lag/-Durchsatz sind live und verlinken das Failover-Runbook.【F:docs/dashboards/pipeline_overview.json†L200-L260】【F:docs/observability/alerts/snapshot_stream.yaml†L1-L66】【F:docs/runbooks/network_snapshot_failover.md†L1-L176】
- **Operator Docs:** 🟢 – Failover-Runbook aktualisiert, inklusive RPC-/CLI-Schritten und Eskalationspfad.【F:docs/runbooks/network_snapshot_failover.md†L1-L176】


## Security Review Update (Kalenderwoche 19/2026)

**Zusammenfassung:** Die Security-Review vom 27. Mai 2026 für Snapshot-Replay,
Resume-Validierung, Admission-Policy-Kontrollen und Audit-Trail-Härtung ist
abgeschlossen. Die Ergebnisse sind im aktualisierten
[Threat Model Addendum](../security/threat_model.md) und dem
überarbeiteten [Security Risk Register](../security/register.md)
mit neuen Outstanding-Maßnahmen dokumentiert.

### Highlights
- Threat-Model-Erweiterung beschreibt Replay-Abwehr, Resume-Schutz,
  Policy-Persistenz und Audit-Trail-Mitigations mit konkreten Kontrollen.
- Risk Register weist offene Maßnahmen inkl. Ownern und Tracking-Links aus
  und dient als Referenz für Phase‑3-Planung.

### Tracking
<a id="snapshot-replay-hardening"></a>
#### Snapshot Replay Hardening (ENG-921)
- Instrumentierung für Manifest-Signature-Telemetrie wartet auf Replay-Simulationen.
- Simnet-Regression deckt Replay-Detection-Cases ab; Ergebnisse werden für das CLI geteilt.

<a id="resume-validation-guardrails"></a>
#### Resume Validation Guardrails (ENG-922)
- Attestationsprüfung merged; Hash-Retry-Schutz in QA.
- Firewood-CLI erhält Integrationstests für Resume-Flows.

<a id="tier-policy-persistence"></a>
#### Tier Policy Persistence (ENG-923)
- Append-only Policy-Log deployed.
- Operator-Runbook wird um Policy-Rollback-Checks erweitert.

<a id="audit-trail-reconciliation"></a>
#### Audit Trail Reconciliation (ENG-924)
- Reconciliation-Job staged für Deployment nach Storage-API-Upgrade.
- SIEM-Playbook ergänzt Eskalationspfad für fehlende Events.

<a id="dual-control-automation-eng-1051"></a>
#### Dual Control Automation (ENG-1051)
- Witness-Approval-Service wird mit Admission-API verdrahtet.
- Rollback-Alerts werden mit Network Operations abgestimmt.

<a id="worm-export-hardening-eng-1052"></a>
#### WORM Export Hardening (ENG-1052)
- Object-Storage-Pipeline (Immutable Buckets) designiert; Compliance prüft Retention.
- Integrationstests für unveränderliche Uploads sind in Planung.

<a id="external-snapshot-verification-eng-1053"></a>
#### External Snapshot Verification (ENG-1053)
- CLI-Spezifikation freigegeben; Prototyp in `tools/firewood` entsteht.
- Manifest-Signatur-Samples aus Replay-Simulationen werden gesammelt.
