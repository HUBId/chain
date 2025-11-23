# Incident Response Playbook

Dieses Playbook ergänzt das [On-Call-Handbuch](./oncall.md) und die
[Phase‑3 Acceptance Checklist](./phase3_acceptance.md), wenn ein Incident eine
sofortige Reaktion auf Snapshot-Checksummen, Admission-Drift oder Dual-Control-
Genehmigungen verlangt. Jede Sektion beginnt mit einer "First Action"-Checkliste,
die die wichtigsten CLI-Aufrufe, Dashboards und Audit-Trails verlinkt, damit
Auditor:innen die Dokumentation lückenlos nachverfolgen können.

Wenn ein CI-Chaostest fehlschlägt, folge dem Abschnitt
[„CI failure response for chaos drills“](../observability.md#ci-failure-response-for-chaos-drills)
für die Eskalationskette, Artefakt-Downloads und die zu prüfenden Dashboards.

Für Replay-Störungen in der Timetoke-Pipeline verweist dieses Playbook auf das
[Timetoke-Failover-Runbook](./timetoke_failover.md), das Detection-Signale,
Recovery-Schritte und Troubleshooting-Tipps für die Wiederanbindung der
Snapshot-Kette bündelt.

## Proof-Verifier-Fehler (ZK)

- **First action:** Öffne das [ZK-Backend-Playbook](../zk_backends.md#incident-runbook-rpp-stark-verification-failures) und folge der Stage-Flag-Tabelle, um den fehlerhaften Schritt zu identifizieren und die passende Gegenmaßnahme auszuwählen.【F:docs/zk_backends.md†L74-L135】
- **CLI & Konfiguration:** Nutze die im Playbook dokumentierten Proof-Replay-Befehle (`cargo test --features backend-rpp-stark --test interop_rpp_stark ...`) sowie die Feature-/Konfigurationsschalter für Backend-Wechsel oder temporäre Enforcement-Ausnahmen, bevor du Änderungen im Incident-Log dokumentierst.【F:docs/zk_backends.md†L137-L156】
- **Backend-Wechsel ohne Datenverlust:** Wenn der Incident einen Backend-Flip erfordert, folge der [Zero-data-loss backend switch procedure](../zk_backends.md#zero-data-loss-backend-switch-procedure), bevor du Nodes neu startest oder Rolling Deployments auslöst. Dokumentiere Prerequisites, Proof-Drain und die gewählte Rollout-/Rollback-Strategie im Incident-Log.【F:docs/zk_backends.md†L137-L192】
 - **Backend-Wechsel ohne Datenverlust:** Wenn der Incident einen Backend-Flip erfordert, folge der [Zero-data-loss backend switch procedure](../zk_backends.md#zero-data-loss-backend-switch-procedure), bevor du Nodes neu startest oder Rolling Deployments auslöst. Dokumentiere Prerequisites, Proof-Drain und die gewählte Rollout-/Rollback-Strategie im Incident-Log und halte den Nachweis aus `tools/backend_switch_check.sh --url http://<host>:<port> --backend <ziel>` oder dem automatisierten Integrationstest `backend_switch_routes_proofs_to_active_backend` fest, damit klar ist, wann die neue Backend-Pipeline tatsächlich Proofs verarbeitet hat.【F:docs/zk_backends.md†L137-L192】
- **Escalation:** Falls Stage-Flags trotz Replay und Konfigurationsanpassungen fehlschlagen, eskaliere gemäß dem Abschnitt „Fallback paths“ des Playbooks und protokolliere Build-/Feature-Flips sowie erneute `/status/node`-Abfragen im Incident-Ticket.【F:docs/zk_backends.md†L185-L207】

## Einsatzvorbereitung

1. Aktualisiere das Incident-Ticket mit Uhrzeit, Alert-ID und Host, bevor du eine
   der Checklisten startest.
2. Öffne das zentrale Incident-Log (Standard: `oncall/incident_log.md`) und
   protokolliere jeden Schritt aus den Checklisten.
3. Halte RPC-Token und Validator-Konfigurationspfad bereit, sodass CLI-Befehle
   (`rpp-node ...`) ohne erneute Authentifizierung ausgeführt werden können.

## Snapshot-Checksum-Fehler

Eine Warnung wie `snapshot chunk validation failed` oder ein Anstieg von
`snapshot_chunk_checksum_failures_total{kind="checksum_mismatch"}` signalisiert
lokale Korruption. Folge diesen Erstmaßnahmen, bevor du Streams neu startest oder
Peer-Wechsel einleitest.

### First Action Checklist

- [ ] **CLI:** Erfasse den Session-Status über
      [`cargo run -p rpp-chain -- validator snapshot status`](./network_snapshot_failover.md#step-1--verify-control-plane-health)
      und sichere den Output im Incident-Log.
- [ ] **Dashboards:** Öffne die [Snapshot- & Light-Client-Metriken](../observability/pipeline.md#snapshot--light-client-sync-metrics)
      und exportiere die Panels für `snapshot_stream_lag_seconds`,
      `snapshot_bytes_sent_total` sowie `light_client_chunk_failures_total`.
- [ ] **Audit-Log:** Exportiere die `snapshot_validator`-Warnungen mit
      `journalctl -u rpp-node -t snapshot_validator` und hänge den Export an die
      Artefaktensammlung für die
      [Phase‑3-Beweislage](./phase3_acceptance.md#snapshot-slis--replay-evidenz).

### Nächste Schritte

1. Prüfe das lokale Manifest und Chunk-Verzeichnis wie in der
   [Background Chunk Validation](../network/snapshots.md#background-chunk-validation)
   beschrieben. Ersetze beschädigte Dateien aus einem sauberen Snapshot oder
   fordere einen frischen Export beim Peer an.
2. Nutze das [Failover-Runbook](./network_snapshot_failover.md) für Resume-
   Versuche oder Peer-Wechsel. Wiederhole die Checkliste nach jedem Eingriff.
3. Dokumentiere Recovery, neue Checksummen sowie Dashboard-Screenshots im
   Incident-Log und verknüpfe sie mit dem entsprechenden Phase‑3-Checklisteneintrag.

## Tier-Policy-Drift erkennen

Policy-Drift-Alerts (`rpp.node.admission.policy_drift_detected_total`) deuten auf
Abweichungen zwischen Live-Policies, Persistenz und Audit-Log hin. Sichere die
Belege, bevor du Änderungen akzeptierst oder zurückrollst.

### First Action Checklist

- [ ] **CLI:** Ziehe den aktuellen Stand mit
      [`GET /p2p/admission/policies`](../runbooks/observability.md#admission-audit-abfragen)
      oder `cargo run -p rpp-chain -- validator admission backups download` und lege den Dump im
      Incident-Log ab.
- [ ] **Dashboards:** Kontrolliere die Admission-Metriken im
      [Pipeline-Dashboard](../observability/pipeline.md#snapshot--light-client-sync-metrics)
      sowie spezifische Drift-Panels (`policy_drift_detected_total`) gemäß dem
      [Admission-Runbook](./admission.md#reconciliation-checks).
- [ ] **Audit-Log:** Paginierte Exporte aus
      [`GET /p2p/admission/audit`](../runbooks/observability.md#admission-audit-abfragen)
      sichern, um fehlende oder widersprüchliche Einträge hervorzuheben.

### Nächste Schritte

1. Vergleiche Policy-Dumps mit dem auf Disk konfigurierten Pfad
   (`network.admission.policy_path`) und führe bei Abweichungen einen Restore
   über die [Backup-CLI](./admission.md#backups-and-restores) durch.
2. Hält Drift trotz Restore an, stoppe Admission-Änderungen und eskaliere an das
   Security-Team mit Hinweis auf die betroffenen Audit-Einträge.
3. Verknüpfe Dumps, Audit-Exports und Dashboard-Screenshots mit der
   [Phase‑3-Checkliste](./phase3_acceptance.md#tier-admission-persistenz--audit).

## Dual-Approval-Eskalationen

Fehlende Zweitfreigaben bei `POST /p2p/admission/policies` oder Restore-Vorgängen
lösen Audit-Alerts aus und erfordern unmittelbare Abstimmung mit den
Genehmigenden. Nutze die folgenden Schritte, um Nachweise zu sichern und den
Rollback vorzubereiten.

### First Action Checklist

- [ ] **CLI:** Wiederhole die Anfrage mit `--dry-run` oder `--approval`-Flags über
      die [Admission-CLI](./admission.md#dual-approval-workflow), um die fehlende
      Rolle zu identifizieren und die Payload im Incident-Log zu speichern.
- [ ] **Dashboards:** Überwache `rpp.node.admission.approval_missing_total` und
      verwandte Panels in den [Admission-Dashboards](../observability/pipeline.md#snapshot--light-client-sync-metrics)
      für weitere Fehlversuche.
- [ ] **Audit-Log:** Ziehe den entsprechenden Eintrag via
      [`GET /p2p/admission/audit?offset=0&limit=50`](../runbooks/observability.md#admission-audit-abfragen)
      sowie das zugehörige Ticket/Change-Request-Protokoll.

### Pending/Freigabe/Ablehnung/Wiederherstellung

Stütze dich auf die vier Incident-Listen aus dem [Admission-Runbook](./admission.md#first-action-checklisten), wenn
die Eskalation konkret eine Pending-Queue, Freigabe, Ablehnung oder einen
Restore betrifft:

- [ ] **Pending-Approval:** `cargo run -p rpp-chain -- validator admission pending list/show`
      laufen lassen, Diff/Screenshots ins Incident-Log legen und das Security-
      Team aktiv informieren.
- [ ] **Freigabe:** Vor der Approve-Entscheidung den Policy-Status prüfen
      (`admission status`), die Freigabe dokumentieren und Policies erneut
      exportieren.
- [ ] **Ablehnung:** Ablehnungsgrund via CLI im JSON-Format sichern, Alerts
      checken und Governance/Requester:innen informieren.
- [ ] **Wiederherstellung:** Audit-Slice und Backup erheben, Restore via CLI
      mit Dual-Approval durchführen, anschließend Signatur-Verify ausführen.

### Nächste Schritte

1. Fordere die fehlende Rolle zur Freigabe auf oder veranlasse einen
   [Backup-Restore mit vollständigen Approvals](./admission.md#backups-and-restores),
   falls die Änderung unzulässig ist.
2. Aktualisiere das Incident-Log mit dem endgültigen Audit-Eintrag (Erfolg oder
   Rollback) und hinterlege eine Kopie in der Phase‑3-Artefaktensammlung.
3. Eskaliere an das Governance/GRC-Team, wenn wiederholt Freigaben fehlen oder
   die Audit-Log-Kette unterbrochen erscheint.

## Snapshot-Verifier schlägt fehl

Release-Pipelines stoppen, sobald `cargo xtask snapshot-verifier` oder der
GitHub-Job `snapshot-verifier` Abweichungen im Aggregat-Report melden. Sammle
unmittelbar Belege und eskaliere gemäß folgender Kette:

**Eskalationskette & Ansprechpartner:innen**

1. **Release On-Call** (`#releng-oncall`, Telefon `+49 30 1234 5678`) – bestätigt
   die Fehlermeldung und blockiert weitere Promote-Jobs.
2. **Release Engineering Lead** (Mara Schulz, mara.schulz@example.com) –
   koordiniert Neuversuche und entscheidet über Rollback/Hotfix.
3. **Compliance Liaison** (Ishan Patel, ishpatel@example.com) – informiert Audit
   und prüft, ob Freigabefenster verschoben werden müssen.
4. **Security Duty** (sec-duties@example.com) – bewertet, ob Integrität der
   Snapshot-Artefakte kompromittiert ist und initiiert forensische Sicherung.

**Sofortmaßnahmen & CLI-Kommandos**

- [ ] Wiederhole die Aggregation lokal mit
      `cargo xtask snapshot-verifier` und sichere das Verzeichnis
      `target/snapshot-verifier-smoke/` als Zip-Anhang.
- [ ] Prüfe den produktiven Report mit
      `cargo xtask verify-report --report dist/artifacts/<target>/snapshot-verify-report.json`
      gegen das Schema `docs/interfaces/snapshot_verify_report.schema.json`.
- [ ] Führe `cargo run -p rpp-chain -- validator snapshot verify --config <pfad>` gegen das
      zuletzt veröffentlichte Bundle aus, um Chunk-Abweichungen auszuschließen.

**Logs, Alerts & Artefakte**

- Exportiere die CI-Logs des Jobs `snapshot-verifier` (Actions → Job → "Download
  all logs") und hänge sie dem Incident-Log an.
- Sichere `target/snapshot-verifier-smoke/snapshot-verify-report.json` plus
  `.sha256`, sowie den neuesten Release-Report unter
  `dist/artifacts/<target>/snapshot-verify-report.json`.
- Dokumentiere Prometheus-Graph & Alert-Timeline von
  `SnapshotVerifierFailure` (`alerts/compliance_controls.yaml`).
- Hinterlege die CLI-Ausgaben (`stdout`/`stderr`) der oben genannten Kommandos
  im Incident-Log und im Phase‑A/Phase‑3 Evidenzordner.

## WORM-Export fehlerhaft

Ein Fehler im WORM-Pfad gefährdet die revisionssichere Audit-Trail-Aufbewahrung.
Typische Signale sind rote Nightly-Checks (`worm-export-smoke`) oder der Alert
`WormExportNightlyFailure`. Handhabe den Vorfall nach dieser Kette:

**Eskalationskette & Ansprechpartner:innen**

1. **Compliance On-Call** (`#compliance-oc`, Telefon `+49 30 9876 5432`) –
   stoppt Archiv-Freigaben und erfasst die ersten Artefakte.
2. **Storage Engineering** (Lead: Jin Park, jin.park@example.com) – analysiert
   Exporter-Logs und behebt Pipeline-/S3-Konfigurationsfehler.
3. **Network Operations** (net-ops@example.com) – überprüft Admission-Backups
   und stellt temporäre Backups bereit.
4. **Security Duty** (sec-duties@example.com) – bewertet Auswirkungen auf die
   Unveränderbarkeit und initiiert zusätzliche Logging/Retention-Checks.

**Sofortmaßnahmen & CLI-Kommandos**

- [ ] Führe `cargo xtask test-worm-export` aus und archiviere
      `target/worm-export-smoke/` mitsamt `worm-export-summary.json`.
- [ ] Sammle die Laufzeit-Logs aus dem Validator (`journalctl -u rpp-node --grep
      "worm export"`) sowie das Admission-Audit via
      `cargo run -p rpp-chain -- validator admission backups download`.
- [ ] Falls das Produktivsystem betroffen ist, pausiere Exporte kurzfristig über
      den Betriebs-Workflow (z. B. `systemctl stop rpp-node`) nach Rücksprache mit
      Compliance und dokumentiere Uhrzeit sowie Ticket.

**Logs, Alerts & Artefakte**

- Lade die Nightly-Logs/Artefakte des Jobs `worm-export-smoke` herunter.
- Sichere die mit `test-worm-export` erzeugten Dateien (`audit.jsonl`,
  `worm/`, `retention.meta`, `worm-export-summary.json`).
- Dokumentiere den Alert-Verlauf `WormExportNightlyFailure` sowie die Metrik
  `worm_export_failures_total` in Prometheus/Grafana.
- Erfasse jede manuelle Stop/Start-Aktion des Validators (z. B.
  `systemctl stop|start rpp-node`) mit Timestamp im Incident-Log.

## Phase‑C Kontrollen

Die folgenden Kontrollen stammen aus Phase C und adressieren Langzeit-
Retention, Evidenzintegrität sowie den Chaos-Drill für Snapshot-Partitionen.
Jede Kontrolle besitzt eine eigene Eskalationskette und nutzt Nightly-
Artefakte für die Erstdiagnose.

> **Review 28. Aug 2026:** Evidence-Bundle
> `phase3-evidence/nightly-2026-08-21/phase3-evidence-2026-08-21T09-00-42Z.tar.gz`
> liegt im Artefakt-Archiv; Manifest- und Bundle-Prüfsummen sind dokumentiert
> (`sha256` `76c8f0c99a8be379fc5a18d28288fd4099dc41f47ea70e0cd950e18b9e8f12f4` /
> `8e2c1a6fb2df5cd0bfdf66c75dd8fa24cbe2a3ed56bfec4d3c19d67b2c4a9e11`).

### Finale Hinweise Phase-C Sign-off

<a id="phase-c-kontrollen"></a>

- **Evidence Bundle & Manifest:** Aktueller Ablageort siehe
  [`docs/status/artifacts/phase3_evidence_bundle_2026-08-21.json`](../status/artifacts/phase3_evidence_bundle_2026-08-21.json);
  das Manifest verweist auf SLO-Summary, Replay-Telemetrie, Admission-/WORM-
  Nachweise und Chaos-Report mitsamt SHA256-Prüfsummen.【F:docs/status/artifacts/phase3_evidence_bundle_2026-08-21.json†L2-L31】
- **Nightly-Reports:** Für Wiederholungen/Spot-Checks immer den
  [Weekly-Statusbericht](../status/weekly.md#phase-c-kontrollen-nightly) sowie
  [`nightly_status.md`](../../nightly_status.md) konsultieren; dort sind die
  Ampel-Status und Nightly-Drills verlinkt.【F:docs/status/weekly.md†L10-L57】【F:nightly_status.md†L1-L3】
- **Acceptance-Update:** Die
  [Phase‑C Acceptance Checklist](./phaseC_acceptance.md#evidence-bundle-integrity)
  dokumentiert die abschließende Abnahme inkl. Artefaktpfaden und Prüfsummen.【F:docs/runbooks/phaseC_acceptance.md†L50-L86】
> Enthalten sind das Phase‑C SLO-Summary, die Timetoke-Replay-Telemetrie vom
> 21. Aug 2026, der Nightly WORM-Retention-Report sowie der Chaos-Drill-Report
> `snapshot_partition_report.json`. Verweise: Nightly SLO-/Telemetry-Exports in
> [`docs/status/phaseC_slo_summary.md`](../status/phaseC_slo_summary.md) und WORM-
> Retention-Nachweise in [`docs/status/phaseC_retention_summary.md`](../status/phaseC_retention_summary.md).
> Der Chaos-Drill-Status ist im Weekly-Report Abschnitt „Phase‑C Kontrollen“
> dokumentiert.【F:docs/status/artifacts/phase3_evidence_bundle_2026-08-21.json†L2-L31】【F:docs/status/phaseC_slo_summary.md†L1-L36】【F:docs/status/phaseC_retention_summary.md†L7-L33】【F:docs/status/weekly.md†L6-L21】

### WORM-Retention-Check schlägt fehl

**Eskalationskette & Ansprechpartner:innen**

1. **Compliance On-Call** (`#compliance-oc`, Telefon `+49 30 9876 5432`) –
   übernimmt das Incident-Ticket, sperrt Freigaben und fordert das Nightly-
   Artefakt `worm_retention_report.json` an.
2. **Storage Engineering** (Lead: Jin Park, jin.park@example.com) – prüft
   Retention-Metadaten, Signaturen und prüft das zugrunde liegende Bucket-
   Setup gegen die [WORM-Export-Dokumentation](./worm_export.md).
3. **Security Duty** (sec-duties@example.com) – bewertet Manipulations-
   verdacht und initiiert forensische Sicherungen des Audit-Pfads.

### First Action Checklist

- [ ] Lade das Nightly-Artefakt `worm-export-smoke` herunter und
      verlinke `worm_retention_report.json` sowie das zugehörige `manifest.json`
      aus dem Evidence-Bundle (`phase3-evidence-<timestamp>`).
- [ ] Vergleiche im Report die Felder `stale_entries`, `unsigned_entries` und
      `retention_violations` mit den Nightly-Schwellenwerten; dokumentiere die
      Abweichungen im Incident-Log und referenziere die betroffenen Summaries.
- [ ] Führe `cargo xtask worm-retention-check --report <pfad>` erneut aus, um
      lokale Gegenproben zu erhalten, und hänge den CLI-Output an die
      Incident-Dokumentation.

**Investigation & Artefakte**

- Korrelieren `worm_retention_report.json` mit `worm-export-summary.json`
  (Nightly `worm-export-smoke`), um festzustellen, welche Signaturen oder
  Retention-Fenster betroffen sind.
- Nutze `journalctl -u rpp-node --grep "worm export"` und die Admission-
  Backups, um Lücken in den Audit-Streams zu identifizieren.
- Bei wiederholten Abweichungen eskaliere an Governance/GRC und dokumentiere
  Korrekturmaßnahmen in der [Compliance Overview](../governance/compliance_overview.md).

### Evidence-Bundle-Verifizierung fehlgeschlagen

**Eskalationskette & Ansprechpartner:innen**

1. **Compliance On-Call** (`#compliance-oc`) – koordiniert das Review des
   Nightly-Artefakts `phase3-evidence-<timestamp>` und informiert Audit.
2. **Release Engineering Lead** (Mara Schulz, mara.schulz@example.com) –
   prüft das Sammelskript (`cargo xtask collect-phase3-evidence`) auf fehlende
   Quellen oder Validierungsfehler.
3. **Security Duty** – bewertet Integritätsverletzungen am Evidence-Bundle
   (fehlende Signaturen, Manipulationshinweise) und sperrt ggf. weitere
   Bundles.

### First Action Checklist

- [ ] Öffne das Nightly-Bundle `phase3-evidence-<timestamp>` und kontrolliere
      `manifest.json` auf fehlende Einträge (`missing`-Abschnitt) sowie die
      Prüfsummen der Kategorien „WORM export evidence“ und „Snapshot reports“.
- [ ] Wiederhole `cargo xtask collect-phase3-evidence --output-dir <tmp>` lokal,
      um Validierungs-Logs (`verify.log`) zu erhalten, und vergleiche die
      erzeugte Struktur mit dem Nightly-Artefakt.
- [ ] Sichere `verify.log`, `manifest.json` und betroffene Belegdateien im
      Incident-Log und verlinke den passenden Abschnitt im
      [Evidence Bundle Index](../governance/evidence_bundle_index.md).

**Investigation & Artefakte**

- Prüfe im Manifest die Referenzen auf `worm_retention_report.json` und
  `snapshot-verify-report.json`, um fehlende oder ungültige Prüfsummen
  einzugrenzen.
- Nutze `cargo xtask verify-report --report <pfad>` und `sha256sum` für
  Snapshot-Reports, sowie `jq '.entries[]' worm_retention_report.json` für
  WORM-Deltas, um Abweichungen zu bestätigen.
- Bei systematischen Fehlern im Sammelskript eröffne ein Engineering-Ticket
  und dokumentiere Hotfixes/Workarounds im Evidence-Bundle-Manifest.

### Snapshot-Chaos-Run / Partition Drill fehlgeschlagen

**Eskalationskette & Ansprechpartner:innen**

1. **Release On-Call** (`#releng-oncall`, Telefon `+49 30 1234 5678`) –
   stoppt abhängige Release-Jobs und fordert das Nightly-Artefakt
   `snapshot_partition_report.json` an.
2. **Network Operations** – analysiert Partitionierung, Peer-Verfügbarkeit und
   Streaming-Lag anhand der Report-Deltas und startet Recovery-Maßnahmen.
3. **Compliance Liaison** (Ishan Patel, ishpatel@example.com) – stellt sicher,
   dass der Drill im Phase‑C-Evidence-Log dokumentiert und an Auditor:innen
   kommuniziert wird.

### First Action Checklist

- [ ] Lade das Nightly-Artefakt `snapshot-partition` und sichere
      `snapshot_partition_report.json` inkl. grafischer Anhänge (`timeline.png`,
      falls vorhanden) im Incident-Log.
- [ ] Prüfe im Report die Felder `resume_latency_seconds` und
      `retry_chunks` gegenüber den Phase‑C-Grenzwerten (SLO ≤ 120 s Resume,
      ≤ 25 Retries) und notiere Abweichungen.
- [ ] Führe `cargo xtask snapshot-health --report <pfad>` oder
      `cargo run -p rpp-chain -- validator snapshot status` gegen das betroffene Cluster aus,
      um den aktuellen Stream-Lag zu bestätigen.

**Investigation & Artefakte**

- Vergleiche `snapshot_partition_report.json` mit dem Prometheus-Export
  (`snapshot_stream_lag_seconds`, `snapshot_chunk_checksum_failures_total`)
  und dokumentiere Graphen im Incident-Log.
- Korrelieren Partition-Deltas mit Peer-Logs (`journalctl -u rpp-node -t
  snapshot_validator`), um fehlerhafte Peers oder Netzpfade zu identifizieren.
- Verweise auf das [Snapshot-Failover-Runbook](./network_snapshot_failover.md)
  für Recovery-Schritte und hänge das Ergebnis (z. B. `resume_success=true`)
  dem Phase‑C-Evidence-Archiv an.
