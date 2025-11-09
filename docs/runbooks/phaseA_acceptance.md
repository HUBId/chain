# Phase‑A Acceptance Checklist

Phase A tracks the external hardening deliverables for pruning snapshots. This
checklist lists the artefacts reviewers must inspect before signing off the
milestone.

## Snapshot provenance

- [ ] **Aggregated verifier report vorhanden.** Führe `scripts/build_release.sh`
      mit gesetztem `SNAPSHOT_MANIFEST_PUBKEY_HEX` für jedes Release-Target aus
      (oder verweise auf den Release-Workflow `Build <target>`). Der Lauf erzeugt
      pro Manifest `*-verify.json` sowie das Bündel
      `snapshot-verify-report.json` und `snapshot-verify-report.json.sha256`
      unter `dist/artifacts/<target>/`. Hinterlege die JSON- und SHA256-Datei als
      Pflichtartefakte, archiviere die Einzelberichte für spätere Audits und
      verweise im Evidence-Bundle auf den [`Evidence Bundle Index`](../governance/evidence_bundle_index.md).【F:scripts/build_release.sh†L273-L348】【F:.github/workflows/release.yml†L122-L209】【F:docs/governance/evidence_bundle_index.md†L9-L49】
      Validiere den JSON-Inhalt zusätzlich lokal via
      `cargo xtask verify-report --report dist/artifacts/<target>/snapshot-verify-report.json`
      – das Kommando prüft sowohl die Aggregation als auch Einzelreports gegen
      `docs/interfaces/snapshot_verify_report.schema.json`. Führe das Ergebnis im
      Übergabeprotokoll auf.【F:xtask/src/main.rs†L1594-L1677】【F:docs/interfaces/snapshot_verify_report.schema.json†L1-L173】
- [ ] **CLI-Verifikation nachvollzogen.** Dokumentiere mindestens einen Lauf von
      `rpp-node validator snapshot verify --config <pfad>` gegen das produktive
      Bundle. Der Report muss `signature_valid=true` und keine Chunk-Abweichungen
      melden; bei Fehlern liefert das CLI Exit-Code `2` (Signatur) oder `3`
      (Segmentabweichungen). Hänge den JSON-Output an die Übergabeunterlagen, damit
      Reviewer:innen die lokale Prüfung nachverfolgen können.【F:rpp/node/src/main.rs†L140-L227】【F:rpp/node/tests/snapshot_verify.rs†L1-L123】
- [ ] **SHA256 im Freigabeprotokoll festgehalten.** Die Release Notes enthalten
      den Abschnitt „Snapshot verifier attestation“ mit den Hashes aus den
      `.sha256`-Dateien. Vergleiche mindestens einen Wert lokal via
      `sha256sum dist/artifacts/<target>/snapshot-verify-report.json` und
      dokumentiere den Abgleich im Freigabeprotokoll.【F:.github/workflows/release.yml†L210-L233】
- [ ] **CI/Nightly-Referenzen verlinkt.** Verweise auf den CI-Job
      `snapshot-verifier`, der das synthetische Prüfbündel unter
      `target/snapshot-verifier-smoke/` erzeugt, sowie auf die Release-Artefakte
      `snapshot-verifier-<target>` im Actions-Tab. So lässt sich das Ergebnis
      reproduzieren, ohne die produktiven Artefakte neu zu signieren.【F:.github/workflows/ci.yml†L369-L397】【F:.github/workflows/release.yml†L150-L209】
- [ ] **Telemetry-Gate überprüft.** Prüfe im Prometheus-/OTLP-Scrape, dass der
      Zähler `snapshot_verify_failures_total` nach dem Release-Lauf weiterhin
      `0` ist. Bei einem Anstieg muss der Alert
      `SnapshotVerifierFailure` (siehe [`alerts/compliance_controls.yaml`](../observability/alerts/compliance_controls.yaml))
      auslösen; dokumentiere im Übergabeprotokoll, dass der Alarm grün bleibt
      und verlinke ggf. den Grafana-Panel-Screenshot.
- [ ] **Incident-Response-Referenz aktualisiert.** Verweise im Übergabedokument
      auf das Incident-Runbook ([Snapshot-Verifier schlägt fehl](./incident_response.md#snapshot-verifier-schlägt-fehl)), damit
      Auditor:innen die Eskalations- und Artefaktsammlung für Fehlerszenarien
      nachvollziehen können.

## WORM export audit trail

- [ ] **Nightly smoke erfolgreich.** Der Nightly-Job `worm-export` führt
      `cargo xtask test-worm-export` gegen den Append-only-Stub aus, erzeugt die
      exportierten JSON-Objekte plus `worm-export-summary.json` und lädt das
      Artefakt `worm-export-smoke` hoch. Verlinke den Lauf und prüfe, dass die
      Summary `signature_valid=true` meldet.【F:.github/workflows/nightly.yml†L10-L24】【F:xtask/src/main.rs†L120-L318】
- [ ] **Evidence-Bundle aktualisiert.** Bestätige, dass
      `cargo xtask collect-phase3-evidence` die WORM-Logs (`target/worm-export-smoke`)
      samt Signaturen ins Bundle kopiert, die Manifestdatei die Quellen
      aufführt und der [`Evidence Bundle Index`](../governance/evidence_bundle_index.md)
      die Pfade dokumentiert. Dokumentiere Speicherort und Prüfsumme im
      Freigabeprotokoll.【F:xtask/src/main.rs†L1516-L1584】【F:xtask/src/main.rs†L1606-L1644】【F:docs/governance/evidence_bundle_index.md†L51-L85】
- ✅ **Bootstrap-Guard aktiv.** Produktions-Release-Channels (`canary`/`mainnet`)
  verweigern den Start, wenn `network.admission.worm_export` keinen S3-Endpoint,
  Zugangsdaten und ein Retention-Fenster setzt. Der Guard schreibt einen
  Bootstrap-Fehler und erhöht die Metrik `worm_export_misconfigured_total`; prüfe
  Logs und Prometheus-Export beim Abbruch.【F:rpp/node/src/lib.rs†L520-L590】
- [ ] **Nightly-Metriken grün.** Validere, dass der Prometheus-Zähler
      `worm_export_failures_total` während des Nightly-Laufs nicht steigt und
      der Alert `WormExportNightlyFailure` (siehe [`alerts/compliance_controls.yaml`](../observability/alerts/compliance_controls.yaml))
      in Grafana/Alertmanager grün bleibt. Hänge bei Abweichungen das Nightly-Log
      sowie die Alert-Timeline an das Protokoll.
- [ ] **Incident-Runbook referenziert.** Ergänze in den Freigabeunterlagen den
      Hinweis auf den Abschnitt [„WORM-Export fehlerhaft“](./incident_response.md#worm-export-fehlerhaft), sodass On-Call-Teams
      die Eskalationskette und Artefaktliste unmittelbar finden.

## Exit-Kriterien

Die Phase ist abgeschlossen, wenn alle Kontrollpunkte erfüllt sind und die
nachfolgende Checkliste vollständig abgehakt ist:

| Status | Kriterium | Nachweis & Links |
| --- | --- | --- |
| [ ] | **Verifier-Report signiert.** `"all_passed": true` im Aggregat und `signature_valid=true` in allen Einzelreports; Hashwerte im Protokoll dokumentiert. | [CI-Artefakt `snapshot-verifier`](https://github.com/<org>/<repo>/actions/runs/<snapshot-run-id>#artifact), [Workflow `ci.yml` (Job `snapshot-verifier`)](../../.github/workflows/ci.yml#L398-L412), [Evidence-Bundle-Verweis](../governance/evidence_bundle_index.md#snapshot-verifier-nachweise) |
| [ ] | **WORM-Smoke-Test grün.** Nightly-Summary `signature_valid=true`, keine Fehlalarme (`WormExportNightlyFailure`). | [Nightly-Artefakt `worm-export-smoke`](https://github.com/<org>/<repo>/actions/runs/<worm-run-id>#artifact), [Workflow `nightly.yml` (Job `worm-export`)](../../.github/workflows/nightly.yml#L10-L46), [Runbook WORM-Export](./worm_export.md) |
| [ ] | **Threat-Model-Review dokumentiert.** Sign-off des Security-Teams und aktualisierte Findings im Threat Model. | [Review-Artefakt `threat-model-review`](https://github.com/<org>/<repo>/actions/runs/<review-run-id>#artifact), [Threat Model Addendum](../security/threat_model.md), [Audit-Protokoll](../THREAT_MODEL.md) |
| [ ] | **Operator-Guides aktualisiert.** Änderungen aus Phase A in Betriebshandbüchern und Onboarding-Guides nachgezogen. | [Operator Guide](../rpp_node_operator_guide.md), [Runbook `startup`](./startup.md), [Incident-Response-Checkliste](./incident_response.md) |

Vor der Freigabe müssen alle Links im Übergabeprotokoll geprüft und in den
Release-Notes referenziert werden. Änderungen an Artefakten oder Workflows sind
erneut gegenzuzeichnen.

## Finale Abnahme

| Rolle | Name | Datum | Unterschrift / Review |
| --- | --- | --- | --- |
| Product Owner | | | |
| Security Lead | | | |
| Operations Lead | | | |
| Audit/Compliance | | | |
