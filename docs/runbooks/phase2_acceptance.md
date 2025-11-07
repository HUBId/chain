# Phase‑2 Acceptance Checklist

Diese Checkliste bündelt alle Nachweise, die für die Abnahme der Phase‑2-Deliverables
notwendig sind. Jeder Punkt erwartet einen verlinkten Beleg (Artefakt im Repository,
CI-Artefakt, Dashboard-Screenshot oder Ticket-Referenz).

## Artefaktliste

### Erweiterte Proofs & Metadaten
- [ ] **Proof-Bundles versioniert.** Erweiterte Konsens-, Pruning- und Snapshot-Proofs sind
      als reproduzierbare Artefakte abgelegt (z. B. `release/`-Assets oder signierte Nightly
      Bundles) und dokumentieren Circuit-ID, Constraint-Zählung sowie unterstützte Backends.
- [ ] **Proof-Metadaten publiziert.** Release-Notizen und Operator-Dokumentation verlinken
      die aktuelle Proof-Version inkl. Hashes/Checksums, damit Auditor:innen die Artefakte
      verifizieren können.

### Tamper-Tests
- [ ] **Manipulationssuite bestanden.** `cargo xtask test-consensus-manipulation` läuft für
      STWO und Plonky3 grün; Logs mit fehlgeschlagenen Tamper-Versuchen sind archiviert.
- [ ] **Regressionstabelle aktualisiert.** `docs/testing/consensus_regressions.md` führt die
      Tamper-Szenarien mit Ergebnisstatus, Datum und verantwortlichem Reviewer auf.

### Simnet-Szenarien
- [ ] **Nightly `simnet` grün.** Die täglichen Läufe (`consensus_quorum_stress`,
      `ci_block_pipeline`, `ci_state_sync_guard`) liefern erfolgreiche JSON/HTML-Reports.
- [ ] **Regression-Run dokumentiert.** Der manuelle/CI-Regressionslauf (`tools/simnet`
      Regression-Binary) ist verlinkt und beschreibt, wo Artefakte und Analyseberichte liegen.

### VRF- & Quorum-Metriken
- [ ] **Dashboard-Screenshots archiviert.** Grafana-Panels für
      `consensus_vrf_verification_time_ms` und `consensus_quorum_verifications_total` zeigen
      p95-Latenzen und Fehlerraten während der Nightly-/Tamper-Läufe.
- [ ] **Prometheus-Queries dokumentiert.** Die genutzten Queries oder Aufzeichnungslinks
      sind notiert, inklusive erwarteter Schwellenwerte und Observability-Runbook-Verweise.

### Alerts & On-Call
- [ ] **Alerts aktiviert.** Prometheus-/Alertmanager-Regeln für VRF-/Quorum-Anomalien sind
      aktiv, getestet (Alert-/Silence-Drill) und mit Ticket/Log verlinkt.
- [ ] **On-Call-Log gepflegt.** Incident-Log oder Runbook-Vermerk beschreibt das Vorgehen,
      Eskalationspfade und Follow-up-Aufgaben.

## Exit-Kriterien

Phase 2 gilt als abgenommen, sobald alle Kontrollkästchen oben abgehakt und mit Nachweisen
unterlegt sind **und** folgende Bedingungen erfüllt werden:

- ✅ **Tamper-Suite bestanden:** Alle Manipulationsläufe schlagen fehl und sind im Artefakt-Log
  dokumentiert.
- ✅ **Simnet nightly grün:** Die Nightly-Simnet-Pipeline liefert über den definierten Zeitraum
  (mindestens drei aufeinanderfolgende Nächte) ausschließlich erfolgreiche Runs.
- ✅ **VRF-/Quorum-Metriken innerhalb der Limits:** p95-Latenzen und Fehlerraten bleiben unter
  den im Observability-Runbook festgelegten Schwellen.
- ✅ **Alerts aktiviert:** Die produktiven Alarmregeln feuern erwartungsgemäß und sind nachweislich
  in die On-Call-Eskala eingebunden.
- ✅ **Proof-Artefakte veröffentlicht:** Erweiterte Proof-Bundles und Metadaten sind versioniert,
  signiert und in Roadmap/Status-Dokumenten verlinkt.

Erst wenn jede Bedingung erfüllt ist und Reviewer:innen auf alle Verweise zugreifen können,
ist die Phase offiziell abgeschlossen.
