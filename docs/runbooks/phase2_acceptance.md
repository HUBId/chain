# Phase‑2 Acceptance Checklist

Nutze diese Checkliste, um den Abschluss der Phase‑2-Anforderungen (VRF-/Quorum-Proofs,
Simulationsabdeckung, Observability und Release-Metadaten) nachvollziehbar zu dokumentieren.
Jeder Punkt erwartet einen verlinkten Nachweis (Log, Dashboard-Screenshot, Report oder
Release-Asset).

## Konsensus- und Simulationsnachweise

- [ ] **Regression-Sweep archiviert.** `cargo run -p simnet --bin regression` mit Produktions-Flaggen
      ausführen (bzw. CI/Nightly-Artefakt verwenden) und `regression.json`/`regression.html`
      im Abnahmeordner speichern. Reports listen p95 prove/verify, Tamper-Zähler und P2P-Summaries
      für VRF-/Quorum-Stress, Snapshot-Rebuild und Gossip-Backpressure.【F:tools/simnet/src/bin/regression.rs†L1-L240】【F:tools/simnet/scenarios/snapshot_rebuild.ron†L1-L13】【F:tools/simnet/scenarios/gossip_backpressure.ron†L1-L13】
- [ ] **Tamper-Rejections bestätigt.** Logs aus `target/simnet/consensus-quorum` (oder dem Regression-Run)
      belegen abgelehnte VRF-/Quorum-Manipulationen (`invalid VRF proof`, `duplicate precommit detected`).【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】
- [ ] **Dashboard-Screenshots abgelegt.** Grafana-Panels `consensus_vrf_verification_time_ms` und
      `consensus_quorum_verifications_total` dokumentieren p95-Werte und `result="failure"`-Slices
      während der Tests.【F:docs/dashboards/consensus_grafana.json†L1-L200】

## Observability & Alerting

- [ ] **VRF-/Quorum-Alerts getestet.** Prometheus-Regeln aus
      `docs/observability/alerts/consensus_vrf.yaml` aktiviert, Alerts ausgelöst
      (oder Drill per `amtool silence` dokumentiert) und Response nach Playbook abgearbeitet.【F:docs/observability/alerts/consensus_vrf.yaml†L1-L47】【F:docs/runbooks/observability.md†L1-L160】
- [ ] **Incident-Log aktualisiert.** Für jeden Alert Zeitstempel, `reason`-Label und Gegenmaßnahme im
      On-Call-Log festgehalten; Regression-Reports/Grafana-Screenshots verlinkt.【F:docs/runbooks/observability.md†L120-L160】

## Release-Metadaten & Dokumentation

- [ ] **Release-Notizen mit Proof-Metadaten aktualisiert.** `docs/release_notes.md` enthält für die
      aktuelle Version Circuit-IDs, Constraint-Zählungen und Backend-Support; automatische Einbettung über
      den Release-Workflow geprüft.【F:docs/release_notes.md†L1-L160】【F:.github/workflows/release.yml†L1-L120】
- [ ] **Operator-/ADR-Referenzen gesetzt.** `docs/rpp_node_operator_guide.md` und
      `docs/adr/0001_consensus_proofs.md` verlinken die neuen Release-Metadaten, damit Auditor:innen die
      Proof-Versionierung nachvollziehen können.【F:docs/rpp_node_operator_guide.md†L120-L210】【F:docs/adr/0001_consensus_proofs.md†L1-L120】
- [ ] **Artefakte im Statusbericht vermerkt.** Weekly-Status aktualisiert, um Regression-Job, Alerts
      und Release-Metadaten hervorzuheben (Anker für Stakeholder).【F:docs/status/weekly.md†L20-L120】

> ✅ Erst wenn alle Punkte abgehakt und mit Belegen hinterlegt sind, gilt Phase 2 als betriebsbereit.
