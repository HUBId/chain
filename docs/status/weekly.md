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
nachverfolgen. Die Operator-Dokumentation enthält detaillierte Belege für Phase‑2-Audits.

### Highlights
- **Tamper-Tests:** `cargo xtask test-consensus-manipulation` läuft für STWO und Plonky3; die Cases in
  `tests/consensus/consensus_certificate_tampering.rs` sind als Abnahmebeleg dokumentiert.【F:xtask/src/main.rs†L1-L120】【F:tests/consensus/consensus_certificate_tampering.rs†L1-L160】
- **Observability:** Neues Dashboard `docs/dashboards/consensus_grafana.json` plus Handbuch
  `docs/observability/consensus.md` liefern Panels und Alert-Vorlagen für
  `consensus_vrf_verification_time_ms` und `consensus_quorum_verifications_total`.【F:docs/dashboards/consensus_grafana.json†L1-L200】【F:docs/observability/consensus.md†L1-L70】
- **Runbooks:** Operator Guide und Observability-Runbook beschreiben Simnet-Logs, RPC-Checks und
  Grafana-Screenshots für Phase‑2-Freigaben.【F:docs/rpp_node_operator_guide.md†L120-L174】【F:docs/runbooks/observability.md†L1-L120】
- **Regression-Orchestrierung:** Der neue Binary `tools/simnet/src/bin/regression.rs` fährt VRF-/Snapshot-/Gossip-Szenarien
  sequenziell, erzeugt JSON/HTML-Berichte und läuft in CI/Nightly als `simnet-regression`-Job.【F:tools/simnet/src/bin/regression.rs†L1-L240】【F:.github/workflows/ci.yml†L184-L226】【F:.github/workflows/nightly.yml†L80-L120】
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

