# Wöchentlicher Statusbericht – Vorlage

> Diese Vorlage strukturiert die wöchentliche Berichtserstellung. Ersetze die Platzhalter (☐) durch den aktuellen Status,
> konkrete Daten und Links zu den jeweiligen Artefakten.

## Kalenderwoche ☐ (Phase ☐)

**Zusammenfassung:** ☐

### Highlights
- ☐
- ☐
- ☐

### Nächste Schritte
- ☐
- ☐
- ☐

### CI-Nachweise & Reviews
- `snapshot-verify-report`: [CI-Artefakt `snapshot-verifier`](https://github.com/<org>/<repo>/actions/runs/<run-id>#artifact) – Aggregierter Report (`snapshot-verify-report.json`) inklusive SHA256. Stelle sicher, dass der Link auf den aktuellen Merge-/Nightly-Run zeigt.
- `worm-export-smoke`: [CI-Protokoll `worm-export-smoke`](https://github.com/<org>/<repo>/actions/runs/<run-id>#summary-logs) – Laufprotokoll des Smoke-Tests inklusive Artefaktpaket `worm-export-smoke.zip`.
- `threat-model-review`: [Review-Protokoll](https://github.com/<org>/<repo>/actions/runs/<run-id>#artifact) – Export aus dem Security-Review-Workflow (`threat-model-review.md` oder Meeting-Minutes).

### Ampelstatus
- **Tests:** ☐
- **Monitoring:** ☐
- **Operator Docs:** ☐

---

> **Hinweis:** Ergänze bei Bedarf zusätzliche Abschnitte (z. B. „Phase ☐ Tracking“, „Security Review Update“) und kopiere die obige Nachweis-Sektion in jeden relevanten Phasenblock, damit die direkten Verlinkungen zu Artefakten konsistent bleiben.
