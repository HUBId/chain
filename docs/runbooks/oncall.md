# On-Call-Handbuch

Dieses Handbuch fasst den operativen Ablauf für Bereitschaftsdienste zusammen. Es verlinkt auf die
Detail-Runbooks und Checklisten, die für Phase‑3 relevant sind, und stellt die Snapshot-CLI,
Audit-Log-Abfragen und Alert-Reaktionen in einem Ablaufdiagramm zusammen.【F:docs/runbooks/observability.md†L1-L170】【F:docs/runbooks/phase3_acceptance.md†L8-L62】

## Triage-Einstieg

1. **Telemetry-Schnellcheck.** Öffne das Observability-Runbook und die verlinkten Dashboards
   (`pipeline_overview.json`, `pipeline_proof_validation.json`, `vrf_overview.json`) für ein
   Gesundheitsbild. Die Snapshot-CLI liefert ergänzende Statusinformationen, die du direkt in das
   Incident-Log übernehmen kannst.【F:docs/runbooks/observability.md†L6-L46】【F:docs/dashboards/pipeline_overview.json†L200-L260】【F:docs/dashboards/pipeline_proof_validation.json†L1-L60】【F:docs/dashboards/vrf_overview.json†L1-L60】
2. **Runbooks nach Kategorie.** Snapshot-Ausfälle folgen dem
   [network_snapshot_failover](./network_snapshot_failover.md)-Playbook; Admission-Themen nutzt du mit dem
   [admission-Runbook](./admission.md); Telemetrie- oder Storage-Anomalien bleiben im
   [Observability-Runbook](./observability.md). Erfasse alle Links im Incident-Log, damit die Phase‑3-Checkliste
   vollständig bleibt.【F:docs/runbooks/network_snapshot_failover.md†L1-L176】【F:docs/runbooks/admission.md†L1-L120】【F:docs/runbooks/phase3_acceptance.md†L8-L62】
3. **Artefakt-Ablage.** Nach Abschluss eines Incidents aktualisierst du die
   [Phase‑3 Acceptance Checklist](./phase3_acceptance.md) mit CLI-Ausgaben, Dashboard-Screenshots und Audit-Exporten.

## Snapshot-Recovery

1. **Session anlegen oder fortsetzen.** Nutze `rpp-node validator snapshot start --peer <peer>`
   bzw. `rpp-node validator snapshot resume --session <id> --peer <peer> --plan-id <plan>`, um den
   Stream neu zu initialisieren oder fortzusetzen. Die CLI fügt automatisch Token aus der Validator-Konfiguration
   hinzu und liefert strukturierte Statuszeilen für das Incident-Log.【F:rpp/node/src/main.rs†L118-L310】
2. **Fortschritt prüfen.** `rpp-node validator snapshot status --session <id>` zeigt Chunk-Index, letzte Höhe
   und Fehlerzustände. Kopiere den Output in das Incident-Log und sichere parallel Screenshots der genannten
   Dashboards, um Phase‑3-Belege abzulegen.【F:rpp/node/src/main.rs†L118-L310】【F:docs/dashboards/pipeline_overview.json†L200-L260】【F:docs/dashboards/pipeline_proof_validation.json†L1-L60】
3. **Failover und Abbruch.** Folge bei Peer-Wechseln dem Netzwerk-Runbook und stoppe gescheiterte Streams mit
   `rpp-node validator snapshot cancel --session <id>`. Dokumentiere jeden Abbruch inkl. Zeitstempel.
4. **Nachbereitung.** Aktualisiere die [Observability-Checkliste](./observability.md#snapshot-cli-diagnose) und
   die Phase‑3-Abnahme, damit Auditor:innen lückenlose Artefakte vorfinden.【F:docs/runbooks/observability.md†L6-L46】【F:docs/runbooks/phase3_acceptance.md†L8-L62】

## Admission-Audit

1. **Policies sichern.** `curl -sS -H "Authorization: Bearer ${RPP_RPC_TOKEN}" ${RPP_RPC_URL}/p2p/admission/policies | jq .`
   zeigt den aktuellen Allow-/Blocklist-Stand. Hänge den JSON-Dump an das Incident-Log an.【F:rpp/rpc/src/routes/p2p.rs†L126-L209】
2. **Audit-Einträge sammeln.** `curl -sS -H "Authorization: Bearer ${RPP_RPC_TOKEN}" "${RPP_RPC_URL}/p2p/admission/audit?offset=0&limit=50" | jq .`
   liefert die jüngsten Änderungen mit `actor`, `reason` und `approvals`. Bewahre den Export mit dem entsprechenden Ticket-Link
   auf und referenziere ihn in der Phase‑3-Checkliste.【F:rpp/rpc/src/routes/p2p.rs†L110-L209】【F:docs/runbooks/phase3_acceptance.md†L13-L42】
3. **Retention prüfen.** Vergleiche die Log-Größe mit `network.admission.audit_retention_days` und halte Rotation oder Erweiterung
   schriftlich fest.【F:rpp/runtime/config.rs†L942-L1004】
4. **Dual-Control bestätigen.** Kontrolliere, dass jede Policy-Änderung zwei genehmigte Rollen enthält; fehlende Rollen sofort
   eskalieren.【F:rpp/rpc/src/routes/p2p.rs†L158-L209】

## Alert-Reaction Quick Reference

1. **`ConsensusVRFSlow` (warning).** Prüfe das Panel `consensus_vrf_verification_time_ms` und vergleiche p95-Werte mit den
   Regressionsergebnissen. Entlaste Hardware oder reduziere Testlast, bevor das Budget dauerhaft überschritten wird.【F:docs/dashboards/consensus_grafana.json†L1-L200】【F:tools/simnet/src/bin/regression.rs†L96-L214】
2. **`ConsensusVRFFailureBurst` (page).** Untersuche das Label `reason` im Panel `consensus_quorum_verifications_total` und validiere
   mit dem Regressionstool, dass manipulierte Zeugen weiterhin abgelehnt werden. Dokumentiere Resultat und Recovery im Incident-Log.【F:docs/dashboards/consensus_grafana.json†L1-L200】【F:tools/simnet/src/bin/regression.rs†L96-L214】
3. **`ConsensusQuorumVerificationFailure` (page).** Stoppe Blockproduktion, notiere betroffene Validatoren und stimme dich mit dem
   Consensus-Team ab, falls der Fehler nach erneuter Validierung bestehen bleibt.【F:docs/observability/alerts/consensus_vrf.yaml†L27-L47】
4. **Incident-Log & Checkliste.** Jede Alert-Reaktion endet mit einem Eintrag in Observability-Runbook, On-Call-Log und der
   Phase‑3-Checkliste (Abschnitt *Observability Dashboards & Alerts*).【F:docs/runbooks/observability.md†L49-L115】【F:docs/runbooks/phase3_acceptance.md†L23-L44】

## Nachbereitung

- Sammle CLI-Transkripte, Dashboard-Screenshots und Audit-Dumps in der Teamablage und verlinke sie in Phase‑3.
- Übergib offene Maßnahmen (z. B. Retention-Anpassungen, Follow-up-Tests) mit Ticket-Link an das nächste Team.
- Aktualisiere dieses Handbuch nach größeren Änderungen an CLI- oder Dashboard-Flows.
