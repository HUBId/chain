# Phase‑3 Acceptance Checklist

Diese Checkliste bündelt alle Nachweise, die für die Phase‑3-Abnahme erforderlich sind. Jeder Punkt erfordert verlinkte Artefakte (Reposnapshot, CI-Artefakt, Dashboard-Screenshot oder Ticket-Referenz), damit Auditor:innen und Stakeholder den Fortschritt nachvollziehen können.

## Artefaktliste

### Snapshot-SLIs & Replay-Evidenz
- [ ] **Snapshot-SLI-Baselines archiviert.** Exportierte Panels aus den Pipeline-Dashboards dokumentieren Durchsatz, Chunk-Lag und Fehlerquoten der Snapshot-Pipeline (`snapshot_bytes_sent_total`, `snapshot_stream_lag_seconds`).【F:docs/dashboards/pipeline_overview.json†L219-L260】【F:rpp/node/src/telemetry/pipeline.rs†L12-L76】
- [ ] **Replay-Schutz protokolliert.** Die Guardrails gegen Snapshot-Replay sind mit Testlogs aus `snapshot_streams_verify_via_network_rpc` belegt, inklusive RPC-/P2P-Traces und Lag-Metriken.【F:tests/network/snapshots.rs†L1-L120】【F:rpp/runtime/node_runtime/node.rs†L375-L503】
- [ ] **Pruning- & Snapshot-Metadaten konsistent.** Die validierten Pruning-Receipts zeigen, dass `known_snapshot_sets` und persistierte Pruner-Zustände übereinstimmen.【F:tests/state_sync/pruning_validation.rs†L1-L60】【F:storage/src/nodestore/mod.rs†L661-L701】

### Tier-Admission Persistenz & Audit
- [ ] **Allowlist/Blocklist-Dumps versioniert.** Persistente `AdmissionPolicies`-Snapshots (JSON/YAML oder RPC-Dumps) sind abgelegt und referenzieren die Peerstore-Reload-Logs.【F:rpp/p2p/src/peerstore.rs†L961-L1097】【F:rpp/runtime/node.rs†L3174-L3552】
- [ ] **Tier-Downgrade-Protokolle.** Slashing- und Tier-Transitions sind mit Testnachweisen (`slashed_peer_cannot_publish_consensus_gossip`, `tier_two_identity_cannot_publish_votes_gossip`) dokumentiert, inklusive Seriennummern der Persistenzartefakte.【F:tests/p2p_admission.rs†L1-L120】【F:rpp/runtime/node_runtime/network.rs†L26-L160】
- [ ] **RPC-Policy-Roundtrip.** `GET /p2p/admission/policies` und `POST /p2p/admission/policies` sind im Audit-Log enthalten und verweisen auf die Persistenzprüfungen.【F:rpp/rpc/src/routes/p2p.rs†L58-L227】【F:docs/runbooks/observability.md†L80-L83】

### Timetoke Replay-Tests & Snapshot-Pfade
- [ ] **Timetoke-Snapshot-Roundtrip.** Artefakte aus `timetoke_snapshot_roundtrip` zeigen Producer-/Consumer-Logs, Root-Hashes und Replay-Zeitstempel.【F:tests/consensus/timetoke_snapshots.rs†L1-L80】【F:rpp/runtime/node_runtime/node.rs†L430-L503】
- [ ] **Replay-Validator-Belege.** Fehlerszenarien (`SnapshotRootMismatch`, `PruningDigestMismatch`, `DomainTagMismatch`) sind mit Testläufen und Log-Snippets archiviert.【F:tests/consensus/timetoke_snapshots.rs†L81-L170】【F:rpp/runtime/sync.rs†L232-L270】
- [ ] **Reputation-/Reward-Verknüpfung.** Dokumentiert, wie Timetoke-Replay in die Reputation-/Reward-Governance einfließt (Config-Snapshots, Governance-Protokolle).【F:rpp/runtime/config.rs†L340-L416】【F:tests/consensus/timetoke_rewards.rs†L1-L80】

### Observability Dashboards & Alerts
- [ ] **Grafana-Dashboards importiert.** Panels für Snapshot-, Admission- und Timetoke-Metriken (Pipeline Overview, Pipeline Proof Validation, VRF Overview) sind exportiert, versioniert und mit Screenshot-Belegen versehen.【F:docs/dashboards/pipeline_overview.json†L200-L260】【F:docs/dashboards/pipeline_proof_validation.json†L1-L60】【F:docs/dashboards/vrf_overview.json†L1-L60】
- [ ] **Alert-Regeln getestet.** Alertmanager-/Prometheus-Regeln für Snapshot-Lag, Admission-Anomalien und Timetoke-Replay-Fehler besitzen Drill-Protokolle (Alert firing, Silence, Recovery).【F:docs/observability/alerts/snapshot_stream.yaml†L1-L96】【F:docs/observability/alerts/consensus_vrf.yaml†L1-L40】【F:rpp/p2p/src/metrics.rs†L106-L147】
- [ ] **Runbooks verlinkt.** Die relevanten Runbooks (`observability`, `network_snapshot_failover`, `phase3_acceptance`) sind in On-Call-Docs eingebunden und enthalten Eskalationspfade.【F:docs/runbooks/observability.md†L1-L120】【F:docs/runbooks/network_snapshot_failover.md†L1-L120】

## Verifikation & Audit-Trails

| Deliverable | Prüfkommando / Dashboard | Referenzen |
| --- | --- | --- |
| Snapshot-SLIs & Replay | `cargo test --test network_snapshots -- snapshot_streams_verify_via_network_rpc` (führt RPC-Trace & Lag-Metriken aus) | 【F:tests/network/snapshots.rs†L1-L160】【F:rpp/p2p/src/behaviour/snapshots.rs†L58-L520】 |
| Pruning- & Snapshot-Metadaten | `cargo test --test state_sync_pruning_validation -- pruning_receipts_align_with_snapshot_metadata` (führt Fixture-Abgleich aus) | 【F:tests/state_sync/pruning_validation.rs†L1-L80】【F:storage-firewood/src/lifecycle.rs†L18-L105】 |
| Tier-Admission Persistenz | `cargo test --test p2p_admission -- slashed_peer_cannot_publish_consensus_gossip` (Cluster wird gestartet, Slashing/Tier-Downgrade überprüft) | 【F:tests/p2p_admission.rs†L1-L160】【F:rpp/p2p/src/peerstore.rs†L961-L1151】 |
| Timetoke Replay | `cargo test --test timetoke_snapshots -- timetoke_snapshot_roundtrip` (Producer/Consumer/Validator-Roundtrip) | 【F:tests/consensus/timetoke_snapshots.rs†L1-L170】【F:rpp/runtime/sync.rs†L232-L270】 |
| Observability Dashboards | Grafana-Import laut Dashboard-README sowie Alert-Drills mit `promtool test rules` dokumentiert | 【F:docs/dashboards/README.md†L1-L80】【F:docs/observability/alerts/snapshot_stream.yaml†L1-L96】【F:docs/observability/alerts/consensus_vrf.yaml†L1-L40】 |

## Abnahmebedingungen

Phase 3 gilt als abgenommen, sobald alle Kontrollkästchen belegt sind **und** folgende Bedingungen nachweislich erfüllt werden:

- ✅ **Snapshot-Lag innerhalb der SLOs:** `snapshot_stream_lag_seconds` bleibt im definierten SLO (≤ 5 s über mindestens drei aufeinanderfolgende Nachweise) und die Export-Artefakte sind archiviert.【F:docs/dashboards/pipeline_overview.json†L219-L260】
- ✅ **Admission-Persistenz reproduzierbar:** Peerstore-Reloads und RPC-Policies spiegeln dieselben Allowlist-/Blocklist-Daten wider; Audit-Logs enthalten die Roundtrip-Kommandos.【F:rpp/p2p/src/peerstore.rs†L961-L1097】【F:rpp/rpc/src/routes/p2p.rs†L58-L227】
- ✅ **Timetoke-Replay geprüft:** `TimetokeReplayValidator` akzeptiert gültige Kombinationen und lehnt manipulierte Roots/Tags nachweislich ab.【F:tests/consensus/timetoke_snapshots.rs†L81-L170】【F:rpp/runtime/sync.rs†L232-L270】
- ✅ **Observability aktiviert:** Snapshot-, Admission- und Timetoke-Alerts sind aktiv und haben mindestens einen Drill mit Recovery-Protokoll dokumentiert.【F:docs/observability/alerts/snapshot_stream.yaml†L1-L96】【F:docs/observability/alerts/consensus_vrf.yaml†L1-L40】【F:rpp/p2p/src/metrics.rs†L106-L147】

Sobald diese Kriterien erfüllt sind und alle Artefakte über die verlinkten Status- & Roadmap-Dokumente abrufbar sind, kann Phase 3 offiziell abgeschlossen werden.
