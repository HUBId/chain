# Malachite BFT – Cross-Cutting Concerns

Dieses Dokument fasst übergreifende Anforderungen für die vollständige Umsetzung des Malachite-BFT-Blueprints in der RPP-Blockchain zusammen. Es dient als Ergänzung zur Anforderungsanalyse & Architekturplanung und soll sicherstellen, dass alle begleitenden Querschnittsthemen (Konfiguration, Telemetrie, Dokumentation, Tests, Betrieb) konsistent adressiert werden.

## 1. Konfiguration & Parametrisierung

### 1.1 Zentrale Parameterdatei
* **Ziel**: Einfache Anpassung der Blueprint-Parameter ohne Codeänderung.
* **Umsetzung**: Einführung einer dedizierten Konfigurationsdatei `config/malachite.toml` (oder YAML), die von Node- und Konsensdiensten geladen wird.
* **Konfigurations-Layer**: Priorität `CLI-Flags → Umgebungsvariablen → Config-Datei → Default-Werte`.

### 1.2 Relevante Parametergruppen
1. **Validator- & Leader-Selektion**
   * `validator_set_size`, `witness_count` – maximale Teilnehmer je Epoche.
   * `vrf_threshold_curve` – Funktionsdefinition zur Ableitung der Schwelle aus der Timetoke-Balance.
   * `epoch_duration`, `round_timeout`, `max_round_extensions` – Steuerung des Konsens-Tempos.
2. **Reputation & Timetoke**
   * `tier_thresholds` – Score-Grenzen für Tier 3+, konfigurierbar via
     `reputation.tier_thresholds` in `config/node.toml` für operatorseitige
     Anpassungen.【F:config/node.toml†L39-L43】
   * `weights` – Gewichtung der Bewertungsquellen (Validierung, Uptime,
     Konsens, Peer-Feedback, Decay). Alle Werte müssen im Bereich `[0.0, 1.0]`
     liegen und sich zu `1.0` normalisieren; anpassbar per
     `[reputation.weights]` im Node-/Governance-Config.【F:config/node.toml†L45-L51】
   * `timetoke_decay_rate`, `timetoke_accrual_rate`, `timetoke_cap` – Stabilisierung der Uptime-Gewichtung.
   * `snapshot_interval`, `max_snapshot_age` – Synchronisationsfenster.
3. **Rewards & Slashing**
   * `base_block_reward`, `leader_bonus_pct`, `witness_reward_pct` – Split des Reward-Pools.
   * `double_sign_penalty`, `fake_proof_penalty`, `inactivity_penalty` – Reputation- und Balance-Abzüge.
4. **Proof-System**
   * `proof_batch_size`, `proof_cache_ttl`, `max_recursive_depth` – Performance- und Speichersteuerung.
5. **Netzwerk & Ressourcen**
   * `gossip_fanout`, `max_channel_buffer`, `rate_limit_per_channel` – Stabilität der P2P-Kanäle.
   * `max_block_size`, `max_votes_per_round` – DoS- und Kapazitätsbegrenzung.
6. **Secrets & Schlüsselmaterial**
   * `secrets.backend` wählt den VRF-Keystore (Filesystem, Vault, HSM-Placeholder)
     und kontrolliert, ob Schlüsseldateien lokal angelegt oder per API bezogen
     werden.【F:config/node.toml†L8-L13】【F:rpp/runtime/config.rs†L328-L367】
   * `NodeConfig::load_or_generate_vrf_keypair` kapselt die Backend-Auswahl und
     verhindert Klartext-Logs von Tokens/TLS-Zugangsdaten beim Laden aus Vault & Co.【F:rpp/runtime/config.rs†L567-L574】【F:rpp/runtime/node.rs†L611-L615】【F:rpp/crypto/mod.rs†L262-L316】

### 1.3 Versionsverwaltung & Migration
* Konfigurationsschema per SemVer kennzeichnen, z. B. `config_version = "1.0"`.
* Node startet nur, wenn Config-Version kompatibel ist; andernfalls Migrationshinweis.
* Dokumentation von Default-Werten und deren Rationale in `docs/config_reference.md`.

## 2. Telemetrie, Observability & Auditierbarkeit

### 2.1 Metriken
* **Konsens**: Round-Laufzeiten (ms), Leader-Wechsel, VRF-Erfolgsrate, Quorum-Latenzen, Witness-Gossip-Zähler, Slashing-Ereignisse und fehlgeschlagene Votes.
* **Reputation & Timetoke**: Durchschnittliche Timetoke-Balance, Anzahl Promotion/Demotion-Events, Reputation-Decay-Statistiken.
* **Rewards**: Verteilte Rewards pro Epoche, Leader-Bonus-Anteil, Witness-Ausschüttungen.
* **Anti-Abuse**: Detektierte Double-Signs, Fake-Proofs, Zensurmeldungen, angewandte Slashing-Fälle.
* **Netzwerk**: Nachrichtenvolumen pro Kanal (`blocks`, `votes`, `proofs`, `snapshots`, `meta`), Fehlerquoten, Rate-Limits.
* **Proofs**: Erstellungszeit, Verifizierungszeit, Cache-Hitrate.

### 2.2 Logging & Tracing
* **Structured Logging**: JSON/Protobuf-Logs mit Feldern `round_id`, `epoch`, `leader_id`, `validator_id`, `tier`, `timetoke_balance`, `event_type`.
* **Tracing**: OpenTelemetry-Integration, Spans für VRF-Auswertung, Leader-Wahl, Proof-Building, Netzwerk-Dispatch.
* **Log-Level-Policy**: Debug für Testnet, Info/Warn für Produktion, Audit-relevante Events auf Warn oder höher.

### 2.3 Audit-Trail & Compliance
* Signierte Audit-Logs für Anti-Abuse-Ereignisse, bereitgestellt über gesicherten Export (z. B. S3, IPFS).
* Datenschutzbeachtung: Pseudonymisierte Validator-IDs, keine Klartext-IP-Adressen in Public-Logs.
* Aufbewahrungsfristen pro Netzwerkumgebung festlegen (z. B. Testnet 30 Tage, Mainnet ≥ 1 Jahr).

## 3. Dokumentation & Entwickler-Experience

### 3.1 Blueprint- und API-Dokumente
* **Blueprint Coverage**: Fortlaufende Pflege eines Coverage-Index (z. B. `docs/blueprint_coverage.md`) mit Status `geplant → in Arbeit → umgesetzt` pro Blueprint-Feature.
* **API-Referenzen**: Rustdoc-Generierung und separate Markdown-Guides für Konsens-, Reward- und Netzwerk-Schnittstellen.
* **Sequenzdiagramme**: BPMN/PlantUML-Diagramme für Konsensrunde, Timetoke-Sync und Rewards.

### 3.2 Entwicklerleitfäden
* Quickstart-Guide für lokale Validator-Nodes inkl. Konfigurationsbeispiele.
* Troubleshooting-Playbook für häufige Fehler (z. B. fehlende Timetoke-Snapshots, VRF-Mismatch).
* Coding-Guidelines für neue Module (z. B. Fehlerbehandlung, Telemetrie-Hooks, Test-Patterns).

### 3.3 Kommunikationskanäle
* Changelog-Struktur mit Fokus auf Konsensänderungen.
* RFC-Prozess für größere Anpassungen (Proof-System, Slashing-Politik).

## 4. Teststrategie & Qualitäts­sicherung

### 4.1 Testpyramide
1. **Unit-Tests**: Deterministische Tests für VRF-Thresholds, Reward-Berechnung, Reputation-/Timetoke-Funktionen.
2. **Property-Based Tests**: Proptest-Szenarien decken `ConsensusRound::new` (Quorum, Fallback-Pfade), Reward-Distribution (`distribute_rewards`) und Evidence-Slashings (`submit_evidence`/`slash`) ab. Die Suites laufen mit den Standard-Features (`prover-stwo`) sowie der Minimal-Feature-Matrix über `scripts/test.sh --integration`.
3. **Integrationstests**: Simulierte Konsensrunden mit Mock-Netzwerk, um Quorum und Proof-Embedding zu verifizieren.
4. **Systemtests / Testnet**: Mehrknoten-Simulation mit realem Netzwerkstack und Telemetrie-Sammlung.
5. **Fuzzing**: Eingabe-Fuzzing für Netzwerk-Nachrichten und Proof-Verifizierer.
6. **Performance- & Lasttests**: Messung von Blockzeiten, Proof-Latenzen, Ressourcenverbrauch.

### 4.2 Testautomatisierung
* **CI/CD**: Pipeline-Stufen `fmt → clippy → unit → integration → fuzz-nightly → performance-weekly`.
* **Artefakte**: Testberichte, Coverage-Metriken, Benchmark-Charts. Property-Tests sind über `cargo test -p rpp-consensus --test property_vrf` bzw. `cargo test -p rpp-chain --test property_consensus_round` reproduzierbar; beide Kommandos respektieren die vorhandenen Cargo-Feature-Sets (`--feature-set minimal|default|full`).
* **Gatekeeper**: Merge nur bei `ci_status == green` und dokumentiertem Blueprint-Fortschritt.

### 4.3 Testdaten & Fixtures
* Generierung deterministischer Seeds für VRF-Tests, Reputationsprofile, Timetoke-Snapshots.
* Nutzung synthetischer Netzwerkevents (z. B. Delay, Packet Loss) für Stabilitätsprüfungen.
* Dummy-Recursive-Proofs zur Validierung der Einbettung, bevor echte STWO-Proofs vorliegen.

## 5. Betriebs- & Rollout-Aspekte

### 5.1 Feature-Flags & Kompatibilität
* Einführen von Feature-Toggles für: `malachite_consensus`, `timetoke_rewards`, `witness_network`.
* Legacy-Knoten erkennen über Gossip den aktivierten Feature-Set-Status und handeln entsprechend (Fallback-Modus oder Sync-Anweisung).

### 5.2 Deployments & Migrationen
* Rolloutplan: Devnet → Testnet → Canary-Mainnet → Vollständiges Mainnet.
* Datenmigrationen versionieren, Backups vor Aktivierung der neuen Module erzwingen.
* Automatisierte Health-Checks vor/ nach Aktivierung (Validator-Set-Größe, Telemetrie-Signale, Proof-Validierung).

### 5.3 Betrieb & SRE
* Runbooks für Incident Response (z. B. Leader-Ausfall, Proof-Verifikationsfehler, Netzwerkpartitionen).
* Alerting-Regeln für kritische Metriken (Leader-Wechselrate, VRF-Fehler, Snapshot-Verzug, Slashing-Spikes).
* Kapazitätsplanung: Ressourcenbedarf pro Node (CPU für Proofs, Speicher für Snapshots, Bandbreite pro Kanal).

### 5.4 Sicherheitsmaßnahmen
* Secrets-Management für VRF-Schlüssel (z. B. HSM, Vault-Integration) inklusive
  keystore-spezifischer Zugriffsdaten im `[secrets]`-Abschnitt von
  `config/node.toml`.【F:config/node.toml†L8-L13】【F:rpp/runtime/config.rs†L328-L367】
* Runtime-Initialisierung darf keinerlei Klartext-Tokens loggen; die Keystore-
  Implementierungen kapseln Requests und propagieren nur sanitised Fehlercodes.【F:rpp/crypto/mod.rs†L262-L316】【F:rpp/runtime/node.rs†L611-L615】
* Härtung der P2P-Schicht (TLS/Noise, Peer-Authentifizierung, Sybil-Resistenz).
* Regelmäßige Security-Audits & Bug-Bounty-Programme.

## 6. Offene Aufgaben & Verantwortlichkeiten

| Bereich | Owner | Deliverable | Status |
| --- | --- | --- | --- |
| Konfigurationsdatei & Loader | Core Platform Team | `config/malachite.toml`, Parsing-Module | offen |
| Telemetrie-Integration | SRE Team | Metrics-Exporter, Grafana-Dashboards | offen |
| Dokumentationspaket | Developer Relations | API-Guides, Flowcharts, Changelog | offen |
| Testautomatisierung | QA Team | CI-Pipeline mit Nightly-Fuzzing | offen |
| Rollout-Planung | DevOps | Stufenplan & Runbooks | offen |
| Sicherheitskonzept | Security Guild | Secrets-Policy, Audit-Plan | offen |

## 7. Nächste Schritte

1. Config-Schema und Default-Werte finalisieren, anschließend Loader-Modul implementieren.
2. Telemetrie-Schnittstellen in Konsens-, Reputation- und Netzwerkmodulen definieren.
3. Dokumentationspaket strukturieren, Verantwortlichkeiten im Team bestätigen.
4. CI/CD-Pipeline um Property- und Integrationstests erweitern.
5. Rollout- und Sicherheitskonzepte mit Stakeholdern abstimmen.

Diese Cross-Cutting-Übersicht bildet die Basis, um in weiteren Iterationen konkrete Implementierungen, Tests und Betriebskonzepte auszuarbeiten und die vollständige Blueprint-Umsetzung abzusichern.
