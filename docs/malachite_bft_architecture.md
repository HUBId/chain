# Malachite BFT – Anforderungsanalyse & Architekturplan

## Zielsetzung
Diese Analyse übersetzt den aktualisierten Malachite-BFT-Blueprint (mit Leader-Bonus) in konkrete Architekturentscheidungen für die bestehende RPP-Blockchain-Codebasis. Sie dokumentiert die funktionalen und nicht-funktionalen Anforderungen, identifiziert Lücken gegenüber dem Ist-Zustand und beschreibt die daraus abgeleiteten Komponenten- und Schnittstellenerweiterungen.

## Implementierungsstand (Update)
* **Orchestrator & Streams:** `DistributedOrchestrator` stellt Proposal-, Vote- und Commit-Broadcasts für alle Validatoren bereit und koppelt sich über den `TopicRouter` automatisch an Witness-Themen an, womit der verteilte Loop blueprint-konform ausgeliefert wurde.【F:rpp/consensus/src/malachite/distributed.rs†L1-L120】【F:rpp/consensus/src/network/topics.rs†L1-L62】
* **Evidence-Pipeline & Slashing:** Der Evidence-Pool priorisiert Double-Sign-, Availability-, Witness-, Censorship- und Inaktivitätsmeldungen, speist sie in die Slashing-Heuristiken und persistiert die Telemetrie über den Konsens-Status; Regressionstests halten die Priorisierung und Witness/Uptime-Trigger fest.【F:rpp/consensus/src/evidence/mod.rs†L10-L205】【F:rpp/consensus/src/state.rs†L928-L989】【F:tests/consensus/evidence_slashing.rs†L1-L205】
* **Rewards & Penalties:** Konsens-Commits buchen Leader-Bonus, Validator-Anteile und Witness-Pools über die Reward-Engine, wenden Penalty-Flags an und dokumentieren das Ergebnis in der Distribution; Governance-Tests sichern die Splits ab.【F:rpp/consensus/src/rewards.rs†L1-L120】【F:rpp/consensus/src/state.rs†L948-L989】【F:tests/consensus/timetoke_rewards.rs†L1-L54】

## Überblick über Blueprint-Anforderungen
* **Reputation, Timetoke & Tiers**: Teilnahmeberechtigung und Gewichtung der Konsensrollen basieren auf Reputation (Tier ≥ 3), Timetoke-Balance (Uptime) sowie VRF-Outputs.
* **Validator-, Leader- und Witness-Rollen**: Auswahl über VRF + Timetoke, Leader nach Tier/Timetoke/VRF, Witnesses als zusätzliche Prüfer.
* **Konsensfluss**: Proposal → Pre-Vote → Pre-Commit → Commit mit eingebettetem Konsens-Proof.
* **Rewards**: Gleichmäßige Validator-Rewards plus Leader-Bonus (z. B. +20 %).
* **Proof-Integration**: Rekursiver Block-Proof mit Nachweis korrekter Auswahl, Quorum und Leader-Bestimmung.
* **Anti-Abuse**: Maßnahmen gegen Double-Signs, Fake-Proofs, Leader-Zensur, Inaktivität.
* **Nachrichtenkanäle**: `blocks`, `votes`, `proofs`, `snapshots`, `meta`.
* **Rust-Schnittstellen**: Traits/Module für Konsens, Wirtschaftlichkeit, Netzwerk, Clients.

## Ist-Zustand der Codebasis (Kurzfassung)
* **Reputation & Stake**: Reputation verwaltet Score **und** Tier-Level; Timetoke-Balances werden im Ledger gepflegt und bei Reputation-Audits berücksichtigt.
* **Validator-/Proposer-Selektion**: VRF-Auswertung nutzt Timetoke-Daten (`derive_tier_seed`) und filtert Kandidaten mit Tier < 3 aus; Leader-Selektion priorisiert Tier → Timetoke → VRF.
* **Rewards**: `Ledger::distribute_consensus_rewards` verteilt Basis-Rewards gleichmäßig, addiert Gebühren und vergibt einen Leader-Bonus von 20 %. Die Auszahlung belastet die in `rewards.treasury_accounts` hinterlegten Treasury-Konten; fehlen dort Mittel, greift der Ledger automatisch auf den Gebühren-Topf zurück und verbucht verbleibende Fehlbeträge.
* **Proofs**: STWO- und Plonky3-Workflows prüfen Konsens-, Uptime- und Modul-Witnesses, erzwingen vollständige VRF-/Quorum-Metadaten und verwerfen manipulierte Digests bereits vor der Rekursion; neue Regressionstests decken gefälschte VRF-Bundles sowie fehlerhafte Quorum-Wurzeln ab (`tests/consensus/consensus_proof_integrity.rs`, `rpp/proofs/stwo/tests/consensus_metadata.rs`, `rpp/proofs/plonky3/tests.rs`).
  - **Circuit-Constraints (VRF-Bundles)**: Die noch ausstehenden Gadgets in [`rpp/proofs/stwo/aggregation/mod.rs`](../rpp/proofs/stwo/aggregation/mod.rs) und [`rpp/proofs/plonky3/circuit/consensus.rs`](../rpp/proofs/plonky3/circuit/consensus.rs) müssen die Bündelgröße (≤ 32 Einträge), deterministische Sortierung nach Validator-ID, Binding an `epoch_nonce` und Timetoke sowie den Poseidon-Digest der Einzel-VRFs als Merkle-Blatt prüfen. Zusätzlich wird ein Range-Gadget benötigt, das die Threshold-Bits (`threshold_le`, `timetoke_weight`) pro Kandidat gegen die On-Chain-Konfiguration verifiziert.
  - **Circuit-Constraints (Quorum-Zertifikat)**: Konsens- und Witness-Zweige derselben Circuit-Familie benötigen identische Quorum-Checks. Die Constraint-Sets in [`rpp/proofs/stwo/aggregation/mod.rs`](../rpp/proofs/stwo/aggregation/mod.rs) und dem Plonky3-Gegenstück [`rpp/proofs/plonky3/circuit/consensus.rs`](../rpp/proofs/plonky3/circuit/consensus.rs) müssen den 2/3-Threshold über `VotePower` erzwingen, die Signaturaggregate (`quorum_sig_root`) gegen das Validator-Set-Commitment hashen und Witness-Merkle-Pfade (`witness_path_root`) auf Nicht-Leader ausschließen.
  - **Public Inputs**: Beide Backend-Varianten exportieren konsistente Public Inputs bestehend aus `epoch`, `validator_set_root`, `vrf_bundle_root`, `quorum_sig_root`, `leader_selection_digest` sowie `witness_path_root`. Für die Rekursion werden zusätzlich die `recursive_state_root` und `proof_batch_digest` aus [`rpp/proofs/stwo/aggregation/mod.rs`](../rpp/proofs/stwo/aggregation/mod.rs) eingespeist.
  - **Tests**: Neben den bestehenden Metadaten-Checks werden Negativtests für manipulierte VRF-Bundles und Quorum-Wurzeln in [`tests/consensus/consensus_proof_integrity.rs`](../tests/consensus/consensus_proof_integrity.rs) sowie in den Backend-spezifischen Suites [`rpp/proofs/stwo/tests/consensus_metadata.rs`](../rpp/proofs/stwo/tests/consensus_metadata.rs) und [`rpp/proofs/plonky3/tests.rs`](../rpp/proofs/plonky3/tests.rs) ergänzt; die Cases validieren sowohl fehlende Witnesses als auch zu großzügige Thresholds.
* **Anti-Abuse**: Allgemeines Slashing vorhanden, jedoch ohne blueprint-spezifische Checks.
* **Netzwerk**: BFT-Nachrichten sind nicht entlang der geforderten Kanalstruktur organisiert.
* **Rust-Interfaces**: Traits fokussieren auf Stake-BFT, ohne Reputation-/Timetoke-Einbindung.

### Acceptance-Kriterien VRF-/Quorum-Proofs
- [ ] Plonky3- und STWO-Circuits lehnen manipulierte VRF-Bundles deterministisch ab; die Constraint-Implementierungen in [`rpp/proofs/plonky3/circuit/consensus.rs`](../rpp/proofs/plonky3/circuit/consensus.rs) und [`rpp/proofs/stwo/aggregation/mod.rs`](../rpp/proofs/stwo/aggregation/mod.rs) erzwingen Bundle-Integrität, Threshold-Bindungen und Witness-Kohärenz.
- [ ] Negativtests gegen gefälschte Quorum-Wurzeln und Witness-Wege bestehen in [`tests/consensus/consensus_proof_integrity.rs`](../tests/consensus/consensus_proof_integrity.rs), [`rpp/proofs/stwo/tests/consensus_metadata.rs`](../rpp/proofs/stwo/tests/consensus_metadata.rs) und [`rpp/proofs/plonky3/tests.rs`](../rpp/proofs/plonky3/tests.rs).
- [ ] Rekursive Aggregation veröffentlicht die Public-Input-Digests (`recursive_state_root`, `proof_batch_digest`) über RPC und Telemetrie in [`rpp/proofs/stwo/aggregation/mod.rs`](../rpp/proofs/stwo/aggregation/mod.rs), [`rpp/rpc/api.rs`](../rpp/rpc/api.rs) sowie [`rpp/node/src/telemetry`](../rpp/node/src/telemetry).

> [!NOTE] Phase 2 Exit Criteria
> Status: offen – wird auf „erledigt“ gesetzt, sobald alle obigen Acceptance-Kriterien erfüllt, dokumentiert und in den verlinkten Modulen/PRs zusammengeführt sind.

## Phase 2 Exit Criteria

* **Tests:** `cargo xtask test-consensus-manipulation` deckt Plonky3 und STWO ab und
  dokumentiert manipulierte VRF-/Quorum-Zeugen in
  `tests/consensus/consensus_certificate_tampering.rs`. Die Ergebnisse müssen in den
  Phase‑2-Reports archiviert werden.【F:xtask/src/main.rs†L1-L120】【F:tests/consensus/consensus_certificate_tampering.rs†L1-L160】
* **Metriken & Dashboards:** Die Panels in `docs/dashboards/consensus_grafana.json` visualisieren
  `consensus_vrf_verification_time_ms` und `consensus_quorum_verifications_total`; die
  Observability-Dokumentation beschreibt Schwellenwerte und Alerting.【F:docs/dashboards/consensus_grafana.json†L1-L200】【F:docs/observability/consensus.md†L1-L70】
* **Operator-Nachweise:** Die aktualisierten Runbooks verweisen auf CLI- und RPC-Befehle, die
  erfolgreiche und manipulierte Pfade reproduzieren, inklusive Simnet-Logs und Grafana-Screenshots.【F:docs/rpp_node_operator_guide.md†L120-L174】【F:docs/runbooks/observability.md†L1-L120】

## Gap-Analyse nach Funktionsbereichen
| Bereich | Blueprint-Soll | Ist | Lücke |
| --- | --- | --- | --- |
| Reputation/Tiers | Tier ≥ 3 als Mindestanforderung; Reputation beeinflusst Eintritt | `select_validators` filtert Tier < 3 und aktualisiert Gewichte über Reputation/Stake; Ledger-Audits liefern Tierdaten | **TODO**: Tier-Gates auf P2P-Handshakes & Gossip Admission ausweiten |
| Timetoke | Gewichtung/Thresholds, Decay, Synchronisation | Ledger pflegt Timetoke-State (`timetoke_snapshot`/`sync_timetoke_records`), Node kreditiert Uptime-Proofs und VRF-Seed nutzt Timetoke | **TODO**: Netzwerkweiter Sync-Plan (Snapshots, Replay-Schutz) finalisieren |
| VRF & Validator-Set | VRF Input = (sk, epoch_nonce, timetoke) + Threshold aus Timetoke | VRF-Seed kombiniert Adresse & Timetoke; Validator-Gewichte berücksichtigen Reputation + Timetoke | Parametrisierung der Schwellen über `[validator.vrf.threshold]` und Telemetrie-/Log-Ausgabe der Erfolgsquoten implementiert |
| Leader-Selektion | Priorität: Tier → Timetoke → VRF | `select_leader` sortiert nach Tier, Timetoke, VRF-Ausgabe | ✅ |
| Witness-Rolle | Externe Verifikation | Tier 1–2 werden als Observer/Witness geführt, Konsens-Witnesses werden erstellt, bepreist und über die Incentive-Pipeline geprüft ([tests/witness_incentives.rs](../tests/witness_incentives.rs)) | Dedizierte Witness-Kanäle isolieren Proof- und Meta-Gossip, erzwingen Topic-QoS samt Rate-Limits und verbinden Treasury-/Fee-Pools für Witness-Payouts. Die Buchungen sind dokumentiert und per Tests hinterlegt.【F:rpp/p2p/src/behaviour/witness.rs†L1-L164】【F:rpp/p2p/tests/witness_qos.rs†L1-L69】【F:tests/consensus/witness_distribution.rs†L1-L55】【F:docs/consensus/witness_channels.md†L1-L70】 |
| Rewards | Gleichmäßig + Leader-Bonus | Konsens-Rewards teilen Basis-Reward + Gebühren auf Validatoren mit 20 % Leader-Bonus. Treasury- und Gebühren-Pools sind konfigurierbar, Witness-Payouts folgen den in `rewards.witness_pool_weights` definierten Gewichten. | Governance-gesteuerte Timetoke-Leader/Witness-Pools inklusive Budget-Split und Regressionstests umgesetzt.【F:rpp/consensus/src/governance.rs†L1-L126】【F:rpp/consensus/src/timetoke/rewards.rs†L1-L89】【F:tests/consensus/timetoke_rewards.rs†L1-L40】【F:docs/consensus/rewards.md†L1-L25】 |
| Proofs | Nachweis VRF/Leader/Quorum in Block-Proof | Nur Signatur-Check | Proof-Komponenten erweitern |
| Anti-Abuse | Double-Sign, Fake-Proof, Zensur, Inaktivität | Evidence-Pool erzwingt sofortiges Slashing bei Double-Signs und blockiert Reorgs ([tests/reorg_regressions.rs](../tests/reorg_regressions.rs)) | ✅ Konfigurierbare Heuristiken für Vote-/Proof-Zensur sowie Inaktivität mit Reputation-, Slashing- und Reward-Kopplung plus Telemetrie-Export umgesetzt; P2P Admission-Kontrollen folgen separat.【F:rpp/consensus/src/state.rs†L1000-L1199】【F:rpp/consensus/src/reputation/mod.rs†L118-L166】【F:rpp/node/src/telemetry/slashing.rs†L59-L93】【F:tests/consensus/censorship_inactivity.rs†L1-L260】 |
| Netzwerk | Dedizierte Kanäle | Mischverkehr | Messaging-Layer modularisieren |
| Schnittstellen | Konsens-/Ökonomie-/Netzwerk-Traits | Stake-zentriert | Neue Traits/Adapter |

### Referenztests & Historien
* **VRF-Integrität**: `select_validators_rejects_manipulated_proof` sichert die Tier-Gates & Proof-Verifikation ab (`rpp/consensus/src/tests.rs`).
* **Konsens-Proof-Härtung**: `rejects_external_block_with_tampered_state_fri_proof` prüft die Ablehnung manipulierter Blöcke inkl. Consensus/Witness-Bundles (`rpp/runtime/node.rs`).
* **VRF-Historie**: Ledger-Tests (`record_vrf_history_tracks_entries`) stellen sicher, dass VRF-Submissions epochweise archiviert werden (`rpp/storage/ledger.rs`).
* **Reorg-Schutz & Anti-Abuse**: `tests/reorg_regressions.rs` erzwingt, dass der Evidence-Pool konkurrierende Forks unterbindet und den Tip stabil hält.

### Offene Konsens-TODOs
* ✅ **Tier Admission abgesichert:** Peerstore-Handshakes verwerfen Allowlist-Downgrades und koppeln Telemetrie an die Tier-Prüfung, während die Admission-Control Gossip-Publishes unterhalb von Tier 3 blockiert.【F:rpp/p2p/src/peerstore.rs†L512-L588】【F:tests/network/admission_control.rs†L13-L74】
* ✅ **Timetoke-Snapshots und Replay-Härtung ausgeliefert:** Snapshot-Produktion/-Konsum exportiert Ledger-Zustände über das Snapshot-Protokoll, und der Replay-Validator bindet Pruning-Digests sowie Domain-Tags, abgesichert durch Roundtrip- und Replay-Tests.【F:rpp/consensus/src/timetoke/snapshots.rs†L7-L200】【F:rpp/consensus/src/timetoke/replay.rs†L15-L186】【F:tests/consensus/timetoke_snapshots.rs†L48-L169】
* ✅ **VRF-Schwellenwerte telemetriert:** Die VRF-Kryptobibliothek publiziert Histogramme/Zähler zu Schwellen, Erfolgsquoten und Fallbacks, die Observability-Tests über den OpenTelemetry-Exporter validieren.【F:rpp/crypto-vrf/src/telemetry.rs†L10-L205】【F:tests/observability/vrf_metrics.rs†L9-L69】

## Architekturentscheidungen & Komponenten
### Domänenmodelle
1. **Reputation & Tier Registry**
   * Datenstrukturen: `ReputationScore`, `Tier`, `TierThresholds`.
   * Storage: Map `<ValidatorId, ReputationState>` mit Feldern für Score, Tier, letzte Aktualisierung.
   * APIs: `update_reputation`, `apply_slash`, `apply_decay`, `promote_tier`, `demote_tier`.

2. **Timetoke Ledger**
   * Datenstrukturen: `TimetokeBalance`, `TimetokeParams` (Decay-Rate, Cap, Sync-interval).
   * Storage: Map `<ValidatorId, TimetokeState>` mit Feldern für Balance, letzte Aktivität, Sync-Marker.
   * APIs: `credit_uptime`, `debit_penalty`, `snapshot_state`, `sync_state(peer)`.

3. **Validator Set Snapshot**
   * `ValidatorCandidate { id, tier, reputation_score, timetoke_balance, vrf_entry }`.
   * `ValidatorSet { epoch, members: Vec<ValidatorCandidate>, witnesses: Vec<WitnessId> }`.

### Konsens- und Auswahlmodule
1. **VRF Engine**
   * Input: `(secret_key, epoch_nonce, timetoke_balance, validator_id)`.
   * Output: `vrf_entry { randomness, pre_output, proof, public_key, poseidon { digest, last_block_header, epoch, tier_seed } }`.
   * Threshold-Funktion: `threshold = f(timetoke_balance, network_params)` (z. B. logistischer Anstieg).
   * Interface: `trait VrfProvider { fn evaluate(&self, ctx: VrfContext) -> VrfResult; }`.

2. **Validator Selection Service**
   * Schritte: Filter Tier ≥ 3 → VRF Evaluation → Threshold-Check → Sortierung nach Score.
   * Persistiert `ValidatorSet` pro Epoche.
   * Interface: `trait ValidatorSelector { fn select(epoch: EpochId) -> ValidatorSet; }`.

3. **Leader Selection**
   * Input: `ValidatorSet`.
   * Algorithmus: sortiere nach `tier desc`, `timetoke desc`, `vrf_entry.pre_output asc`.
   * Output: `LeaderAssignment { leader_id, witnesses, proof_ref }`.
   * Interface: `trait LeaderStrategy { fn elect(set: &ValidatorSet) -> LeaderAssignment; }`.

4. **Witness Coordination**
   * Konfigurierbarer Anteil externer Nodes (z. B. Top-N Reputation außerhalb Sets).
   * Interfaces für `WitnessValidator` mit Proof-Übermittlung.

### Belohnungsengine
* Konfigurierbare Parameter: `leader_bonus_pct`, `base_reward`, `epoch_reward_pool`.
* Funktion: `calculate_rewards(set: &ValidatorSet, leader_id)` → `Vec<RewardPayout>`.
* Integration in Wirtschaftsschicht mit Treasury/Emissionen.

### Proof-Pipeline
1. **ConsensusProofBuilder**
   * Aggregiert VRF-Proofs, Validator-Set, Leader-Auswahl, Quorum-Zertifikat.
   * Output eingebettet in Block-Header `ConsensusProof { vrf_bundle, validator_set_hash, leader_proof, quorum_signature }`.

2. **Verifier**
   * Prüft VRF-Outputs gegen Timetoke, Leader-Ranking, Quorum ≥ 2/3, Signatur.
   * Exponiert API für Clients/Witnesses.

### Anti-Abuse Framework
* **Double-Sign Detection**: Beobachtete Signaturen pro Runde persistieren; bei Konflikt → Reputation 0, Slash, Bannflag.
* **Fake-Proof Detection**: Proof-Verifier → invalid? → Slash + Audit-Event.
* **Leader Censorship**: Witness-Feedback-Kanal `meta` meldet Anomalien → Reputation-Decay.
* **Inaktivität**: Timetoke-Decay & Timeout-Tracking pro Validator.
* **Gossip-Heuristiken**: Vote-Timeouts, fehlende Proof-Relays und Gossip-Backpressure lösen konfigurierbare Reputationseinbußen aus (`[p2p.reputation_heuristics]`), werden telemetriert und über das RPC `/p2p/censorship` reportet.

### Netzwerk & Messaging
* Einführung eines Multiplexers, der folgende Streams bereitstellt:
  * `blocks`: Leader-Proposals (Block + ConsensusProof).
  * `votes`: Pre-Vote/Pre-Commit Nachrichten (mit Validator-ID, Proof-Refs).
  * `proofs`: Weiterleitung aggregierter Proofs (VRF, Consensus, Recursive).
  * `snapshots`: Timetoke/Reputation State-Sync.
  * `meta`: Peer-Discovery, Reputation-Events, Misbehavior-Reports.
* Verwendung eines Topic-Tagging-Systems innerhalb vorhandener P2P-Schicht.

### Schnittstellen & Crate-Organisation
* **Neue Crates/Module**:
  * `consensus::malachite` – VRF/Validator-/Leader-Logik, Konsensfluss.
  * `economics::rewards` – Reward-Splitting + Leader-Bonus.
  * `identity::reputation` – Reputation & Tier Management.
  * `uptime::timetoke` – Timetoke Ledger & Sync.
* **Trait-Erweiterungen**:
  * `ConsensusEngine` erweitert um `fn validator_set(&self, epoch)`, `fn leader(&self, epoch)`.
  * `RewardDistributor` mit Leader-Bonus Parametrisierung.
  * `NetworkBroadcaster` mit kanalisiertem Senden/Empfangen.

### Konfiguration & Parameter
* Globales Config-File `config/malachite.toml` (Folgeiteration) mit Parametern:
  * `leader_bonus_pct`
  * `validator.vrf.threshold.curve`, `validator.vrf.threshold.target_validator_count`, `witness_count`
  * `timetoke_decay_rate`, `timetoke_threshold_curve`
  * `slash_penalties`
  * `proof_batch_size`

### Telemetrie & Observability
* Metriken für Timetoke-Distribution, VRF-Erfolgs- und Ablehnungsraten (inkl. Schwellenwerte), Leader-Rotation, Slashing-Events.
* Structured Logging für Konsensentscheidungen (Validator/Leader-Selektion) inklusive aktiver VRF-Schwellen und Rejektionsgründe.
* Audit-Log für Anti-Abuse-Aktionen.

## Risikoanalyse & Offene Fragen
* **Timetoke-Synchronisation**: Wie werden Offline-Validatoren re-synchronisiert, ohne Angriffsfläche für Replays zu öffnen?
* **VRF Threshold Design**: Welche Funktionsform garantiert faire Gewichtung ohne Dominanz einzelner Validatoren?
* **Leader-Bonus Finanzierung**: Stammt Bonus aus zusätzlicher Emission oder Umverteilung innerhalb Reward-Pool?
* **Witness-Anreize**: Brauchen Witnesses eigene Rewards/Slashing-Mechanismen?
* **Proof-Komplexität**: Performance-Auswirkungen der erweiterten Konsens-Proofs müssen modelliert werden.

## Nächste Schritte
1. Detaillierte Spezifikation der Datenmodelle (Serde-Schemas, Storage-Keys).
2. Prototypische Implementierung des Timetoke-Ledgers und der VRF-Erweiterung in isolierten Modulen.
3. Ausarbeitung der Reward-Distribution und Konfigurationsparameter.
4. Festlegung der Proof-Verifizierungsanforderungen mit Kryptoteam.
5. Definition der Netzwerkkanäle in der P2P-Schicht inkl. Backwards-Kompatibilitätsplan.

