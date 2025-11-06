# ADR 0001: Konsensnachweise – VRF, Witness und Quorumfluss

## Status

Accepted – Phase-2-Ausbau des Konsensnachweis-Stacks ist produktiv geschaltet.

## Kontext

Die Malachite-Konsensschicht musste für Phase 2 einen vollständigen
Nachweisfluss abbilden: deterministische VRF-Auswahl, aggregierte Witness-Daten
und Quorum-Verifikation sollten Ende-zu-Ende nachvollziehbar sein. Frühere
Revisionen fokussierten auf deterministische Fixtures und manuelle Prüfpfade; die
Operator-Runbooks waren dadurch stark linearisiert und ließen wenig Raum für
Telemetriegestützte Fehlersuche.【F:rpp/runtime/node.rs†L5036-L5099】【F:docs/runbooks/observability.md†L27-L59】

## Entscheidung

* **VRF-Datenpfad.** Der Runtime-Knoten filtert das Mempool pro Epoche und Seed,
  erzeugt lokale Poseidon-VRFs und persistiert sie. Falsche Inputs werden mit
  `invalid_vrf_submission` markiert, während `Block::verify_consensus_certificate`
  fehlgeschlagene Prüfungen als `invalid_vrf_proof` reportet und die Quorum-
  Metriken aktualisiert.【F:rpp/runtime/node.rs†L5036-L5099】【F:rpp/runtime/types/block.rs†L2008-L2050】
* **Witness- und Constraint-Schicht.** Die Konsens-Circuits der STWO- und
  Plonky3-Backends prüfen nun sämtliche VRF-Transkripte, Quorum-Parameter und
  Bindings direkt in den AIR-/Gate-Constraints. Beide Varianten erzwingen
  vollständige VRF-Einträge (Randomness, Pre-Output, Proof, Public-Key sowie
  Poseidon-Header/Tier-Seed), stimmen diese gegen Block-Hash und Epoche ab und
  binden Witness-Commitments, Reputation-Roots sowie Quorum-Wurzeln an das
  Block-Seed. Fehlende oder manipulierte Einträge resultieren in
  `ConstraintViolation`- bzw. `invalid_witness`-Fehlern, die im Backend als
  `ChainError::Crypto` auftauchen.【F:prover/prover_stwo_backend/src/official/circuit/consensus.rs†L125-L295】【F:prover/plonky3_backend/src/circuits/consensus.rs†L500-L705】【F:rpp/proofs/stwo/prover/mod.rs†L419-L472】
* **Quorum-Evaluierung.** Konsenszertifikate prüfen Vote-Gewichte,
  Teilnehmerkonsistenz und Witness-Zuordnung. Zusätzlich erzwingen die neuen
  Bindings, dass `quorum_bitmap_root` und `quorum_signature_root` mit den im
  Circuit rekonstruierten Digests übereinstimmen. Jede Abweichung aktualisiert
  das Telemetrie-Label `consensus_quorum_verification_failure`, sodass
  Dashboards und Runbooks einheitlich auf die Ursache verweisen können.【F:prover/plonky3_backend/src/circuits/consensus.rs†L646-L705】【F:rpp/runtime/types/block.rs†L2053-L2173】【F:docs/dashboards/consensus_grafana.json†L1-L200】

## Nachvollziehbarkeit (Tests, Metriken, Runbooks)

* **Tests.**
  * `tests/vrf_selection.rs` rekonstruiert Konsensrunden über historische VRF-
    Daten und stellt sicher, dass ohne valide VRF-Ausgaben keine Quoren erreicht
    werden.【F:tests/vrf_selection.rs†L12-L120】
  * Die Backend-Test-Suiten validieren die Circuit-Constraints: STWO weist
    manipulierte VRF-Outputs, vertauschte Proofs und veränderte Quorum-Wurzeln
    zurück, während Plonky3 dieselben Tamper-Fälle im Proof-Verifier ablehnt.【F:prover/prover_stwo_backend/src/backend.rs†L1185-L1333】【F:prover/plonky3_backend/tests/consensus.rs†L605-L690】
  * `tests/consensus/censorship_inactivity.rs` erzwingt Witness- und
    Quorum-Constraints (z. B. Doppeltstimmen, fehlende Witness-Teilnehmer) und
    verifiziert Slashing-Trigger sowie Penalty-Anwendung.【F:tests/consensus/censorship_inactivity.rs†L1-L220】
  * Simnet-Szenario `tools/simnet/scenarios/consensus_quorum_stress.ron`
    reproduziert fehlerhafte Witness-Bundles und wird via `cargo xtask
    test-consensus-manipulation` im Observability-Runbook referenziert.【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】【F:docs/runbooks/observability.md†L27-L59】
* **Metriken und Dashboards.**
  * `docs/observability/consensus.md` und `docs/observability/vrf.md`
    dokumentieren die Prometheus-Namen `consensus_vrf_verification_time_ms` und
    `consensus_quorum_verifications_total`, inklusive Fehlerslices für VRF- und
    Witness-Pfade.【F:docs/observability/consensus.md†L1-L120】【F:docs/observability/vrf.md†L1-L120】
  * Grafana-Boards `docs/dashboards/consensus_grafana.json` und
    `docs/dashboards/consensus_proof_validation.json` visualisieren Laufzeiten,
    Fehlerraten und Witness-Events; Runbooks verlangen, dass Operatoren diese
    Panels exportieren und archivieren.【F:docs/dashboards/consensus_grafana.json†L1-L200】【F:docs/dashboards/consensus_proof_validation.json†L1-L200】
* **Runbooks.**
  * `docs/runbooks/observability.md` beschreibt Schritt-für-Schritt-Checks, um
    VRF- und Quorumfehler nachzustellen, inklusive cURL-Abfragen des
    `/status/consensus`-Endpoints und der Simnet-Harness-Ausführung.【F:docs/runbooks/observability.md†L27-L59】
  * `docs/runbooks/plonky3.md` koppelt Performance-Audits mit den genannten
    Dashboards, damit Proof-Latenzen dokumentiert und archiviert werden.【F:docs/runbooks/plonky3.md†L1-L120】
* **Release-Metadaten.** `docs/release_notes.md` listet pro Version Circuit-IDs,
  Constraint-Zählungen und Backend-Support und wird automatisch im Release-Workflow
  gepflegt, sodass Auditor:innen Proof-Artefakte eindeutig zuordnen können.【F:docs/release_notes.md†L1-L160】【F:.github/workflows/release.yml†L1-L120】

## Konsequenzen

* Operatoren verfügen über einen Ende-zu-Ende-Nachweisfluss, der VRF-Auswahl,
  Witness-Verteilung und Quorumvalidierung vollständig abdeckt. Fehler werden
  sowohl auf Metrikebene als auch im API-Status widergespiegelt.【F:rpp/runtime/node.rs†L5005-L5035】【F:rpp/rpc/src/routes/consensus.rs†L30-L95】
* Konsensverletzungen resultieren in deterministischen Slashing-Events; Tests
  verifizieren die korrekte Strafverteilung und erleichtern Audits.【F:tests/consensus/censorship_inactivity.rs†L160-L220】
* Dokumentation, Tests und Observability-Artefakte sind miteinander verknüpft,
  wodurch Reviewer jeden Fehlpfad reproduzieren können, ohne in den Code greifen
  zu müssen.

## Open Questions/Follow-ups

* GPU-Offload für Witness-Konstruktion ist in Arbeit; das Ziel ist die Reduktion
  der `consensus_vrf_verification_time_ms`- und Witness-Latenzen unter 50 ms.
* Zusätzliches Sampling für Witness-Outlier-Metriken (Per-Validator-Histogramme)
  wird vorbereitet, benötigt jedoch noch Telemetrie-Erweiterungen in der
  Runtime.
* Wir evaluieren einen verpflichtenden PR-Gate für das
  `consensus_quorum_stress`-Szenario, sobald die Simnet-Laufzeiten unter die
  aktuellen CI-Grenzen fallen.
