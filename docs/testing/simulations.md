# Simnet Harness

The Simnet harness orchestrates end-to-end network and consensus simulations by
loading a single scenario description (`.ron`) that enumerates every process to
spawn, the configuration to apply, and the follow-up analysis that should be
recorded. The binary lives under [`tools/simnet`](../../tools/simnet) and shares
the process runner and P2P topology logic with [`rpp/sim`](../../rpp/sim), so
new scenarios can reuse existing admission, gossip, and consensus fixtures.

## Voraussetzungen

* Rust Stable ≥1.75 (installiert über `rustup`).
* Python 3.9+ für die Auswertung via
  [`scripts/analyze_simnet.py`](../../scripts/analyze_simnet.py).
* Optional: gesetzte Feature-Flags (`XTASK_NO_DEFAULT_FEATURES`,
  `XTASK_FEATURES`), um produktive Build-Profile wie
  `prod,prover-stwo,backend-plonky3` zu aktivieren.

Nach dem Checkout genügt `cargo run -p simnet -- --help`, um die verfügbaren
Flags zu prüfen.【F:tools/simnet/src/main.rs†L1-L58】

## Szenarien ausführen

### Direkter Aufruf

```bash
cargo run -p simnet -- \
  --scenario tools/simnet/scenarios/ci_block_pipeline.ron \
  --artifacts-dir target/simnet/ci-block-pipeline
```

Der Runner lädt [`ci_block_pipeline.ron`](../../tools/simnet/scenarios/ci_block_pipeline.ron),
startet die in der Datei beschriebenen Nodes/Wallets und schreibt Logs unter
`logs/`. Zusammenfassungen landen per Default in `summaries/` und enthalten die
propagierten Nachrichten, p50/p95-Latenzen und – falls das Szenario
Vergleichsdaten definiert – Delta-Metriken.【F:tools/simnet/src/config.rs†L10-L132】

Wichtige CLI-Flags:

* `--artifacts-dir`: überschreibt den in der Scenario-Datei hinterlegten Pfad
  (Standard: `target/simnet/<slug>`).
* `--keep-alive`: hält Prozesse nach der Auswertung für 60 s offen, um manuell
  Logs oder RPC-Endpunkte zu inspizieren.【F:tools/simnet/src/main.rs†L18-L58】

### `cargo xtask test-simnet`

Für reproduzierbare CI-Läufe kapselt `cargo xtask test-simnet` die Referenz-
Szenarien. Der Task respektiert die Feature-Flags der Umgebung, erstellt für
jede `.ron`-Datei ein eigenes Artefakt-Verzeichnis und führt die folgenden
Szenarien aus：【F:xtask/src/main.rs†L60-L110】

1. [`ci_block_pipeline.ron`](../../tools/simnet/scenarios/ci_block_pipeline.ron) –
   Smoke-Test für Blockproduktion, Gossip und RPC-Verfügbarkeit.
2. [`ci_state_sync_guard.ron`](../../tools/simnet/scenarios/ci_state_sync_guard.ron) –
   Guard-Szenario für Snapshot-/Light-Client-Sync inklusive Root-Schutz.
3. [`consensus_quorum_stress.ron`](../../tools/simnet/scenarios/consensus_quorum_stress.ron) –
   Phase‑2-Stresstest der VRF-/Quorum-Constraints, generiert CSV- und JSON-Reports
   über Tamper-Rejections und Prover/Verifier-Latenzen.【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】

Beispiel für einen vollständigen Phase‑2-Lauf:

```bash
XTASK_NO_DEFAULT_FEATURES=1 \
XTASK_FEATURES="prod,prover-stwo,backend-plonky3" \
cargo xtask test-simnet
```

Die Kommandoausgabe listet jeden Szenario-Namen; bei Fehlern (z. B.
Start-Timeouts oder abgelehnten Prozessen) bricht `xtask` mit einem nicht-null
Exitcode ab.【F:xtask/src/main.rs†L60-L110】

## Artefakte und Auswertung

Jedes Artefaktverzeichnis enthält:

* `logs/<prozess>.log` – stdout/stderr aller gestarteten Prozesse.
* `summaries/*.json` – Netzwerk- oder Konsensusberichte inklusive p50/p95-Werten
  und Tamper-Zählern.
* Optional `summaries/*.csv` für konsensusbezogene Laufzeitverteilungen (z. B.
  im Quorum-Stress-Szenario).【F:tools/simnet/src/config.rs†L118-L200】

Die Auswertung erfolgt mit:

```bash
python3 scripts/analyze_simnet.py \
  target/simnet/ci-block-pipeline/summaries/ci_block_pipeline.json \
  target/simnet/consensus-quorum-stress/summaries/consensus_quorum_stress.json
```

Das Skript bricht bei Überschreitung der Standard-Schwellen (P2P p95 > 500 ms,
Consensus-Prove p95 > 5.5 s, Consensus-Verify p95 > 3.2 s oder akzeptierte
Tamper-Proofs) mit Exitcode 1 ab und liefert damit CI-freundliche Fail-fast-
Signale.【F:scripts/analyze_simnet.py†L1-L120】 Die Ausgabe listet zusätzlich die
Anzahl abgelehnter VRF-/Quorum-Manipulationen, damit Auditor:innen
Nachvollziehbarkeit herstellen können.【F:scripts/analyze_simnet.py†L120-L200】

## Szenario-Katalog & Ownership

| Datei | Zweck | Owner |
| --- | --- | --- |
| [`ci_block_pipeline.ron`](../../tools/simnet/scenarios/ci_block_pipeline.ron) | Basislauf für Blockproduktion, Gossip, Wallet ↔ Node RPC. | Core Testing (`#simnet-harness`)|
| [`ci_state_sync_guard.ron`](../../tools/simnet/scenarios/ci_state_sync_guard.ron) | Überprüft Snapshot-/Light-Client-Schutzpfade und Root-Guards. | Core Testing (`#state-sync`)|
| [`consensus_quorum_stress.ron`](../../tools/simnet/scenarios/consensus_quorum_stress.ron) | VRF-/Quorum-Stresstest mit Tamper-Injektion und Latenzmetriken. | Consensus/Proofs (`#consensus-ztk`)|

Die Owner-Channels sind im internen Slack verankert; bei Ausreißern oder neuen
Szenarioanforderungen bitte direkt dort eskalieren.

## Ergebnisse interpretieren

* **P2P-Szenarien:** Prüfen, ob `propagation_ms p95` innerhalb der dokumentierten
  Schwellen bleibt. Die Ausgabe von `scripts/analyze_simnet.py` zeigt ebenfalls
  Deltas gegenüber Referenzläufen (falls konfiguriert) und sollte bei positiven
  Werten oberhalb von +50 ms untersucht werden.【F:scripts/analyze_simnet.py†L1-L120】
* **Consensus-Stress:** Die JSON- und CSV-Dateien enthalten p50/p95/max für
  Prover/Verifier, `tamper_vrf`/`tamper_quorum` zählen erwartete Ablehnungen.
  Unerwartete Akzeptanzen (`unexpected_accepts > 0`) gelten als Blocker und
  lösen einen roten Status in Nightly aus.【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】【F:scripts/analyze_simnet.py†L120-L200】

## CI- und Nightly-Integration

* **CI (`.github/workflows/ci.yml`):** Der Job `simnet-smoke` ruft
  `cargo xtask test-simnet` mit Standard-Feature-Flags auf und lädt die artefakte
  der Smoke-Szenarien hoch. Trigger: `pull_request` gegen `main`.【F:.github/workflows/ci.yml†L63-L118】
* **Nightly (`.github/workflows/nightly.yml`):** Der neue Job `simnet` führt
  täglich um 01:30 UTC `cargo xtask test-simnet` mit dem Production-Feature-Set
  aus, wertet anschließend alle JSON-Summaries mit
  `scripts/analyze_simnet.py` aus und veröffentlicht ein Tarball mit Logs,
  JSON- und CSV-Reports. Triggert automatisch sowie manuell über
  `workflow_dispatch`. Bei Grenzwertüberschreitungen setzt der Analyse-Schritt
  den Workflow-Status auf rot (Fail-fast).【F:.github/workflows/nightly.yml†L1-L86】

Alle Artefakte stehen für 30 Tage im Actions-Tab bereit und sind im Weekly
Status-Bericht verlinkt.
