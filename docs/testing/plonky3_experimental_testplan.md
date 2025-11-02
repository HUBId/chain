# Plonky3 Production Test Plan

## Scope

Phase 2 liefert den produktiven Plonky3-Prover/-Verifier. Diese Teststrategie
überprüft Keygen-, Prover- und Verifier-Flows über alle Circuit-Familien und
belegt die Tamper-Resilienz, die das Blueprint fordert.

* Wallet- und Node-Flows erzeugen echte Plonky3-Proofs, die in CI und Nightly
  verifiziert werden. Telemetrie exportiert Cache-Größe sowie Erfolgs-/Fehler-
  Zähler, die im Runbook dokumentiert sind.【F:rpp/proofs/plonky3/prover/mod.rs†L19-L520】【F:rpp/runtime/node.rs†L161-L220】
* Das Simnet-Stressszenario `consensus-quorum-stress` misst Keygen/Prover/Verifier
  unter hoher Validator-/Witness-Last und injiziert absichtlich manipulierte
  VRF-/Quorum-Daten. Die Nightly-Pipeline speichert die JSON-Summary und bricht
  bei p95-Verletzungen oder unerwartet akzeptierten Tamper-Proofs ab.【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】【F:scripts/analyze_simnet.py†L1-L200】
* Acceptance-Kriterien (maximale p95-Latenzen, Fehlerraten, Tamper-Rejections)
  sind in `performance/consensus_proofs.md` festgehalten und werden vom
  Grafana-Export `docs/dashboards/consensus_proof_validation.json` visualisiert.

## Test Commands

| Command | Purpose |
| --- | --- |
| `scripts/test.sh --backend plonky3 --unit --integration` | Führt Unit- und Integrationstests mit dem produktiven Plonky3-Backend aus, inklusive Konsensus-/Tamper-Tests.【F:scripts/test.sh†L1-L220】【F:tests/consensus/consensus_proof_integrity.rs†L1-L140】 |
| `cargo test --features backend-plonky3 --test plonky3_transaction_roundtrip` | Validiert Transaktions-/State-/Pruning-Proofs und die deterministische Witness-Kodierung unter dem Vendor-Backend.【F:tests/plonky3_transaction_roundtrip.rs†L1-L200】 |
| `cargo test --features backend-plonky3 --test plonky3_recursion` | Prüft rekursive Aggregationen und stellt sicher, dass Verifier-Checks Manipulationen an Witness-Payloads abweisen.【F:tests/plonky3_recursion.rs†L1-L360】 |
| `cargo run -p simnet -- --scenario tools/simnet/scenarios/consensus_quorum_stress.ron --artifacts-dir target/simnet/consensus-quorum-stress` | Lasttest für Konsensus-Proofs mit VRF-/Quorum-Tamper; erzeugt JSON-/CSV-Summaries für `scripts/analyze_simnet.py`. |
| `python3 scripts/analyze_simnet.py target/simnet/consensus-quorum-stress/summaries/consensus_quorum_stress.json` | Prüft p95-Grenzwerte und Tamper-Rejections. Schlägt fehl, wenn Acceptance-Kriterien verletzt werden.【F:scripts/analyze_simnet.py†L1-L200】 |

## Results

| Command | Outcome |
| --- | --- |
| `scripts/test.sh --backend plonky3 --unit --integration` | ✅ Produziert Vendor-Proofs für alle Circuit-Familien und verifiziert sie innerhalb der Blueprint-Grenzen.【F:scripts/test.sh†L1-L220】 |
| `cargo test --features backend-plonky3 --test plonky3_transaction_roundtrip` | ✅ Deckt Witness-Roundtrips und Public-Input-Validierung ab.【F:tests/plonky3_transaction_roundtrip.rs†L1-L200】 |
| `cargo test --features backend-plonky3 --test plonky3_recursion` | ✅ Prüft rekursive Aggregationen und lehnt manipulierte VRF-/Quorum-Werte ab.【F:tests/plonky3_recursion.rs†L1-L360】 |
| Simnet + Analyse | ✅ `consensus-quorum-stress` bleibt unter den dokumentierten p95-Grenzen und lehnt alle Tamper-Proofs ab (siehe `performance/consensus_proofs.md`). |

## Offene Arbeitsschritte

1. GPU-basierte Benchmarks ergänzen (Nightly-Matrix erweitern, sobald dedizierte
   Runner verfügbar sind).
2. Offline-Key-Distribution (Caches/Artifacts) für Mehr-Region-Deployments im
   Runbook mit konkreten SLOs hinterlegen.
3. Dashboard-Alerts für plonky3-spezifische Metriken (`backend="plonky3"`) mit
   Produktionsschwellen verknüpfen.
