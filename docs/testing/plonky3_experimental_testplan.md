# Plonky3 Stub Test Plan & Gaps

## Scope

Aktueller Fokus: Die Stub-Implementierung validieren und offene Punkte für die
echte Plonky3-Integration dokumentieren.

* Wallet- und Node-Flows erzeugen deterministische JSON-Proofs aus dem Stub und
  prüfen Commitments/Metadaten – echte Plonky3-Beweise fehlen noch.【F:rpp/proofs/plonky3/README.md†L1-L34】
* Verifier-Integrationen akzeptieren die Stub-Artefakte und speisen Health-
  Telemetrie ein; reale Kryptoprüfungen folgen erst mit dem Vendor-Backend.【F:rpp/proofs/plonky3/verifier/mod.rs†L1-L120】
* Telemetrie-Snapshots tracken Stub-Läufe, sodass Dashboards vorab validiert
  werden können.

## Test Commands

| Command | Purpose |
| --- | --- |
| `scripts/test.sh --backend plonky3 --unit --integration` | Läuft gegen das Stub-Backend, um Fixtures, Commitment-Checks und Telemetrie-Hooks abzusichern.【F:scripts/test.sh†L1-L220】 |
| `cargo test --features backend-plonky3 --test plonky3_transaction_roundtrip` | Prüft deterministische Wallet-Fixtures und dokumentiert fehlende echte Beweise.【F:tests/plonky3_transaction_roundtrip.rs†L1-L200】 |
| `cargo test --features backend-plonky3 --test plonky3_recursion` | Validiert Aggregations-Checks des Stubs und markiert offene TODOs für echte Beweise.【F:tests/plonky3_recursion.rs†L1-L360】 |
| `cargo test --package rpp-chain --lib --features backend-plonky3` | Deckt Telemetrie- und API-Helfer für das Stub-Backend ab.【F:rpp/proofs/plonky3/prover/mod.rs†L201-L233】 |

Der Release-Workflow führt `scripts/test.sh` weiterhin aus, deckt aber nur das
Stub-Backend ab. Ein dedizierter Vendor-Lauf folgt erst nach Integration der
echten Artefakte.【F:.github/workflows/release.yml†L1-L160】【F:rpp/proofs/plonky3/tests.rs†L58-L74】

## Results

| Command | Outcome |
| --- | --- |
| `scripts/test.sh --backend plonky3 --unit --integration` | ⚠️ Läuft in CI, prüft aber nur das Stub-Backend.【F:.github/workflows/release.yml†L1-L160】 |
| `cargo test --features backend-plonky3 --test plonky3_transaction_roundtrip` | ✅ Stub-Fixtures bestehen weiterhin lokal und in CI.【F:tests/plonky3_transaction_roundtrip.rs†L1-L200】 |
| `cargo test --features backend-plonky3 --test plonky3_recursion` | ✅ Rekursionspfade des Stubs werden abgedeckt; echte Verifikation steht aus.【F:tests/plonky3_recursion.rs†L1-L360】 |
| `cargo test --package rpp-chain --lib --features backend-plonky3` | ✅ Telemetrie-Helfer für das Stub-Backend gedeckt.【F:scripts/test.sh†L1-L220】 |

## Offene Arbeitsschritte

1. Vendor-Plonky3-Prover/Verifier anbinden und Stub-Proof-Generierung ersetzen.
2. CI-Matrix (`ci-plonky3-matrix`) reaktivieren, sobald reproduzierbare echte
   Beweise möglich sind.【F:rpp/proofs/plonky3/tests.rs†L58-L74】
3. Telemetrie-/Dashboard-Grenzwerte mit echten Messwerten kalibrieren, nachdem
   produktive Läufe Daten liefern.
