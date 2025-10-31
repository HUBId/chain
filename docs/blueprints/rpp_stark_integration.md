# Blueprint: Integration rpp-stark in chain (Rust 1.79, stable-only)

## 0) Leitplanken (gelten immer)

- Toolchain: Rust 1.79 überall (Repo-Root `rust-toolchain.toml`, CI pinned).
- Kein `#![feature]`, keine `-Z` Flags, kein Nightly—auch nicht in Subcrates (inkl. DB/Storage).
- Additiv integrieren: bestehendes Standard-Backend bleibt unverändert; `rpp-stark` ist optional.
- Feature-Gate in chain: `backend-rpp-stark` (Default aus).
- Alle Bytes/Hashes/Digests/Indizes exakt wie in `rpp-stark` (Golden-Vectors).
- Clippy: `-D warnings`. Keine `panic!`/`unwrap` im neuen Pfad.
- DoD global: Workspace `chain` baut & testet mit/ohne Feature; CI grün; keinerlei Nightly-Spuren.

## 1) Abhängigkeit & Feature-Gate

**Ziel**

`rpp-stark` als optionale Dependency; Build von `chain` ändert sich ohne Feature nicht.

**Aufgaben**

- `chain/Cargo.toml`:
  - `[features] backend-rpp-stark = []`
  - `rpp-stark` nur unter `cfg(feature = "backend-rpp-stark")` (git-URL / Tag).
- Keine bestehenden Backends anfassen.

**DoD**: `cargo build` ohne Feature unverändert grün; mit `--features backend-rpp-stark` kompiliert Workspace.

## 2) Adapter-Layer (Typen, Hash, Public-Inputs)

**Ziel**

Byte-kompatible Brücke von `chain` zu `rpp-stark`.

**Struktur (neue Dateien, Beispielpfade)**

- `chain/src/zk/rpp_adapter/felt.rs` — Alias/Wrapper für `rpp-stark`-Feldtyp (nur Weitergabe).
- `chain/src/zk/rpp_adapter/digest.rs` — fester 32-Byte Digest (Hex/Bytes-Konvertierungen, Debug/Display).
- `chain/src/zk/rpp_adapter/hash.rs` — falls `chain` getrennt hashen muss: Adapter auf die in `rpp-stark` festgelegte 32-B Hashfamilie; andernfalls nur Re-export.
- `chain/src/zk/rpp_adapter/public_inputs.rs` — kanonische LE-Kodierung & Feldreihenfolge exakt wie `rpp-stark/docs/PUBLIC_INPUTS_ENCODING.md`.

**Tests (Unit, stable)**

- Round-trip-Test der Public-Inputs-Bytes vs. `rpp-stark/vectors/stwo/mini/public_inputs.bin`.
- Digest-Gleichheit vs. `public_digest.hex`.

**DoD**: Adapter-Tests grün; Byte-Layouts belegt; keine Logik aus `rpp-stark` duplizieren.

## 3) Verifier-Fassade im Node

**Ziel**

Ein einheitlicher Einstieg im `chain`-Verifier, der `rpp_stark::verify()` kapselt.

**Aufgaben**

- `chain/src/zk/verifier.rs` o. ä.:
  - Trait `ZkVerifier` (falls vorhanden) erweitern oder neue Fassade `RppStarkVerifier` hinter Feature-Gate.
  - Inputs: `params` (bin), `public_inputs` (bin/struct), `proof` (bin).
  - Aufruf `rpp_stark::verify(...)`.
  - Fehler-Mapping: präzise Übersetzung auf Node-Error.
  - Report: Flags (`params_ok`, `public_ok`, `merkle_ok`, `fri_ok`, ggf. `composition_ok`), `total_bytes`.
  - Ergebnis-Struct `RppStarkVerificationReport` mit Stage-Flags + Byte-Länge exponieren und für Operator/Telemetry dokumentieren.

**DoD**: Smoke-Test ruft `verify()` durch, liefert Report; keine Änderung am Default-Backend.

## 4) Public-Digest & Size-Gate (Kontrakt)

**Ziel**

Node berechnet identischen `public_digest`; Node-Limit == Library-Limit.

**Aufgaben**

- Public-Digest:
  - Im Adapter `public_inputs.rs`: Funktion `compute_public_digest()` (LE-Bytes → 32-B Digest) exakt wie `rpp-stark` (Hashfamilie, Reihenfolge).
  - Optionaler Vor-Check im Verifier-Pfad (Log bei Mismatch, aber Abbruch kommt ohnehin im Verifier).
- Size-Gate:
  - Node-Konfig `max_proof_size_bytes` (falls noch nicht vorhanden).
  - Dokumentiertes Mapping auf `rpp-stark` Param `max_size_kb`.
- Testfälle: Proof knapp unter/über Grenze → OK/Fail.

**DoD**: Digest-Gleichheit demonstriert (gegen Golden-Vector), Limits greifen identisch.

## 5) Golden-Vector Interop (E2E-Test in chain)

**Ziel**

Beweise, dass `chain` den `rpp-stark`-Mini-Proof bitgenau verifizieren kann.

**Vektorzufuhr**

- Variante A (empfohlen): Git-Submodule `rpp-stark` unter `chain/tests/vendor/rpp-stark/` (nur Tests lesen).
- Variante B: Einmalige Kopie der Mini-Vektoren nach `chain/tests/interop_vectors/` (mit Quelle/Commit-Verweis in README).

**Integrationstest**

- `chain/tests/interop_rpp_stark.rs` (Feature-guarded):
  - Lädt `params.bin`, `public_inputs.bin`, `public_digest.hex`, `proof.bin`, `indices.json`.
  - Ruft `RppStarkVerifier::verify()` auf.
  - Assertions: alle relevanten Flags `true`; `total_bytes == len(proof.bin)`; `public_digest`-Gleichheit; Indices lokal (implizit im Verifier) == Vektor (nur Vergleich im Test).

**DoD**: Test grün unter `--features backend-rpp-stark`; deterministisch bei Re-Runs.

## 6) Pipeline-Hook & Telemetrie

**Ziel**

`rpp-stark`-Verifikation in der realen Block/Tx-Validierung — additiv.

**Aufgaben**

- Im Validierungs-Pfad (Block/Tx) neuen Backend-Case `rpp-stark` hinter Feature:
  - Proof-Typ-Dispatch: wenn `rpp-stark` → `RppStarkVerifier`.
- Telemetrie: Metriken (`valid`/`invalid`, `proof_bytes`, `verify_duration_ms`) mit Label `proof_backend="rpp-stark"`.

**DoD**: E2E-Pfad läuft; Default-Backend unverändert. ✅ Hooks publizieren Stufen via `rpp/node/src/pipeline/mod.rs`, Smoke-Test `tests/pipeline/end_to_end.rs` bestätigt Wallet → Proof → BFT → Firewood.

## 7) CI-Matrix (stable) & Quality Gates

**Ziel**

Beides prüfen: Default & `rpp-stark`-Backend—komplett auf 1.79.

**Aufgaben**

- `.github/workflows/*`:
  - Matrix: `features: ["", "backend-rpp-stark"]`
  - Toolchain: `1.79.0`; Jobs: `build`, `test`, `clippy -D warnings`, `fmt --check`.
- Bei Submodule-Variante: checkout mit `submodules: true`.
- Tests nur lesend; keine Artefakt-Mutation in CI.

**DoD**: Beide Spalten grün; Clippy sauber; keine Nightly-Jobs.

## 8) Doku (Operator & Dev)

**Ziel**

Betreiber & Entwickler können `rpp-stark` aktivieren, testen, debuggen.

**Inhalte**

- `chain/docs/zk_backends.md`:
  - Abschnitt „rpp-stark (stable)“:
    - Build: `--features backend-rpp-stark` (stable 1.79)
    - Interop-Test („Golden-Vector Verify“)
    - Public-Inputs-Encoding-Link ins `rpp-stark`-Repo
    - Size-Gate-Mapping Node ↔ Library
    - Fehlermeldungen (Header/Params/Public/Size/Indices/Merkle/FRI/Composition) und Handling
- `README.md`: kurzer Link/Teaser.

**DoD**: Schritt-für-Schritt-Anleitung < 10 Minuten umsetzbar.

## 9) Storage/DB (stable-Safety Check)

**Ziel**

Sicherstellen, dass die DB-Schicht ohne Nightly läuft.

**Aufgaben**

- Grep auf `#![feature]`, `-Z` in `storage/` oder `firewood/` Unterprojekten.
- `rust-version = "1.79"` in deren `Cargo.toml`.
- CI baut Tests für Storage auf 1.79.
- (Wenn C/C++-Bindings: sicherstellen, dass nur Toolchain, nicht Nightly, benötigt wird.)

**DoD**: Storage baut & läuft auf 1.79; Node startet mit DB-Pfad in `data_dir`.

## 10) Risiken & Gegenmaßnahmen

- **ABI-Drift (Proof-Bytes ändern sich)**
  - Gegenmaßnahme: Interop-E2E-Test nimmt die `rpp-stark` Golden-Vectors als Quelle der Wahrheit. Bei `PROOF_VERSION++` Vektoren updaten & Changelog anpassen.
- **Digest-Mismatch (Public-Inputs)**
  - Gegenmaßnahme: Unit-Test im Adapter vergleicht Bytes & `public_digest.hex`, bevor der Node den Verifier ruft.
- **Matrix-Komplexität**
  - Gegenmaßnahme: Feature-Gate isoliert; Default-Spalte bleibt minimal.
- **Versehentlicher Nightly-Leak**
  - Gegenmaßnahme: Lint-Job, der auf `#![feature]`/`-Z` in allen Dateien prüft; Toolchain fix auf 1.79.

## 11) Abnahme (Definition of Done — Integration abgeschlossen)

- ✅ `backend-rpp-stark` Feature existiert; Workspace baut mit/ohne Feature (1.79).
- ✅ Adapter-Layer mappt Felt/Digest/Public-Inputs bytegenau; Unit-Tests belegen es.
- ✅ Verifier-Fassade ruft `rpp_stark::verify()`; Report & Fehler sauber gemappt.
- ✅ Node-Size-Gate & Public-Digest Kontrakt geprüft.
- ✅ Interop-E2E-Test nutzt `rpp-stark` Golden-Vectors; grün & deterministisch.
- ✅ Validierungs-Pipeline prüft `rpp-stark`-Proofs (separater Pfad, Feature-guarded).
- ✅ CI-Matrix (stable) deckt beide Pfade ab; Clippy/Format grün.
- ✅ Doku erklärt Aktivierung, Tests & Troubleshooting.
- ✅ Keine Nightly-Reste (grep-Check), DB/Storage bauen auf 1.79.
