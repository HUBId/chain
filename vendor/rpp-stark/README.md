# rpp-stark

[![Latest release](https://img.shields.io/badge/latest-v1.0.0--beta-blue)](docs/RELEASE_NOTES.md)

## AIR pipeline overview

The AIR layer stitches together the execution trace, polynomial commitments, and
FRI sampling strategy described in Kap. 2–4 and 7. The high-level data flow is:

```text
Trace (Kap. 2) --> Low-Degree Extension (Kap. 3)
                    |
                    v
          Constraint Composition (Kap. 3–4)
                    |
                    v
            Merkle Commitments (Kap. 4)
                    |
                    v
        Transcript / Fiat–Shamir (Kap. 4)
                    |
                    v
                FRI Queries (Kap. 7)
```

Each arrow corresponds to a module under `src/air`:

| Stage | Module | Kap. | Deterministic contract |
|-------|--------|------|------------------------|
| Trace ingestion | [`src/air/trace.rs`](src/air/trace.rs) | 2–3 | Fixed row iterator and column ordering feeding the LDE. |
| LDE profiles | [`src/fft/lde.rs`](src/fft/lde.rs) | 3 | Blowup, ordering, and coset labelling shared by prover and verifier. |
| Composition | [`src/air/composition.rs`](src/air/composition.rs) | 3–4 | Transition/boundary combination bound to transcript challenges. |
| Merkle commitments | [`src/params/mod.rs`](src/params/mod.rs) & [`src/air/types.rs`](src/air/types.rs) | 4 | Canonical leaf encodings and arity selection. |
| Transcript | [`src/transcript/mod.rs`](src/transcript/mod.rs) | 4 | Label ordering for Fiat–Shamir challenges. |
| FRI | [`src/fri`](src/fri) | 7 | Query schedule derived from transcript seeds. |

## Interop-Dokumentation

- [STWO-Interoperabilität](docs/STWO_INTEROP.md)
- [Golden Vectors (STWO Interop)](vectors/stwo/mini/)
- [Public-Inputs-Encoding](docs/PUBLIC_INPUTS_ENCODING.md)
- [Proof-Size-Gate](docs/PROOF_SIZE_GATE.md)

### Trace and public-input schema

```
┌──────────────┐    ┌───────────────────────┐
│ Trace main   │    │ context_tag : [u8;32] │
│ Trace aux    │    │ trace_length : u32    │
│ Trace perm   │    │ public_values : Vec<F>│
│ Trace lookup │    │ challenge_bound : u32 │
└──────────────┘    └───────────────────────┘
```

| Segment | Column symbol | Description |
|---------|----------------|-------------|
| `main` | `columns::MAIN_WIDTH` | Execution registers evaluated at every step. |
| `aux` | `columns::AUX_WIDTH` | Auxiliary witness columns for helper relations. |
| `permutation` | `columns::PERM_WIDTH` | State for permutation arguments (Kap. 3). |
| `lookup` | `columns::LOOKUP_WIDTH` | Witnesses backing lookup constraints. |

Public inputs mirror the schema from [`types::PublicInputs`](src/air/types.rs):

| Field | Encoding | Purpose |
|-------|----------|---------|
| `context_tag` | 32-byte array | Names the execution instance and binds Kap. 2 metadata. |
| `trace_length` | `u32` little-endian | Selects the LDE domain length. |
| `public_values` | `Vec<FieldElement>` | Exposed registers absorbed into the transcript. |
| `challenge_bound` | `u32` little-endian | Caps Fiat–Shamir sampling range as mandated in Kap. 4. |

All serialisation is byte-for-byte reproducible; replaying the same trace and
public inputs therefore yields identical transcript openings and FRI queries.

### Witness layout

Witness blobs follow the fixed header/body layout shown below:

1. `u32` little-endian row count.
2. Four `u32` little-endian column counters in the order `main`, `auxiliary`,
   `permutation`, `lookup`.
3. Column data encoded column-major: for each segment the declared number of
   columns is emitted, each containing `row_count` field elements in canonical
   little-endian form.

The worked LFSR example used by the prover declares a single main column and no
auxiliary segments. Its execution seed is carried in the execution proof body as
an 8-byte little-endian field element. Boundary constraints fix the first and
last row of the column to the deterministic LFSR state to ensure witnesses are
reproducible from public inputs.

### Transcript challenge ordering

The Fiat–Shamir transcript emits challenges in the order shown below. The phase
labels match [`AirTranscript`](src/air/traits.rs) and Kap. 4, ensuring that both
sides derive the same folding seeds and query indices.

```
Init → Public → TraceCommit → CompCommit → FRI(layer i) → Queries → Final
          │            │             │            │
          │            │             │            └─ FriFoldChallenge(i)
          │            │             └─ CompChallengeA
          │            └─ TraceChallengeA
          └─ PublicInputsDigest
```

The resulting challenge stream (`TraceChallengeA`, `CompChallengeA`, successive
`FriFoldChallenge(i)`, then `QueryIndexStream`) is highlighted in Kap. 7’s
worked example.

### Proof layout checkpoints

The execution-proof fixture emitted in `tests/proof_artifacts.rs` is frozen with
[`insta`](https://insta.rs/) to keep the ABI stable. The snapshot
`tests/snapshots/proof_artifacts__execution_proof_artifacts.snap` records the
most relevant artefacts:

| Artefakt | Quelle | Beschreibung |
|----------|--------|--------------|
| Trace-/Composition-Root | `proof_artifacts__execution_proof_artifacts.snap` (`trace_root`/`composition_root`) | Verankert die Merkle-Wurzeln des Ausführungsnachweises. |
| FRI-Layer-Roots | Snapshot-Feld `fri_roots` | Bewahrt die Layer-Sequenz für Fiat–Shamir & FRI-Sampling. |
| Sortierte Query-Indizes | Snapshot-Felder `trace_query_indices`, `composition_query_indices`, `fri_query_positions` | Überprüft deterministische Query-Schedules. |
| Pfadlängen-Histogramme | Snapshot-Felder `trace_path_lengths`, `composition_path_lengths`, `fri_path_lengths` | Machen Drift bei Merkle-Arity bzw. Bundle-Längen sofort sichtbar. |

Das Snapshot-Artefakt dient als Referenz für jede Änderung am Proof-Layout – bei
Abweichungen schlägt der zugehörige Test fehl und fordert eine bewusste
Aktualisierung.

### Negative-Matrix-Checkliste

Die Fehlerklassen des Verifiers werden durch gerichtete Tests in
`tests/proof_lifecycle.rs` abgedeckt. Wichtige Negativfälle:

| Szenario | Testfall | Erwarteter `VerifyError` |
|----------|----------|--------------------------|
| ParamDigest-Byte-Flip | `verification_report_flags_param_digest_flip` | `ParamsHashMismatch` |
| PublicDigest-Verfälschung | `proof_decode_rejects_public_digest_tampering` | `PublicDigestMismatch` |
| Header-Trace-Root-Mismatch | `verification_report_flags_header_trace_root_mismatch` | `RootMismatch::TraceCommit` |
| Header-Composition-Root-Mismatch | `verification_report_flags_header_composition_root_mismatch` | `RootMismatch::CompositionCommit` |
| FRI-Challenge-Flip | `verification_report_flags_fri_challenge_flip` | `MerkleVerifyFailed::FriPath` |
| Composition-Inkonsistenz | `verification_rejects_composition_leaf_misalignment_with_fri` | `CompositionInconsistent` |
| Proof-Größenüberschreitung | `verification_report_flags_proof_size_overflow` | `ProofTooLarge` |

Die Tabelle fungiert als „Negative Matrix“ und dokumentiert, welche Fehlerpfade
im Rahmen der Regressionstests zwingend aktiv bleiben.

## Low-degree extension profiles

Low-degree extension (LDE) configuration lives in [`src/fft/lde.rs`](src/fft/lde.rs).
Instead of providing executable extension routines the module now describes
profiles in terms of their blowup factor, evaluation ordering, coefficient
endianness and deterministic chunking strategy.  Two profiles are currently
documented:

* `PROFILE_X8`: the prover-default ×8 configuration optimised for radix-2 FFTs.
* `PROFILE_HISEC_X16`: a ×16 high-security profile used during audits.

### Audit feature flags

Two opt-in Cargo features expose additional metadata for audit tooling without
changing runtime behaviour:

* `audit-lde` enables static tables that enumerate the standard audit profiles.
* `audit-lde-hisec` extends the above with the high-security ×16 profile and is
  declared as a dependent feature.

## Continuous integration

[![CI](https://github.com/rpp-org/rpp-stark/actions/workflows/ci.yml/badge.svg)](https://github.com/rpp-org/rpp-stark/actions/workflows/ci.yml)

## Toolchain & CI

### Minimum Supported Rust Version (MSRV)

This crate targets **Rust 1.79 stable**. Builds are expected to succeed with the
stable channel at or above this compiler release without relying on nightly
features. The library is supported on the stable toolchain only; nightly
compilers or unstable flags are neither required nor tested.

### CI policy

The GitHub Actions workflow enforces the following gates:

* `cargo build --locked`
* `cargo test -p rpp-stark -- --nocapture`
* `cargo test snapshot_profiles -- --exact`
* `rustfmt --edition 2021 --check $(git ls-files 'src/*.rs' 'src/**/*.rs' 'src/bin/*.rs' 'benches/*.rs' 'benches/**/*.rs')`
* `cargo clippy --locked -- -D warnings`
* `cargo run --bin profile_reports -- --output reports --include-throughput`

Pull requests must pass all of these checks before merging.

> **Hinweis:** Jede Änderung an den eingebauten STARK-Profilen oder deren
> Serialisierung erfordert eine Aktualisierung der gefrorenen `insta`-Snapshots
> unter `tests/snapshots/params_roundtrip__*.snap`. Führe dazu lokal
> `cargo test snapshot_profiles -- --exact` (oder `cargo insta review`) aus und
> nimm die neuen Artefakte mit in den Commit auf.

### CI & Snapshots

Der Workflow [`snapshot-guard`](.github/workflows/snapshot-guard.yml) verhindert Merges, sobald Proof-/Params-Snapshots geändert wurden, ohne dass gleichzeitig `PROOF_VERSION` erhöht und im [`CHANGELOG.md`](CHANGELOG.md) dokumentiert wurde. Wer Snapshots aktualisiert, muss den Version-Bump in [`src/proof/types.rs`](src/proof/types.rs) sowie eine kurze ABI-Notiz im Changelog hinzufügen, damit der Guard wieder grünes Licht gibt. Weitere Hintergründe zu den eingefrorenen Golden-Vectors liefert [docs/STWO_INTEROP.md](docs/STWO_INTEROP.md).

Eine vollständige Übersicht über alle eingefrorenen Artefakte, ihre Ablageorte
und die Änderungsregeln bündelt [docs/SNAPSHOTS.md](docs/SNAPSHOTS.md).

### Linting & Style

- `cargo clippy --locked -- -D warnings` muss lokal und in CI sauber laufen.
- Neue `#[allow(...)]`-Attribute sind nur zulässig, wenn eine nahegelegene
  Begründung (Kommentar) dokumentiert, weshalb die Abweichung für das ABI oder
  deterministische Layout zwingend ist.
- Stil-Anpassungen sollen minimalinvasiv sein; keine API- oder Signaturänderung
  als Teil von Lint-Fixes.

## Projekt-Blueprint

Die folgende Spezifikation beschreibt die Zielarchitektur der Bibliothek
„rpp-stark – vollständige Library (v1.0, Rust stable only)“. Sie dient als
verbindliche Grundlage für Implementierung, Tests, Serialisierung und
Fehlermodell der gesamten Codebasis.

### Ziel & Scope

- **Zweck:** Eigenständige, deterministische STARK-Bibliothek mit klaren ABIs,
  Proof-Envelope, Verifier-API, Merkle/FRI/AIR/Composition, Serialisierung und
  Tests, kompatibel zur RPP-Chain (STWO-Default).
- **Rollen:** Wallet = Prover, Node = Verifier.
- **Ergebnis:** Byte-stabile Proof-Artefakte, präzise Fehlercodes,
  reproduzierbare Tests/Benches, CI-fähig – ohne nightly.

### Querschnitts-Policies (verbindlich)

- **Sprache/Toolchain:** Rust stable (MSRV festlegen und dokumentieren), keine
  `#![feature]`.
- **Safety:** Kein `unsafe`, keine Panics in Bibliothekslogik, keine
  `unwrap`/`expect`.
- **Determinismus:** Gleiche Inputs ⇒ bitidentische Outputs (Bytes, Roots,
  Indizes, Challenges).
- **Endianness:** Little-Endian für alle Ganzzahlen; Feldelemente als feste
  LE-Byte-Breite; Digests roh (byte-order-agnostisch).
- **Randomness:** Ausschließlich via Transcript (Fiat–Shamir); kein OS-RNG,
  keine Uhrzeit, kein Nonce aus Umgebung.
- **Fehler:** Wohldefinierte Enums (keine „stringly typed“ Zustände).
- **Hash & Merkle:** Hashfamilie via Params; STWO-kompatible 32-Byte
  Blake2s-Digests als Default (Adapter für alternative Hashes zulässig).
- **Versionierung:** Jede ABI- oder Protokolländerung ⇒ Versionsfeld erhöhen;
  ältere Verifier müssen deterministisch ablehnen.

### Feature-Flags (opt-in)

- `stark-core` (Standardkern)
- `parallel` (Rayon optional; muss bitidentische Ergebnisse liefern mit/ohne
  Parallelisierung)
- `audit-lde`, `audit-lde-hisec` (zusätzliche Prüfpfade/Assertions)
- `backend-rpp-stark` (für spätere Integration in chain)

Das Default-Feature-Set ändert kein bestehendes Verhalten außerhalb der
Library.

### Parallelisierungs-Feature

Das optionale Cargo-Feature `parallel` aktiviert deterministisch geplante
Rayon-Workloads für zentrale Hotspots:

* Radix-2 FFT-Stufen (bit-reverse und Cooley–Tukey) in `src/fft`.
* Merkle-Baum-Konstruktion in `src/merkle`.
* FRI-Folding (`binary_fold`) in `src/fri`.

Alle Algorithmen verwenden einen festen Chunk-Scheduler und teilen die Arbeit in
stabile Bereiche ein, damit die Reihenfolge der Speicherzugriffe unabhängig von
der Thread-Anzahl bleibt. Die sequentielle und die parallele Ausführung liefern
dadurch byte-identische Roots, Evaluierungen und Proof-Artefakte. Tests unter
`tests/parallel_equivalence.rs` verifizieren diesen Anspruch, indem sie die
Parallelisierung zur Laufzeit deaktivieren und Ergebnisse direkt vergleichen.

### Modulbaum & Dateien (Top-Level)

- `src/params/...` – Parameter, Profile, Hash-Bindings, `params_hash()`.
- `src/ser/...` – zentrales Serialisierungsschema (LE, Längenfelder,
  Enum-Tags).
- `src/transcript/...` – Domain-Separation, Absorb/Challenge, Labels,
  deterministische Streams.
- `src/merkle/...` – Tree, Proof, Open/Verify, Arity 2/4,
  Rightmost-Duplication.
- `src/fri/...` – Folding, Layer, Proof, Verify, Query-Orchestrierung.
- `src/air/...` – AIR-Traits, Trace-Schema, Beispiel-AIR, Composition-Builder.
- `src/proof/...` – Proof-Envelope, Ser/De, Verifier-API, Size-Gates.
- `tests/...` – Unit, Property, Negativ, Snapshot, E2E.
- `benches/...` – Criterion-Benches (nur stable-kompatible Messungen; keine
  nightly-Gates).

### Zentrales Serialisierungsschema (`ser/`)

- Ganzzahlen: `u16`/`u32`/`u64`/`u128` Little-Endian; `bool` als `u8` (0/1).
- Feldelemente: feste Byte-Länge, LE; keine Varints; keine Längenpräfixe
  innerhalb eines Felts.
- Digests: Rohbytes (keine Endianness-Interpretation).
- `Vec<T>`: `u32`-Elementanzahl als Präfix (Zählung in Elementen, nicht in
  Bytes).
- Optionale Felder: `u8`-Flag (0/1) vor dem Feld.
- Enums: fester Tag-Typ (`u8` oder `u16`), unbekannte Tags ⇒ Fehler.
- Zusammengesetzte Typen: Reihenfolge „Header → Fixed Fields → Längen →
  Arrays“; kein Padding.
- Fehlerbehandlung: `SerError`/`SerKind` → Modul-übergreifend auf
  `VerifyError::Serialization(SerKind)` mappen.
- Tests (Pflicht): Roundtrip aller Primitiven, Property-Tests für `Vec<Felt>`
  (begrenzte Länge), Negativfälle (falsche Längen/Tags), Snapshots für
  repräsentative Strukturen (MerkleProof, FriProof, Proof).

### Parameter (`params/`)

- Strukturfelder (verbindlich):
  - `proof`: `version (u16)`, `max_size_kb (u32)`.
  - `fri`: `domain_log2 (u16)`, `queries (u16)`, optionale zielgerichtete
    Layer-/Grad-Limits.
  - `merkle`: `arity (2/4)`, `leaf_width (u8)`, `leaf_encoding (Little; fixed)`,
    `domain-sep-Tag`.
  - `transcript`: `protocol_tag (u64)`, `seed ([u8;32])`.
  - `lde`: `order (RowMajor/ColMajor)`, ggf. Coset-Angaben.
  - `security`: `target_bits (u16)`, `soundness_slack_bits (u8)`.
  - `hash`: Familie/Variante, `digest_len` (z. B. 32).
- Funktion: `params_hash() -> [u8;32]` über kanonisch serialisierte Params.
- Profile: z. B. `PROFILE_X8`, `PROFILE_HISEC_X16`, dokumentiert mit festen
  Werten.
- Tests: Roundtrip & Snapshots der Profile; `params_hash` stabil; Invarianten
  (z. B. `1 << domain_log2 ≥ Trace-Länge`).

### Transcript (`transcript/`)

- Phasen & Reihenfolge (fix):
  1. Init: absorb `ParamsHash`, `ProtocolTag` (`u64` LE), `Seed ([32])`.
  2. Public: absorb `PublicInputsDigest`.
  3. TraceCommit: absorb `TraceRoot`; ggf. Komposition-Challenge(s).
  4. CompCommit (optional): absorb `CompRoot`; Challenges `CompChallengeA/B/...`
     (`α`-Vektor).
  5. FRI: pro Layer absorb `FriRoot(i)`, dann `FriFoldChallenge(i)`.
  6. Queries: absorb `QueryCount` (`u16` LE), dann Challenge-Strom
     `QueryIndexStream`.
  7. Final: optionale Abschlussbytes (reiner Bindungszweck).
- API (verbal): Konstruktor mit Params & Kontext; `absorb_*`
  (Bytes/Digest/Feld); `challenge_field`, `challenge_usize(range)`,
  `challenge_bytes(n)`; deterministisch, ohne OS-RNG.
- Tests: Reproduzierbarkeit der Challenge-Sequenzen bei identischen Inputs;
  Label-Reihenfolge fix.

### Merkle (`merkle/`)

- Leaf-Layout (fix):
  - `leaf_width` Feldelemente pro Leaf.
  - Jedes Felt als LE-Bytefolge; Leaves sind simple Konkatenation ohne Präfixe
    innerhalb des Leafs.
  - Reihenfolge: an `lde.order` gebunden (Row/ColMajor) – einmal definieren und
    überall referenzieren.
  - Domain-Separation: konsistente Tags (z. B. unterschiedlich für Leaves vs.
    innere Knoten).
- Baumregeln:
  - Arity 2 oder 4; Rightmost-Child-Duplication bei ungerader Blattzahl.
  - Proof: versionierte Struktur; Pfadknoten je Ebene arity-konform.
  - Batch-Openings: Indices aufsteigend & eindeutig.
- Fehlerfälle: `leere Leaves`, `LeafWidthMismatch`, `IndexOutOfRange`,
  `DuplicateIndex`, `ArityMismatch`, `InvalidPathLength`, `VerificationFailed`.
- Tests: Commit/Open/Verify; Multi-Openings; Negativ (manipulierte Pfade,
  falsche Root, Arity-Fehler); deterministische Snapshots.

### FRI (`fri/`)

- Spezifikation:
  - Domain: `N = 2^(domain_log2)`; Coset-Shift (falls verwendet) fix
    dokumentieren.
  - Folding (klassisch, arity-2): pro Layer `i` Challenge `βᵢ`; Paarbildungsregel,
    Abbildung der Indizes und Abbild `φ(x)` (z. B. `x→x²`) präzise festlegen.
  - Termination: definierte Anzahl Layer oder finaler Low-Degree-Check;
    Implementationsdetail dokumentieren (z. B. finaler Klein-Layer +
    Direktprüfung).
- Proof-Struktur (verbal): Version, `domain_log2`, `num_layers`, `roots[]`,
  `fold_challenges[]`, `query_proofs[]`, optional `oods`-Block.
- Verifier: Reproduziert Roots/Challenges via Transcript; generiert
  Query-Indizes lokal; prüft Merkle-Pfad & Faltungsrelation je Layer; finaler
  Check.
- Tests: E2E klein; Negativ (Challenge-Flip, Pfad-Fehler); deterministische
  Snapshots (Bytes, Roots, Challenges).

### AIR & Composition (`air/`)

- Traits & Rollen (verbal):
  - `Air`: `id` (stabil), `trace_schema`, `degree_bounds`, `public_spec`,
    `boundary(builder, first, last, public)`,
    `transition(evaluator, row, next, public)`.
  - `TraceBuilder`: deterministischer Witness-Generator aus PublicInputs.
  - `PublicInputsCodec`: kanonisches Encode/Decode (LE-Schema) + Digest
    (z. B. Blake2s-256).
  - `BoundaryBuilder`, `Evaluator`: deklarativ Constraints registrieren; intern
    polynomiale Ausdrücke.
  - `compose(...)`: Randomizer-α via Transcript; Gruppierung; Normierung gegen
    vanishing polynomials; Zielgrad einhalten; liefert Evaluationsvektor(e) +
    optional Commitment.
- Beispiel-AIR: LFSR oder MiMC-Round – komplett beschrieben (Rollen/Constraints
  /Public-Schema/Trace-Gen), um E2E-Tests zu ermöglichen.
- Tests: Determinismus, Degree-Grenzen, Boundary/Transition-Negativ,
  E2E-Mini.

### Proof-Envelope & Verifier (`proof/`)

- ABI (binärstabil):
  - Felder in dieser Reihenfolge:
    1. `proof_version (u16, =1)`
    2. `params_hash (32)`
    3. `public_digest (32)`
    4. `trace_commit (Digest)`
    5. Optional `comp_commit (Digest)` mit vorgeschaltetem `has_comp`-Flag (`u8`)
    6. `fri (FriProof; versioniert; über ser/ serialisiert)`
    7. `openings (Struktur für Trace/Composition/Aux)`
    8. Optional `telemetry` mit `has_tel`-Flag (`u8`) – nicht
       verifikationsrelevant
  - `openings.trace` muss existieren; `composition`/`aux` optional.
  - Jedes Merkle-Bundle: `root`, `indices (u32, aufsteigend & eindeutig &
    identisch zur lokalen Query-Liste)`, `leaves`, `paths`. Längenfelder
    konsistent.
- Verifier-Ablauf (fix):
  - Header-Checks: Version, `params_hash`, `public_digest`, Proof-Größe (echte
    Serialisierungslänge ≤ `max_size_kb × 1024`).
  - Transcript-Rebuild: absorb in fester Reihenfolge: `ParamsHash → ProtocolTag →
    Seed → PublicDigest → TraceRoot → optional CompRoot → alle FRI-Roots` in
    Proof-Reihenfolge; Challenges ziehen (`Composition-α` falls vorhanden; dann
    pro FRI-Layer `FriFoldChallenge`).
  - Query-Indizes lokal erzeugen: `q = params.fri.queries`,
    `N = 2^(domain_log2)`; via `challenge_usize` exakt `q` Werte; danach
    aufsteigend sortieren und Duplikate entfernen (deterministisch). Ergebnis
    muss exakt `openings.trace.indices` entsprechen – andernfalls
    `IndicesNotSorted`/`IndicesDuplicate`/`IndicesMismatch`.
  - Merkle-Openings prüfen: Root-Gleichheit (`RootMismatch`), Länge der Vektoren
    (`Indices`/`Leaves`/`Paths`), Pfad-Verifikation je Index (`MerkleVerifyFailed`).
  - FRI verifizieren: `fri_verify(...)`; Fehler 1:1 mappen.
  - Kompositions-Bindung (falls `comp_commit` existiert): Leaves, auf die
    FRI-Komposition referenziert, müssen bytegenau den `composition`-Leaves an
    denselben Indizes entsprechen (`CompositionInconsistent` bei Abweichung).
  - Report: Flags setzen (`params_ok`, `public_ok`, `merkle_ok`, `fri_ok`,
    `composition_ok`), `total_bytes` als echte Serialisierungslänge, `error`
    für den ersten Fehler. Der Report spiegelt keinen vollständigen `Proof`
    mehr wider – Decoder greifen bei Bedarf direkt auf die Proof-Bytes zu.
- Fehler-Taxonomie (final):
  - `VersionMismatch { expected, got }`
  - `ParamsHashMismatch`
  - `PublicDigestMismatch`
  - `ProofTooLarge { max_kb, got_kb }`
  - `EmptyOpenings` (trace fehlt/leer)
  - `IndicesNotSorted`
  - `IndicesDuplicate { index }`
  - `IndicesMismatch`
  - `RootMismatch { section }`
  - `MerkleVerifyFailed { section }`
  - `FriVerifyFailed(FriError)`
  - `CompositionInconsistent { reason }`
  - `Serialization(SerKind)`
  - `Unsupported(&'static str)`
- Größen-Gate: Proof nicht schätzen – serialisieren und Länge vergleichen.

### Query-Indizes (verbindlich)

- Niemals aus dem Proof übernehmen; immer lokal reproduzieren (Transcript).
- Nach Generierung: sortieren und deduplizieren (deterministisch).
- Identität zu `openings.trace.indices` ist Pflicht.

### Hashing & STWO-Adapter

- Default: Blake2s-256 (32 Byte) für maximale STWO-Kompatibilität (Merkle-Root
  & Public-Digest).
- Alternative Hashfamilien via Adapter-Hasher möglich (Poseidon/Rescue), sofern
  Root-Bytes identisch zum STWO-Pfad geliefert werden, falls Interop nötig.
- Domain-Separation konsistent (Leaf vs. Node; Trace vs. Composition vs. FRI).

### Testsuite (vollständig, stable-kompatibel)

- **Ser/Params:** Roundtrip aller `ser/`-Primitiven; Property-Tests für
  Felt-Vektoren (kleine Grenzen); Negativfälle (Längen/Tags);
  Profile-Snapshot-Bytes; `params_hash`-Stabilität.
- **Merkle:** Commit/Open/Verify (single & batch); Negativ: Pfad manipuliert,
  Root falsch, Arity-Fehler, unsortierte/duplizierte Indizes; Snapshots.
- **FRI:** E2E auf kleiner Domain; Negativ: Fold-Challenge flip, Pfad-Fehler;
  Snapshots von Roots/Challenges/Proof-Bytes.
- **AIR/Composition:** Beispiel-AIR (LFSR/MiMC): deterministischer Trace;
  Constraints-Checks; Degree-Grenzen; E2E klein.
- **Proof/Verifier:** Header-Checks (Positiv + vier Negativfälle
  Version/Params/Public/Size); Transcript/Queries (lokale Liste ==
  `openings.trace.indices`); Merkle-Openings (Positiv + unsortiert + Duplikat +
  Root-Mismatch + Pfad-Fehler); FRI-Glue (Positiv + Fold-Challenge flip ⇒
  Fehler); Composition-Konsistenz (Positiv + Leaf-Mutation ⇒ Fehler);
  Report-Flags plausibel; `total_bytes` korrekt.
- **Property-Tests (stable):** Random kleine Bäume/Indexmengen (engen Rahmen)
  ⇒ Verify OK. Random kleine Beispiel-AIR-Längen ⇒ Prove/Verify OK.
- **Snapshots (stabil):** Mini-Proof (z. B. `domain_log2=8`, `queries=2`,
  `leaf_width=1`, Arity-2, 1–2 FRI-Layer): Proof-Bytes, Roots,
  Fold-Challenges, Query-Liste, Pfadlängen.

### Performanceziele & Benches (stable-friendly)

- Merkle-Commit: Throughput für 1k/16k/64k Leaves; Verify-Latenz je Pfadlänge.
- FRI-Folding: Zeit für `N=2^14`, `2^16` (ohne nightly Tricks).
- Verifier E2E: `queries 8/16/32`, `domain_log2 12/16`.
- Keine Fail-Gates in CI; Berichte als Artefakte speichern.

### CI-Anforderungen (nur stable)

- Build/Test auf stable; MSRV separat prüfen, falls abweichend.
- `clippy -D warnings` (sauber).
- Snapshots deterministisch (keine Umgebungsabhängigkeiten).
- Artefakte: Bench-Reports, Snapshots.

### Integration in chain (später, optional)

- Adapter-Layer: Typalias für Felt, Digest-Wrapper, Hasher-Bindings zum
  STWO-Pfad.
- Feature-Gate `backend-rpp-stark`.
- Zwei kleine CLI-Binaries (separat) für prove/verify zum manuellen Testen.
- Proof-Size-Gate direkt an Node-Konfiguration abbilden.

### Milestones & Abnahme (empfohlene Reihenfolge, stable-only)

1. `ser/` (zentrales Schema) mit vollständigen Tests & Snapshots.
2. `params/` inkl. `params_hash()`, Profile, Snapshots.
3. `transcript/` mit deterministischen Labels/Challenges; Tests.
4. `merkle/` (Arity 2/4, RMD) inkl. Roundtrip/Negativ/Snapshots.
5. `fri/` (Proof & Verify) mit kleinen E2E-Fixtures; Snapshots.
6. `air/` + Beispiel-AIR + Composition (ohne Node-Anbindung) mit E2E-Mini.
7. `proof/` (Envelope/Ser + Header-Verifier) mit Header-Tests & Snapshots.
8. `proof/` (Transcript/Queries/Merkle/FRI/Composition) – komplette
   Verifier-Orchestrierung; volle Testsuite.
9. `parallel/` Flag (Rayon) – Beweis der Bit-Gleichheit on/off mit
   deterministischen Tests.

### Definition of Done

Alle Tests grün, Snapshots stabil, Clippy ohne Warnungen, Benches laufen,
Doku vollständig (Layouts, Reihenfolgen, Versionierung, Policies). Keine
nightly-Abhängigkeiten.

## Roadmap

### Phase 0 – Projektgerüst & Leitplanken

**Ziele:** saubere Basis, keine Nightly, deterministische Tests.

**Aufgaben**

- MSRV festlegen (README + CI).
- `clippy -D warnings`, `#![forbid(unsafe_code)]` in lib-root.
- CI: build+test+clippy auf stable; Artefakte: Test-Logs, Snapshots.
- CI: [Interop Golden-Vector Verify](.github/workflows/interop-golden-vector.yml) hält die Mini-Golden-Vektoren `verify()`-stabil.

**Definition of Done (DoD):** Pipeline grün, keine Warnings, Policies dokumentiert.

### Phase 1 – Zentrales Ser-Schema (`ser/`)

**Ziele:** einheitliche LE-Serialisierung für Ints, Felt, Digest, Vec, Option, Enums.

**Aufgaben**

- Ser-Helfer: `u16`/`u32`/`u64`/`u128` (LE), `bool` (`u8`), Bytes (LP `u32`), Felt (fixe LE-Byte-Länge), Digest (roh), `Vec<T>` (`u32`-Anzahl), Option (`u8`-Flag), Enum-Tag (`u8`/`u16`).
- Fehler `SerError`/`SerKind` + Mapping.
- Tests: Roundtrip, Property (kleine `Vec<Felt>`), Negativ (InvalidLength/Tag), Snapshots für repräsentative Strukturen.

**DoD:** Snapshots stabil, alle Module müssen diese Helfer verwenden.

### Phase 2 – Params (+ Profile & Hash)

**Ziele:** `StarkParams` + `params_hash()` stabil; Profile X8/HISEC.

**Aufgaben**

- Strukturfelder (`proof`/`fri`/`merkle`/`transcript`/`lde`/`security`/`hash`) exakt wie Blueprint.
- Profile definieren (z. B. X8, HISEC X16); Blake2s-256 als Default-Digest.
- Tests: Roundtrip, `params_hash`-Stabilität, Snapshot pro Profil, Invarianten.

**DoD:** `params_hash` fix, Profiles dokumentiert.

### Phase 3 – Transcript

**Ziele:** deterministische Fiat–Shamir-Engine mit festen Labels/Phasen.

**Aufgaben**

- Phasenfolge: Init → Public → TraceCommit → CompCommit? → FRI (layered) → Queries → Final.
- API: `absorb_bytes`/`digest`/`felt`; `challenge_field`/`usize`/`bytes`.
- Tests: Wiederholbarkeit (gleiche Inputs ⇒ gleiche Challenges), Label-Order.

**DoD:** deterministisch, Dokumentation mit Label-Tabelle.

### Phase 4 – Merkle

**Ziele:** Arity-2/4 Baum, festes Leaf-Layout (LE), Verify-API.

**Aufgaben**

- Leaf-Layout: `leaf_width × Felt` (LE-konkat), Order via `lde.order`.
- Domain-Separation (Leaf/Node Tags) dokumentieren.
- Proof-Struktur + Batch-Openings (Indices strikt aufsteigend + unique).
- Tests: Commit/Open/Verify; Negativ (Pfadknoten/Root/Arity/Indices), Snapshots.

**DoD:** Verify stabil; Bytes & Regeln dokumentiert.

### Proof-Envelope & Verifier (stable-only, Rust 1.79)

**Leitplanken (gelten für alle Schritte)**

- MSRV: 1.79; kein Nightly; kein `unsafe`; keine `unwrap`/`expect` in Lib-Logik.
- Ser/De: durch das zentrale `ser/`-Schema (Little-Endian, `u32`-Längen, Option-Flag `u8`).
- Determinismus: gleiche Inputs → bitidentische Bytes; Query-Indizes immer lokal aus dem Transcript generieren (nie aus dem Proof übernehmen).
- Snapshots: Proof-Bytes, Params-Bytes, FRI-Roots, Query-Listen als Referenz einfrieren.
- Fehler sind präzise, dokumentierte Enum-Varianten (keine „stringly typed“ Fehler).
- CI: `build`, `test`, `clippy -D warnings`; Snapshots als Artefakte.

**Gesamtübersicht der Meilensteine (nur Proof & Verifier Scope)**

- C1. Proof-ABI festnageln (Strukturen, Byte-Layout, Ser/De, Size-Gate)
- C2. Header-Verifier (Version, ParamsHash, PublicDigest, Größe)
- C3. Transcript-Rebuild & lokale Query-Indizes (sort & dedup)
- C4. Openings-Disziplin (Indices-Regeln)
- C5. Merkle-Prüfung (Root-Bindung, Pfad-Verify)
- C6. FRI-Verifikation (Einbindung, Fehler-Mapping)
- C7. Composition-Konsistenz (optional)
- C8. Report & Telemetry (Flag-Setzung, `total_bytes`)
- C9. Negative-Matrix & Snapshot-Hardening
- C10. CI/Doku-Abrundung (stable-only Gates, `PROOF_VERSION` Freeze)

> Jeder Commit ist unabhängig kompilierbar, mit eigenen Tests.

#### C1 — Proof-ABI festnageln

**Ziel:** Ein versionierter, binärstabiler Proof-Envelope mit kanonischem Layout; Ser/De über `ser/`; echte Größenmessung.

**Dateien**

- `src/proof/types` (Strukturvertrag: Proof, CompositionBinding, FriHandle,
  OpeningsDescriptor, Openings, MerkleProofBundle, TelemetryOption, Telemetry,
  VerifyError, VerifyReport, `PROOF_VERSION = 1`)
- `src/proof/ser` (Ser/De für Proof, Openings, Bundle, Telemetry; `serialized_len`)
- `src/proof/mod` (Reexports)

**Vertragsdetails (ohne Code)**

- Reihenfolge im Proof-Blob: Version (`u16`) → `ParamsHash` (32) → `PublicDigest` (32) → `TraceCommit` (Digest-Bytes) → Flag & `CompCommit`? → `FRI-Block` (Platzhalter; wird `ser/` eingebunden sobald vorhanden) → Openings → Flag & Telemetry?.
- Openings: Flags für trace/composition/aux; mindestens trace vorhanden.
- Bundle: Root (Digest-Bytes), Indices (`u32`-Liste), Leaves (jeweils: Längenpräfix `u32` + Rohbytes), Paths (dito).
- Optionale Felder: `u8`-Flag vor Daten; keinerlei Padding.
- Fehler: jegliche Ser/De-Abweichung → „Serialization“.

**Tests**

- Roundtrip-Test (serialize → deserialize → Equal).
- Snapshot der Proof-Bytes (Mini-Fixture; deterministische Füllwerte).
- Größenmessung: `serialized_len` entspricht tatsächlicher Bytezahl.

**Definition of Done**

- Proof-Bytes sind eingefroren (Snapshot).
- Keine externen Abhängigkeiten (FRI/Merkle) notwendig.

#### C2 — Header-Verifier (ohne FRI/Merkle)

**Ziel:** `verify()` prüft Version, `params_hash`, `public_digest`, Size-Gate (echte Serialisierung); noch kein Transcript.

**Vertragsdetails**

- Reihenfolge der Checks: Version → `ParamsHash` → `PublicDigest` → SizeGate (`<= max_kb × 1024`).
- Fehler: passende Varianten; kein Fallback auf generische Fehler.
- Report: `params_ok` und `public_ok` gemäß Checks; `total_bytes` befüllt; andere Flags (`merkle`/`fri`/`composition`) bleiben `false`.

**Tests**

- Positivfall.
- Vier Negativfälle: `VersionMismatch`, `ParamsHashMismatch`, `PublicDigestMismatch`, `ProofTooLarge` (Größe real aus Ser; keine Schätzung).

**Definition of Done**

- Verlässlicher Header-Guard; klare Fehlermeldungen.

#### C3 — Transcript-Rebuild & lokale Query-Indizes

**Ziel:** Transcript exakt in fixierter Reihenfolge rekonstruieren und aus ihm Query-Indizes lokal ableiten.

**Reihenfolge (fix)**

- Absorb: `ParamsHash` → `ProtocolTag` → `Seed` → `PublicInputsDigest` → `TraceRoot` → `CompRoot`? → `FRI-Roots` (in Proof-Reihenfolge).
- Challenges: ggf. Composition-α, dann FRI-Fold-Challenges je Layer.
- Query-Indizes: aus Challenge-Strom; danach aufsteigend sortieren und Duplikate deterministisch entfernen.

**Regeln**

- Die so erzeugte Liste gilt als einzige Quelle der Wahrheit.
- Niemals Indizes aus dem Proof übernehmen.

**Tests**

- Vergleich „lokale Query-Liste == openings.trace.indices“ (Positivfall).
- Negativ: wenn Indices im Opening absichtlich permutiert → Mismatch (wird in C4 feingranular aufgeschlüsselt).

**Definition of Done**

- Indizes reproduzierbar; deterministisch.

#### C4 — Openings-Disziplin (Indices-Regeln)

**Ziel:** Formale Disziplin für Indices in jedem Bundle; präzise Fehlersignale.

**Regeln**

- Indices müssen strikt aufsteigend sein (keine Gleichheit).
- Keine Duplikate.
- Identisch zur lokal generierten Liste (Trace-Bundle ist Referenz; Composition/Aux je nach Design ebenfalls abzugleichen).

**Fehler**

- „IndicesNotSorted“, „IndicesDuplicate { index }“, „IndicesMismatch“.

**Tests**

- Drei isolierte Negativfälle pro Regel; Positivfall.

**Definition of Done**

- Fehlerdiagnose landet immer im richtigen Bucket (nicht pauschal).

#### C5 — Merkle-Prüfung (Root-Bindung, Pfad-Verify)

**Ziel:** Bindung zwischen Commit-Root(s) im Header und den Openings; Pfadprüfung je Index.

**Regeln**

- Für jede vorhandene Sektion (trace / composition / aux):
  - `bundle.root ==` erwarteter Commit (`TraceCommit` oder `CompCommit`).
  - `indices`, `leaves`, `paths` müssen konsistente Längen besitzen.
  - Für jeden Index: Verify der Merkle-Pfadregel (Arity & Dom-Sep gemäß Params).

**Fehler**

- „RootMismatch { section }“, „MerkleVerifyFailed { section }“; bei Längeninkonsistenz: „Serialization“ oder eigener Längenfehler (einheitlich handhaben).

**Tests**

- Positivfall (kleiner Baum, 1–2 Indizes).
- Negativ:
  - falscher Root,
  - Pfadknoten-Manipulation,
  - längeninkonsistenter Vektor.

**Definition of Done**

- Root-Bindung und Pfade robust geprüft; klarer Fehlerpfad.

#### C6 — FRI-Verifikation (Einbindung)

**Ziel:** `fri_verify` korrekt einhängen; Fehler sauber mappen; Reihenfolge im Transcript beachten.

**Regeln**

- Vor FRI-Verify sind Merkle-Openings geprüft (frühe, klare Fehler).
- Transcript enthält bereits alle FRI-Roots in Proof-Reihenfolge; Fold-Challenges werden exakt nachgezogen.
- Fehler aus FRI werden 1:1 auf die definierte Fehler-Variante abgebildet.

**Tests**

- Positivfall (Mini-FRI).
- Negativ: Flip der ersten Fold-Challenge → erwarteter FRI-Fehler.

**Definition of Done**

- FRI-Layer korrekt gekoppelt; deterministische Ergebnisse.

#### C7 — Composition-Konsistenz (optional, wenn `CompCommit` existiert)

**Ziel:** Bytestrenge Bindung zwischen FRI-Kompositions-Opens und dem Composition-Bundle.

**Regeln**

- Leaves (Composition) haben identisches Layout wie Trace-Leaves (`Felt`-LE-Konkatenation, `leaf_width`).
- Für die Query-Indizes der Kompositions-Ebene müssen die Leaves bytegenau den gelieferten `composition.leaves` entsprechen.
- Abweichung → „CompositionInconsistent { reason }“.

**Tests**

- Positivfall; Negativ: ein Felt-Byte in `composition.leaves[0]` mutieren → klarer Fehler.

**Definition of Done**

- Kompositionsbindung ist geprüft; kein stilles Auseinanderlaufen.

#### C8 — Report & Telemetry

**Ziel:** Vollständiger, aussagekräftiger Verify-Report; Telemetry lesbar, aber nicht verifikationsrelevant.

**Regeln**

- `total_bytes` ist die tatsächliche Serialisierungslänge des gesamten Proofs (gemessen, nicht geschätzt).
- Flags:
  - `params_ok` und `public_ok` nach Header-Checks,
  - `merkle_ok` nach erfolgreicher Merkle-Prüfung,
  - `fri_ok` nach FRI-Erfolg,
  - `composition_ok` nur falls Composition vorhanden und konsistent.
- `error` enthält (optional) die erste aufgetretene [`VerifyError`]; der Report
  enthält keinen eingebetteten Proof mehr.
- Telemetry wird ignoriert für die Gültigkeit; optional in Report gespiegelt (z. B. Queries, Layers).

**Tests**

- Report-Plausibilität (Flags und Bytes); ein Positivfall, der alle Pfade passiert.

**Definition of Done**

- Report konsistent und nützlich für Node-Logging/Monitoring.

#### C9 — Negative-Matrix & Snapshot-Hardening

**Ziel:** Gezielte Fehlerfälle pro Regel, damit Regressions glasklar auffallen; ABI dauerhaft einfrieren.

**Negativfälle (je ein isolierter Test)**

- `VersionMismatch`
- `ParamsHashMismatch`
- `PublicDigestMismatch`
- `ProofTooLarge`
- `IndicesNotSorted`
- `IndicesDuplicate`
- `IndicesMismatch`
- `RootMismatch`
- `MerkleVerifyFailed`
- `FriVerifyFailed`
- `CompositionInconsistent`

**Snapshots**

- Mini-Proof (kleinste realistische Parameter):
  - Proof-Bytes (Hex/Bytes),
  - Trace/Comp/Fri-Roots separat,
  - lokal erzeugte Query-Indizes als Liste,
  - Pfadlängen je Bundle.

**Definition of Done**

- Jeder Fehler triggert genau den erwarteten Test; Snapshots bleiben stabil.

#### C10 — CI/Doku-Abrundung

**Ziel:** Stabile Produktion: CI schützt, Doku erklärt, `PROOF_VERSION` klar versioniert.

**CI**

- `build`/`test`/`clippy` auf stable 1.79.
- Snapshot-Artefakte uploaden.
- Optional: Job „ABI-Freeze“ der prüft, dass Proof-Snapshots unverändert sind (außer wenn `PROOF_VERSION` erhöht wurde).

**Doku**

- Proof-ABI-Seite (kurz, präzise):
  - Feldreihenfolge (Tabelle),
  - Endianness & Längen-Regeln,
  - Option-Flags,
  - Query-Indizes-Regel (lokal, sort, dedup),
  - Fehlertaxonomie (Tabelle),
  - Versionierungspolitik (jede Layout-Änderung ⇒ `PROOF_VERSION++`).
- FAQ: Warum Indizes lokal? Warum Size-Gate? Wie Telemetry zu verstehen ist?

**Definition of Done**

- CI grün; Doku vollständig; Team kann das Format ohne Rückfragen implementieren.

**Review-Checkliste pro PR (Auszug)**

- Byte-Layout exakt wie dokumentiert?
- Alle Ser/De über zentrales `ser/`?
- Query-Indizes lokal erzeugt, sortiert, dedupliziert?
- Size-Gate misst echte Serialisierung?
- Fehler präzise (richtige Variante)?
- Snapshot-Diffs erklärbar (und ggf. `PROOF_VERSION` erhöht)?
- `CHANGELOG.md` aktualisiert (Unreleased-Eintrag, PROOF_VERSION-/Snapshot-Hinweis)?
- Clippy clean, keine `unwrap`/`expect`, kein `unsafe`?

**Risiken & Gegenmaßnahmen**

- Drift beim Byte-Layout → Snapshots + `PROOF_VERSION`-Disziplin.
- Nichtdeterminismus → Transcript-Only-Randomness, Sort+Dedup, keine OS-RNGs.
- Übergröße/DoS → Size-Gate früh; Tests mit grenzwertigen Proofs.
- Interop-Fehler (STWO) → Digest-Länge 32 B fix; Domain-Separation dokumentiert; Public-Inputs-Digest klar definiert.

### Phase 5 – FRI

**Ziele:** Proof & Verify für kleines N; Folding formal fixiert.

**Aufgaben**

- Domain `N = 2^logN`; Folding mit βᵢ; Index-Mapping klar.
- Proof: version, `roots[]`, `fold_challenges[]`, `query_proofs[]`, optional OODS.
- Verifier: reproduziert Roots/Challenges via Transcript; nutzt lokale Query-Indizes.
- Tests: E2E klein; Negativ (Challenge flip, Pfad-Fehler), Snapshots.

**DoD:** Kleine FRI-Beweise laufen deterministisch.

### Phase 6 – AIR & Composition

**Ziele:** AIR-Traits + Beispiel-AIR + Composer.

**Aufgaben**

- Traits: `Air`, `TraceBuilder`, `PublicInputsCodec` (Encode + Digest), `Evaluator`/`Boundary`.
- Composer: α-Randomizer via Transcript; Degree-Limits; Evaluationsvektoren.
- Beispiel-AIR (LFSR/MiMC) für E2E.
- Tests: deterministischer Trace, Degree-Grenzen, E2E-Mini.

**DoD:** Beispiel-AIR generiert Prove/Verify-fähige Evaluations.

### Phase 7 – Proof-Envelope (ABI) & Header-Verifier

**Ziele:** binärstabiler Envelope + Header-Checks.

**Aufgaben**

- Proof-Layout exakt laut Blueprint (Version, Hashes, Commits, FRI, Openings, Telemetry).
- Ser/De via `ser/`.
- `verify()` (Teil A): Version, `params_hash`, `public_digest`, `size_gate` (echte Serialisierung).
- Tests: Roundtrip + Snapshot; 4 Negativfälle (Version/Params/Public/Size).

**DoD:** Proof-Bytes eingefroren (Snapshot), Header-Verifier grün.

### Phase 8 – Verifier-Orchestrierung komplett

**Ziele:** vollständige Verify-Pipeline.

**Aufgaben**

- Transcript-Rebuild (fixe Reihenfolge).
- Query-Indices lokal erzeugen, sortieren, deduplizieren; mit `openings.trace.indices` abgleichen (`NotSorted`/`Duplicate`/`Mismatch`).
- Merkle-Openings: Root-Match + Pfad-Verify.
- FRI-Verify einhängen, Fehler mappen.
- Composition-Konsistenz (falls `comp_commit`): Leaves bytegenau an gleichen Indizes.
- Report-Flags setzen; `total_bytes` füllen.
- Tests: Queries-Gleichheit, Merkle-Negativmatrix, FRI-Glue (flip), Composition-Mutation, Report.

**DoD:** Alle Verifier-Tests grün; Diagnose-Fehler präzise.

### Phase 9 – Parallelisierung (optional, stable)

**Ziele:** Rayon-Flag ohne Ergebnisabweichung.

**Aufgaben**

- Parallele Pfade (Commit/FRI) hinter `parallel`-Feature; deterministische Reduktionen.
- Tests: Bit-Gleichheit on/off für Mini-Proof.

**DoD:** Byte-identische Outputs mit/ohne Parallel.

### Phase 10 – Hardening, Docs, Release

**Ziele:** robuste Lib, klare Doku, Version 1.0.

**Aufgaben**

- Negative Property-Tests (gezielte Fail-Injection).
- README/Docs: Layout-Tabellen (Proof/Openings/Bundle), Label-Reihenfolge, Versionierungspolitik, Size-Gates, STWO-Adapterhinweise.
- Benchmarks (stable): Parse/Verify für kleine/mittlere Größen; Artefakte speichern.
- Version taggen; [`CHANGELOG.md`](CHANGELOG.md) mit Release-Abschnitt und PROOF-ABI-Hinweisen aktualisieren.

**DoD:** Doku vollständig, CI grün, Bench-Artefakte vorhanden, Tag v1.0.0.

#### CHANGELOG- & Proof-ABI-Pflege

- Jede Änderung am Serialisierungs-Layout des Proofs (Envelope, Openings, Transcript, Merkle-Bundles, Telemetry) erfordert einen `PROOF_VERSION`-Bump und einen dokumentierten Eintrag im [`CHANGELOG.md`](CHANGELOG.md).
- Snapshots werden nach ABI-Änderungen via `cargo test -p rpp-stark -- --nocapture` ausgeführt und anschließend mit `cargo insta review` geprüft; nur genehmigte Diffs landen im Repo.
- Vor dem Merge prüft das Review-Team, ob `CHANGELOG.md` gepflegt wurde (Unreleased-Eintrag, PROOF_VERSION-Notiz) und ob der Snapshot-Diff mit der dokumentierten Änderung übereinstimmt.

### PR-Plan (empfohlen, klein & linear)

1. Ser-Schema + Tests.
2. Params + Profiles + Snapshots.
3. Transcript + Determinismus-Tests.
4. Merkle + Tests/Snapshots.
5. FRI + Mini-E2E + Snapshots.
6. AIR + Beispiel-AIR + E2E.
7. Proof-Envelope + Header-Verifier + Snapshots.
8. Vollständiger Verifier (Queries/Merkle/FRI/Composition) + Tests.
9. Parallel-Flag + Gleichheits-Tests.
10. Docs/Benches/Release.

### Quality Gates (pro PR)

- `cargo test` (stable)
- `cargo clippy -D warnings`
- deterministische Snapshots (keine Umgebungsabhängigkeiten)
- Kein `unsafe`, keine `unwrap`/`expect` in Lib-Logik
- `CHANGELOG.md` gepflegt (Unreleased-Eintrag, PROOF_VERSION-/Snapshot-Hinweis)
- Review-Checklist: Endianness, Längenfelder, Fehlerpfade, deterministische Reihenfolge

### Risiken & Gegenmaßnahmen

- Drift beim Ser-Layout: Snapshots + `PROOF_VERSION++` bei Änderungen.
- Nichtdeterminismus: alle Zufallspfade über Transcript; keine OS-RNGs; Sort + Dedup für Indizes.
- Größen-Explosion: Size-Gate früh aktiv; Benchmarks zur Beobachtung.
- STWO-Interop: Digest 32B (Blake2s) + dokumentierte Domain-Separation; ggf. Adapter-Hasher.

### Spätere Chain-Integration (separat)

- Adapter-Layer (Felt/Digest/Hasher) hinter dem Feature-Gate
  `backend-rpp-stark`: die Wrapper `backend::Felt`, `backend::Digest` und
  `backend::Hasher` spiegeln die Feld- und Hash-Primitiven der Lib. Der Hasher
  stellt das Domain-Tag `rpp-stark:blake2s:commit` via
  `backend::Hasher::DOMAIN_TAG` bereit und bietet mit
  `backend::Hasher::new_with_domain_tag()` sowie
  `backend::ChainHasher::absorb_domain_tag(...)` deterministisches Seeding für
  32-Byte-Digests.
- Mapping-Helfer: `backend::node_limit_to_params_kb(...)`,
  `backend::params_limit_to_node_bytes(...)` und
  `backend::ensure_proof_size_consistency(...)` halten das Proof-Size-Gate und
  das Node-Limit synchron.
- Zwei CLI-Binaries (`prove`, `verify`) für manuelle Tests.

### Roadmap-Erweiterung – Kette komplett (Integration & Betriebsreife)

**Leitplanken:** MSRV 1.79, kein nightly, kein `unsafe`, keine `unwrap`/`expect` in
der Lib-Logik. Integration erfolgt additiv (keine Refactors im `chain`-Repo),
das Feature `backend-rpp-stark` ist standardmäßig deaktiviert.

**A1 – Adapter-Layer & Feature-Gate**

- Neue Adapter-Typen für Felt, 32-Byte-Digest-Wrapper sowie Hasher-Trait-
  Implementierungen bereitstellen.
- Feature `backend-rpp-stark` im `chain`-Workspace verdrahten (Dependency &
  Exports), ohne bestehende Dateien umzubenennen.
- **DoD:** Build mit und ohne Feature bleibt grün, der Default-Pfad bleibt
  unverändert.

**A2 – Public-Inputs-ABI & Digest-Kontrakt**

- Kanonische Reihenfolge und LE-Kodierung der Public Inputs festschreiben.
- Blake2s-256 als Default-Hashfamilie fixieren bzw. Adapter anlegen.
- Mini-Vektor mit `public_inputs.bin` und erwartetem Digest als Snapshot
  einfrieren.
- **DoD:** `public_digest` reproduzierbar, Snapshot stabil.

**A3 – Proof-Size-Gate-Mapping**

- `max_size_kb` in den Params verankern und der Verifier misst reale Proof-Bytes.
- Mapping auf `max_proof_size_bytes` der Node-Konfiguration dokumentieren.
- Testfall: Proof knapp unter/über Limit ⇒ OK/Fail.
- **DoD:** Limits greifen identisch in Library und Node.

**A4 – CLI-Brücken (optional, isoliert)**

- Zwei kleine Binaries außerhalb des Node-Main-Pfads:
  `wallet_stark_prove`, `node_stark_verify`.
- I/O via Dateien für Public Inputs und Proof, Ausgabe als JSON-Report.
- **DoD:** End-to-End-Probelauf ohne Node-Umbau möglich.

**A5 – CI-Erweiterungen (additiv)**

- Zusätzliche Jobs: `build-rpp-stark`, `test-rpp-stark`, `clippy-rpp-stark`.
- Artefakte sammeln: Snapshot-Files, Test-Logs.
- **DoD:** Pipeline grün, bestehende Jobs unverändert.

**A6 – Doku & Releasefluss**

- `docs/INTEGRATION.md`: Feature-Flag, Adapter, Limits, CLI-Kommandos,
  Troubleshooting.
- `CHANGELOG.md`: `PROOF_VERSION`-Regeln, ABI-Änderungen.
- Release-Tag-Schema (z. B. `rpp-stark-v1.0.0`).
- **DoD:** Doku vollständig, Tags & SemVer definiert.

**PR-Reihenfolge:** A1 → A2 → A3 → A4 → A5 → A6.

**Quality Gates:** Build/Test/Clippy (1.79), Snapshot-Stabilität, kein `unsafe`/
`unwrap`.

### Roadmap-Erweiterung – Fail-Matrix & Snapshot-Hardening

**Leitplanken:** Jeder Negativtest mutiert genau eine Ursache. Snapshots frieren
Bytes und Ordnungen (Proof, Params, Roots, Indizes, Challenges) ein. Tests
bleiben klein und deterministisch.

**B1 – Fixtures & Mutations-Infra**

- Mini-Params (z. B. `domain_log2=8`, `queries=2`, `leaf_width=1`).
- Datencontainer für Proof und Sektionen; Mutations-Helper (Byte flippen,
  Indizes permutieren usw.).
- **DoD:** Fixture-Erzeugung in 1–2 Zeilen pro Test.

**B2 – Header-Fehler (4 Fälle)**

- `VersionMismatch`: Versionsfeld +1.
- `ParamsHashMismatch`: 1 Byte im Hash flippen.
- `PublicDigestMismatch`: 1 Byte im Digest flippen.
- `ProofTooLarge`: Proof seriell über Limit aufblasen.
- **DoD:** Richtige Fehler-Variante, klare Asserts.

**B3 – Indices-Disziplin (3 Fälle)**

- `IndicesNotSorted`: Zwei Einträge vertauschen.
- `IndicesDuplicate`: Zwei gleiche Werte setzen.
- `IndicesMismatch`: Einen Wert außerhalb der lokalen Liste ändern.
- **DoD:** Eindeutige Fehlerdiagnosen.

**B4 – Merkle-Fehler (3 Fälle)**

- `RootMismatch`: Root-Bytes ändern.
- `MerkleVerifyFailed`: Pfadknoten korrumpieren.
- Vektor-Längeninkonsistenz: Leaves/Paths asynchron halten.
- **DoD:** Passender Fehlerpfad, keine Panics.

**B5 – FRI-Fehler (1 Fall)**

- `FoldChallenge[0]` mutieren ⇒ Verifier endet mit `FriVerifyFailed`.
- **DoD:** Exakter Fehler, keine Merkle-Verwechslung.

**B6 – Composition-Fehler (1 Fall)**

- In `composition.leaves[0]` ein Felt-Byte flippen ⇒ `CompositionInconsistent`.
- **DoD:** Exakte Fehlermeldung.

**B7 – Snapshot-Freeze**

- Snapshots: Proof-Bytes, Params-Bytes (Profile), Roots-Listen,
  Challenges-Listen, Query-Indizes, Pfadlängen.
- CI-Guard: Snapshot-Diffs nur erlaubt, wenn `PROOF_VERSION` erhöht wird.
- **DoD:** Snapshot-Stabilität als Gate.

**PR-Reihenfolge:** B1 → (B2, B3, B4, B5, B6) → B7.

**Quality Gates:** Determinismus, präzise Fehlervarianten, Snapshot-Artefakte.

### Roadmap-Erweiterung – STWO-Interop-Haken

**Leitplanken:** Ziel sind identische Root- und Digest-Bytes wie im STWO-Pfad
(oder dokumentierte Adapter). Keine Seiteneffekte für bestehende Backends.

**C1 – Hashfamilie & Digest-Länge**

- Hash-Trait mit Familie/Variante, `digest_len=32` (Blake2s-Default).
- Adapter-Hasher für alternative interne Backends (Poseidon/Rescue).
- Test: Gleicher Input ⇒ gleiche Root-Bytes wie STWO-Referenz.
- **DoD:** Byte-genaue Kompatibilität.

**C2 – Merkle-Parameter & Domain-Separation**

- Arity-2 als Default, Arity-4 nur bei belegter Kompatibilität.
- Domain-Tags (Leaf/Node) dokumentieren und anwenden.
- Test: Bekannte Leaf-Menge ⇒ Root exakt wie Referenz.
- **DoD:** Root-Gleichheit, Pfad-Verify deckungsgleich.

**C3 – Public-Inputs-Digest**

- Fixe Reihenfolge/Kodierung (LE) der Public-Felder; keine dynamischen Sorts.
- Hashfamilie identisch zur Merkle- oder dokumentiert.
- Test: `public_inputs.bin` ⇒ Digest-Fixture reproduzieren.
- **DoD:** Deterministischer Digest, Snapshot vorhanden.

**C4 – Params-Mapping & Profile-Gleichklang**

- `PROFILE_X8`, `PROFILE_HISEC_X16` spiegeln Node-Erwartungen (domain_log2,
  queries, leaf_width).
- `params_hash()`-Snapshot, Node-Seite nachrechenbar.
- **DoD:** `params_hash` stabil, Profile deckungsgleich.

**C5 – Size-Gate-Kontrakt**

- Library misst reale Bytes und vergleicht mit `max_size_kb`.
- Node-Konfig `max_proof_size_bytes` dokumentiert mappen.
- Test: Proof knapp unter/über Grenze ⇒ erwartetes Verhalten.
- **DoD:** Identische Entscheidungen in Lib und Node.

**C6 – Interop-Protokolltests**

- Golden-Vector-Set mit kleinem Proof (Roots, Indizes, Challenges, Bytes).
- Verifier-Report-Vergleich: Flags und `total_bytes` identisch.
- **DoD:** Vollständiger Roundtrip kompatibel.

**PR-Reihenfolge:** C1 → C2 → C3 → C4 → C5 → C6.

**Quality Gates:** Byte-Identität bei Hash/Merkle/PublicDigest;
Profile/Snapshots stabil.

## Canonical STARK parameters

The [`params`](src/params/mod.rs) module defines `StarkParams` as the single
source of truth for every security and performance relevant configuration item.
The structure is serialised into a deterministic byte layout which is used to
derive a stable `params_hash`.  The table below summarises the built-in
profiles:

| Profile | Field | Hash | Blowup | FRI queries | Merkle arity | Target bits |
|---------|-------|------|--------|-------------|--------------|-------------|
| `PROFILE_X8` | Goldilocks | Poseidon2 (set 0) | 8 | 30 | Binary | 96 |
| `PROFILE_HISEC_X16` | BN254 | Rescue (set 1) | 16 | 48 | Quaternary | 128 |

In addition to the builder presets, the proof system exposes deterministic
`ProfileConfig` descriptors.  The default rollup pipeline now ships with both a
binary and a quaternary Merkle configuration: `PROFILE_STANDARD_CONFIG`
(`COMMON_IDENTIFIERS`) and `PROFILE_STANDARD_ARITY4_CONFIG`
(`COMMON_IDENTIFIERS_ARITY4`).  Switching between them adjusts the Merkle
branching factor without affecting the transcript, hashing backend or AIR
parameters.

### Canonical byte layout

The binary format is free of padding and all integers are little-endian:

| Field | Bytes |
|-------|-------|
| `params_version` | 2 |
| `field` | 2 |
| `hash.family` | 1 |
| `hash.parameter_id` | 2 |
| `lde` (`blowup`, `order`, `coset_tag`) | 13 |
| `fri` (`r`, `queries`, `domain_log2`, `folding`, `num_layers`) | 7 |
| `merkle` (`leaf_encoding`, `leaf_width`, `arity`, `domain_sep`) | 11 |
| `transcript` (`protocol_tag`, `seed`, `challenge_bounds`) | 42 |
| `proof` (`version`, `max_size_kb`) | 6 |
| `security` (`target_bits`, `soundness_slack_bits`) | 3 |

Equal byte sequences imply identical parameter sets and therefore the same
`params_hash`.

## Transcript subsystem

The [`transcript`](src/transcript/mod.rs) module documents a deterministic
Fiat–Shamir transcript shared by prover and verifier.  The transcript operates
over labelled phases; each label is an enum variant to guarantee domain
separation at compile time.

| Phase | Label | Purpose |
|-------|-------|---------|
| Init | `ParamsHash`, `ProtocolTag`, `Seed`, `ContextTag` | Bind the transcript to the negotiated [`StarkParams`](src/params/stark_params.rs). |
| Public | `PublicInputsDigest` | Absorb canonical public inputs. |
| TraceCommit | `TraceRoot`, `TraceChallengeA` | Bind the execution trace commitment and emit the first challenge. |
| CompCommit | `CompRoot`, `CompChallengeA` | Bind composition commitments and emit the folding seed. |
| FRI | `FriRoot(i)`, `FriFoldChallenge(i)` | Iterate through each FRI layer. |
| Queries | `QueryCount`, `QueryIndexStream` | Fix the number of queries and derive deterministic indices. |
| Final | `ProofClose` | Produce the final 32-byte proof binding digest. |

Determinism is guaranteed by deriving every sponge update from the parameter
hash, transcript seed, protocol tag and context label.  Replaying the exact same
label/data sequence reproduces the state digest and challenge stream bit for
bit.  The query index stream uses a modulo reduction; the residual bias is
negligible for domain sizes above 2<sup>16</sup> and is documented in the
rustdoc comments.

## AIR benchmarking

Criterion benches covering the AIR layer live under [`benches`](benches).  The
`air_benches` target measures transition evaluation and constraint composition
throughput for the worked LFSR example across multiple trace lengths.  All
inputs are derived from a fixed seed and deterministic parameter set, ensuring
that repeated runs produce identical transcripts and commitments.

Run the suite with:

```
cargo bench --bench air_benches
```

The command completes without accessing randomness or the network, making the
results stable across invocations and hosts.
