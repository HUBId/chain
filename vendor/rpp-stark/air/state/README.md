# State AIR Specification Skeleton

## 0. Ziel & Scope
- **Ziel**: Beweise, dass die Diff-Operationen die Multiset-Konsistenz zwischen Pre-State und Post-State erhalten.
- **Scope**: Bindet die im Proof-Header angegebenen Public Inputs sowie externe Commitments über das Transcript (`CommitmentDigest`). Keine Simulation von BLAKE3 innerhalb der AIR; stattdessen werden arithmetische Spiegel-Digests verwendet.

## 1. Public Inputs & Transcript Binding
- **PreStateRoot (32 Bytes)**
- **PostStateRoot (32 Bytes)**
- **DiffDigest (32 Bytes)**
- Reihenfolge und Little-Endian-Kodierung sind fix. Diese Werte erscheinen in Phase 5 des Proof-Envelopes und werden über Boundary-Anker an die Trace gebunden.
- `DiffDigest_arith` spiegelt die externen Diff-Operationen, sodass genau die in der Trace verwendeten Operationen (Insert/Update/Delete) gebunden sind.

## 2. Trace Layout (Column-Major, Dense)
### 2.1 Registerklassen
**Core (≤48 Spalten empfohlen)**
- `A_pre`: Arithmetischer Akkumulator für Pre-State (feldkodierte Key/Value-Paare).
- `A_post`: Arithmetischer Akkumulator für Post-State.
- `A_diff`: Arithmetischer Akkumulator für Diff-Operationen.
- `K`, `V_old`, `V_new`: Feldkodierte Schlüssel bzw. Werte der aktuellen Operation.
- `Op_tag`: Kodiert den Operationstyp (`INS`, `UPD`, `DEL`); Lookup-gesichert.
- `H_acc` (optional): Poseidon-basierter Hash-Akkumulator für feldinterne Bindungen von KV-Listen.

**Aux (≤32 Spalten empfohlen)**
- Zerlegungen/Range-Limbs für `K`, `V_old`, `V_new`.
- Binäre Flags/Masken pro Operation (`f_ins`, `f_upd`, `f_del`).
- Grand-Product-/Permutation-Hilfsregister (`Z`).
- Konsistenzregister zur Key-Ordnung (optional für Ordnungsprüfungen).

**Selector (≤8 Spalten empfohlen)**
- `σ_first`, `σ_last`.
- `σ_scan`: Markiert Zeilen mit Diff-Operationen.
- `σ_finalize`: Markiert das Endfenster (Bindung an Public Inputs, Ruhe der Akkus).
- `σ_hash_absorb` (optional): Steuert Poseidon-Absorption.

### 2.2 Zeilensemantik & Phasen
- Dichte Spur mit Schrittweite 1.
- **Scan-Phase** (`σ_scan = 1`): Jede Zeile repräsentiert genau eine Diff-Operation (`INS`, `UPD`, `DEL`).
- **Finalize-Phase** (`σ_finalize = 1`): Keine weiteren Operationen; Akkus werden stabilisiert und an Public Inputs gebunden.
- Randmarker: `σ_first(i) = 1 ⇔ i = 0`, `σ_last(i) = 1 ⇔ i = T − 1`.
- Disjunktheit: `σ_scan + σ_finalize = 1` in jeder Zeile, `σ_first · σ_last = 0`.

## 3. Boundary Constraints
- **Startanker** (`σ_first = 1`):
  - `A_pre = PreStateDigest_arith_init`
  - `A_post = PostStateDigest_arith_init`
  - `A_diff = DiffDigest_arith_init`
  - Optional: `H_acc = H_init`
- **Endanker** (`σ_last = 1`):
  - `A_pre = PreStateDigest_arith_final`
  - `A_post = PostStateDigest_arith_final`
  - `A_diff = DiffDigest_arith_final`
  - Optional: `H_acc = H_pi`
- `*_init` und `*_final` sind identische arithmetische Spiegel der Public Inputs; sie erzwingen stabile Akkumulatorwerte während der Finalize-Phase.

## 4. Transition Constraints
### 4.1 Akkumulator-Regeln (Scan)
Für `σ_scan = 1`:
- `A_pre(next) = A_pre(cur) + φ_pre(K, V_old, Op_tag)`
- `A_post(next) = A_post(cur) + φ_post(K, V_new, Op_tag)`
- `A_diff(next) = A_diff(cur) + φ_diff(K, V_old, V_new, Op_tag)`
- Die Funktionen `φ_*` sind deterministische lineare/affine Abbildungen, die in der begleitenden Dokumentation festgelegt werden.

### 4.2 Akkumulator-Stabilisierung (Finalize)
Für `σ_finalize = 1`:
- `A_pre(next) = A_pre(cur)`
- `A_post(next) = A_post(cur)`
- `A_diff(next) = A_diff(cur)`
- Optional: `H_acc(next) = H_acc(cur)`

### 4.3 Operationstyp-Kohärenz
- `Op_tag` muss einem der gültigen Tags entsprechen (Lookup auf `{TAG_INS, TAG_UPD, TAG_DEL}`).
- Flags erfüllen `f_ins + f_upd + f_del = 1` und werden via Lookup/Permutation an `Op_tag` gebunden.

### 4.4 Wert-Kohärenz pro Operation
- **Insert** (`f_ins = 1`): `V_old = 0`, `V_new ≠ 0`.
- **Delete** (`f_del = 1`): `V_new = 0`, `V_old ≠ 0`.
- **Update** (`f_upd = 1`): `V_old ≠ V_new`; beide Werte bestehen Range-/Formatprüfungen.
- Null- und Ungleichheitsprüfungen werden über Range-/Lookup-Argumente und lineare Nebenbedingungen realisiert.

### 4.5 Selektoren
- `σ_scan + σ_finalize = 1`
- `σ_scan · σ_finalize = 0`
- `σ_first · (1 − σ_scan) = 0`
- `σ_last · σ_finalize = σ_last`

### 4.6 Hash-Akkumulator (optional)
- `σ_hash_absorb · (H_acc(next) − Poseidon_absorb(H_acc(cur), pack(K, V_old, V_new, Op_tag))) = 0`
- `(1 − σ_hash_absorb) · (H_acc(next) − H_acc(cur)) = 0`
- Poseidon-Parameter: `t = 12`, `rate = 8`, `capacity = 4`, `α = 5`, `r_f = 8`, `r_p = 56`.

## 5. Lookups & Formatregeln
- **Op-Tag Lookup**: `Op_tag ∈ {TAG_INS, TAG_UPD, TAG_DEL}`.
- **Key-Format**: Feld-Limbs (z. B. Basis `2^16`) mit Präfix-/Typ-Tags und optionaler Partition-ID; validiert durch Lookup-Tabellen.
- **Value-Format**: Typ-Tags und Range-Bedingungen; ebenfalls via Lookup.
- **Nullrepräsentation**: `0` steht für „kein Wert“ und ist durch Lookup abgesichert.
- **Update-Kohärenz**: Für Updates wird `(K, V_old) ≠ (K, V_new)` durch `V_old ≠ V_new` und Range-Prüfungen garantiert.

## 6. Multiset-/Permutation-Argument
### 6.1 Zielstellung
- Modelliert die Relation `pre ⊎ diff.ops = post` über KV-Paare.
- `INS`: Beitrag nur rechts (`post`).
- `DEL`: Beitrag nur links (`pre`).
- `UPD`: Entfernt `(K, V_old)` links, fügt `(K, V_new)` rechts hinzu.

### 6.2 Transcript-Challenges
- Ziehe `β`, `γ`, `δ` aus dem Transcript (`CommitmentDigest`).
- Mapping: `ψ(K, V) = β + K + γ · V + δ · tag`, optional mit Domain-Separationstag für verschiedene Tabellen.

### 6.3 Grand-Product
- Grand-Product-Spalte `Z` (Aux):
  - Initialisierung: `σ_first · (Z − 1) = 0`.
  - Scan-Schritt: `Z(next) = Z(cur) · f(i)` mit Faktor `f(i)`:
    - `INS`: multipliziere `ψ(K, V_new)`.
    - `DEL`: multipliziere `ψ(K, V_old)^{-1}`.
    - `UPD`: multipliziere `ψ(K, V_new)` und `ψ(K, V_old)^{-1}`.
  - Finalize: `σ_finalize · (Z(next) − Z(cur)) = 0`.
  - Abschluss: `σ_last · (Z − 1) = 0`, sofern linke Faktoren als Inversen einfließen.
- Alternativ kann `Π_pre` als konstante arithmetische Spiegelung gebunden werden; Auswahl wird in der Implementierung dokumentiert.

## 7. DEEP-Komposition & Out-of-Domain Openings
- Kanonische Constraint-Reihenfolge: Boundary → Selektor-Gesetze → Akkumulator-Updates (`A_pre`, `A_post`, `A_diff`) → Operationskohärenz → Lookup/Format → Grand-Product → optional Hash-Akkumulator.
- Unabhängige α-Gruppen für Boundary- und Transition-Constraints.
- Mindestens zwei OOD-Punkte `{ζ₁, ζ₂}` aus dem Transcript.
- Öffnungen an den OOD-Punkten: `A_pre`, `A_post`, `A_diff`, `Z`, optional `H_acc`, sowie der zusammengesetzte Constraint-Wert `C(ζ)`.
- Reihenfolge der Spalten und Serialisierung: column-major, Little-Endian, konsistent mit ParamDigest/Proof-Envelope (Phasen 2–5).

## 8. Degree Bounds
- Selektor-, Boundary- und Akkumulatorgleichungen: Grad ≤ 2.
- Op-Tag-/Format-Lookups: Grad ≤ 3 (lookup-spezifisch).
- Grand-Product-Schritt: Grad ≤ 2.
- Poseidon-S-Box (optional): Grad 5, selektiv aktiviert.
- Gesamtbudget: kompatibel mit Profil `STD` (LDE × 8, 64 Queries) und `HiSec` (LDE × 16, 96 Queries).

## 9. Commitments & Openings
- **Commitments (Phasen 4/5)**:
  - Core-Gruppe: LDE-Evaluierungen von `A_pre`, `A_post`, `A_diff`, `K`, `V_old`, `V_new`, `Op_tag`, optional `H_acc`.
  - Aux-Gruppe: Zerlegungen, Flags, Lookup-Hilfen, Grand-Product `Z`, optionale Ordnungshilfen.
- **Openings**: Pro Query-Position vollständiger Zeilenvektor je Commitment-Gruppe (Core getrennt von Aux). Reihenfolge/Indexierung fix, Little-Endian serialisiert.

## 10. Fehlerklassen
- `ErrStateBoundary`
- `ErrStateOpTag`
- `ErrStateFormat`
- `ErrStateUpdateTrivial`
- `ErrStatePermutation`
- `ErrStateSelector`
- `ErrStateDegreeBound`

## 11. Profil-Obergrenzen & Ressourcen
- Breite (Core + Aux + Selector): ≤ 72 Spalten.
- Schritte: ≤ 2²² für state-heavy Szenarien (abhängig von Diff-Größe).
- Profil `HiSec`: gleiche/mehr Schritte, 96 Queries, LDE × 16.
- Throughput-Variante: gleiche Breite, reduzierte Queries (48/56) nach Größenbudget.

## 12. Tests (ohne Code)
- **Determinismus**: Gleiches `PreStateRoot` und `DiffDigest` → identische `proof_bytes`.
- **Operationseinzelfälle**:
  - Nur `INS`: `post = pre ∪ {KV}`.
  - Nur `DEL`: `post = pre \ {KV}`.
  - `UPD`: `post = pre \ {K, V_old} ∪ {K, V_new}`.
  - Vertauschte Reihenfolge der Operationen → akzeptiert (Multiset-Invarianz).
- **Permutation-Fail**: Ersetze ein KV-Paar durch ein anderes → `ErrStatePermutation`.
- **Format-Fail**: Ungültiger Key-/Value-Tag → `ErrStateFormat`.
- **Op-Tag-Fail**: Unbekannter Tag → `ErrStateOpTag`.
- **Update trivial**: `V_old = V_new` → `ErrStateUpdateTrivial`.
- **Boundary-Fail**: Veränderung eines Public Inputs → `ErrStateBoundary`.
- **Degree-Budget**: Wechsel `STD → HiSec` erzeugt neuen `ParamDigest`; alte Proofs werden abgelehnt.

## 13. Sicherheitsrationale
- Transcript-gebundene Challenges (`β`, `γ`, `δ`) verhindern Replay/Kollisionsangriffe und sichern Domain-Separation.
- Lookup-basiertes Format-Checking stellt die strukturelle Gültigkeit von Keys/Values und Tags sicher.
- Boundary-Anker binden den Blockkontext über das Transcript.
- FRI/LDE-Parameter liefern ≥100–120 Bit Sicherheit (profilabhängig).
- Optionaler Poseidon-Akkumulator ermöglicht feldinterne Spiegelung externer Strukturen ohne Byte-Hashing in der AIR.
