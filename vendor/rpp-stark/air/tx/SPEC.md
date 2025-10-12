# Transaction AIR Specification Skeleton

## 0. Ziel & Scope
- Nachweis, dass jede Transaktion bilanzneutral ist und alle strukturellen Formatregeln (Ranges, Nonce, Fees) erfüllt.
- Bindung der Public Inputs (PI) und der externen Commitments über Transcript-Phasen (Phase 3/5) sicherstellen.
- Keine arithmetische Simulation von BLAKE3-Pfaden innerhalb der AIR; Merkle-Wurzeln und externe Commitments werden ausschließlich über Transcript- und Boundary-Bindungen verankert.

## 1. Public Inputs (kanonisch, Little-Endian)
Die folgenden Felder werden in genau dieser Reihenfolge in den Public Inputs geführt und sind im Proof-Envelope-Header (Phase 5) eingebettet. Sie werden in Phase 3 über das Transcript gebunden und in der AIR via Boundary-Polynome referenziert.

| Feld | Größe | Beschreibung |
| --- | --- | --- |
| `TxID` | 32 B | Eindeutiger Transaktions-Identifier. |
| `InputCommitRoot` | 32 B | Merkle-Wurzel der Input-Commitments. |
| `OutputCommitRoot` | 32 B | Merkle-Wurzel der Output-Commitments. |
| `Fee` | `u64` | Gesamtgebühr, zusätzlich in Boundary-Bedingungen verankert. |
| `Nonce` | `u64` | Anti-Replay-Wert, ebenfalls via Boundary gebunden. |

## 2. Trace-Layout (Column-Major, dicht)
### 2.1 Registerklassen
**Core-Register (≤ 32 Spalten empfohlen)**
- `S_in`: Akkumuliert Input-Beträge.
- `S_out`: Akkumuliert Output-Beträge.
- `S_fee`: Akkumulator für die Gebühr (endet auf `Fee`).
- `S_nonce`: Akkumulator für den Nonce (endet auf `Nonce`).
- `H_acc`: Poseidon-basierter Hash-Akkumulator (optional) zur Bindung strukturierter Feldlisten.
- `L_in[i]`, `L_out[j]`: Optionale Rolling-Summenregister für „streamende“ IO-Verarbeitung.

**Auxiliary-Register (≤ 24 Spalten empfohlen)**
- Zerlegungsregister für Betrag-Limbs in Basis `B = 2^16`.
- Carry-Hilfsregister `C_*` für Limb-Addition.
- Lookup-Hilfsregister für das Permutation-/Lookup-Argument (siehe Abschnitt 6).
- `Z`: Grand-Product-Spalte für das Multiset-Argument.

**Selector-Register (≤ 8 Spalten empfohlen)**
- `σ_first`, `σ_last`: Randmarker (erste/letzte Zeile).
- `σ_io_in`, `σ_io_out`: Phasenindikatoren für Input- bzw. Output-Verarbeitung.
- `σ_finalize`: Indikator für Finalize-Phase.
- `σ_hash_absorb`: Optionaler Selektor für Poseidon-Absorb-Schritte.
- `σ_fee_once`: Optional zur Sicherung der einmaligen Inversion des Fee-Faktors im Grand-Product.

### 2.2 Zeilensemantik & Phasen
- Die Spur ist dicht, Schrittweite 1.
- Phasensteuerung erfolgt über Selektoren:
  - **Input-Phase:** `σ_io_in = 1`, `σ_io_out = σ_finalize = 0`.
  - **Output-Phase:** `σ_io_out = 1`, `σ_io_in = σ_finalize = 0`.
  - **Finalize-Phase:** `σ_finalize = 1`, `σ_io_in = σ_io_out = 0`.
- Randmarker: `σ_first` nur in Zeile `0 = 1`; `σ_last` nur in Zeile `T-1 = 1`.
- Selektoren sind deterministische Funktionen des Zeilenindex und der konfigurierten Fensterlängen `N_in`, `N_out`.

## 3. Parameter & konstante Größen
- Zerlegungsbasis: `B = 2^16`.
- Maximalbetrag: `M = 2^64 − 1` (`u64`).
- IO-Fenstergrößen: `N_in`, `N_out` (batch- und profilabhängig, deterministisch).
- Feld: Goldilocks-Prime (Phase 2-Konfiguration).
- Poseidon-Parameter: `t = 12`, `rate = 8`, `capacity = 4`, `α = 5`, `r_f = 8`, `r_p = 56` (Phase 3).
- FRI- und Query-Parameter: Profilabhängig (Phasen 2/3/5).

## 4. Selektor-Definitionen (semantisch)
Für jeden Zeilenindex `i` bei Gesamtlänge `T`:
- `σ_first(i) = 1 ⇔ i = 0`, sonst `0`.
- `σ_last(i) = 1 ⇔ i = T − 1`, sonst `0`.
- `σ_io_in(i) = 1` für `i ∈ [0, N_in − 1]`, sonst `0`.
- `σ_io_out(i) = 1` für `i ∈ [N_in, N_in + N_out − 1]`, sonst `0`.
- `σ_finalize(i) = 1` für `i ∈ [N_in + N_out, T − 1]`, sonst `0`.
- Disjunktheit: `σ_io_in + σ_io_out + σ_finalize = 1` für alle `i`.
- Randbindung: `σ_first ≤ 1`, `σ_last ≤ 1`, `σ_first · σ_last = 0`.
- Selektor-Constraints erzwingen diese Beziehungen polynomiell (siehe §5.2).

## 5. Constraints
### 5.1 Boundary-Constraints (harte Anker)
Bindung der PIs über Anfangs- und Endzeilen:
- Startwerte (`σ_first`):
  - `σ_first · S_in = 0`
  - `σ_first · S_out = 0`
  - `σ_first · S_fee = 0`
  - `σ_first · S_nonce = 0` (oder policy-spezifischer Startwert)
  - Optional: `σ_first · H_acc = H_init` (Konstante)
- Endwerte (`σ_last`):
  - `σ_last · (S_in − S_out − Fee) = 0`
  - `σ_last · (S_fee − Fee) = 0`
  - `σ_last · (S_nonce − Nonce) = 0`
  - Optional: `σ_last · (H_acc − H_pi) = 0`, wobei `H_pi` das feldarithmetische Spiegelbild eines PI-Digests ist.

### 5.2 Transition-Constraints (Phasenlogik)
**Additive Akkumulatoren:** Für jede Zeile mit Zuständen `cur` und `next`:
- Inputs: `σ_io_in · (S_in(next) − S_in(cur) − a_in(i)) = 0`
- Outputs: `σ_io_out · (S_out(next) − S_out(cur) − a_out(i)) = 0`
- Finalize: `σ_finalize · (S_in(next) − S_in(cur)) = 0`, `σ_finalize · (S_out(next) − S_out(cur)) = 0`

**Gebühren & Nonce:**
- Gebühr (setzen in Finalize): `σ_finalize · (S_fee(next) − Fee) + (1 − σ_finalize) · (S_fee(next) − S_fee(cur)) = 0`
- Nonce-Optionen:
  - Setzen: analog zur Gebühr.
  - Inkrementieren: `σ_finalize · (S_nonce(next) − (S_nonce(cur) + 1)) + (1 − σ_finalize) · (S_nonce(next) − S_nonce(cur)) = 0`

**Hash-Akkumulator (optional):**
- `σ_hash_absorb · (H_acc(next) − Poseidon_absorb(H_acc(cur), chunk(i))) = 0`
- `(1 − σ_hash_absorb) · (H_acc(next) − H_acc(cur)) = 0`

**Selektor-Gesetze:**
- `σ_io_in · σ_io_out = 0`, `σ_io_in · σ_finalize = 0`, `σ_io_out · σ_finalize = 0`
- `σ_io_in + σ_io_out + σ_finalize − 1 = 0`
- `σ_first · (1 − σ_io_in) = 0`
- `σ_last · σ_finalize = σ_last`
- Optional: `σ_fee_once` wird genau einmal in der Finalize-Phase aktiviert (siehe §6.3).

### 5.3 Struktur- und Formatregeln via Lookups
- Range-Check Beträge: Zerlege `a ∈ [0, M]` in Limbs `a = Σ_{k=0}^{3} limb_k · B^{k}` mit `limb_k ∈ [0, B^2 − 1]`. Lookups gegen Tabelle `T_16bit` oder `T_32bit`.
- Nichtnegativität ergibt sich aus der Range-Zerlegung.
- Gebührenregel: `Fee ∈ [0, M]` (Range-Lookup).
- Nonce-Regel: `Nonce ∈ [0, M]` (Range-Lookup).

## 6. Bilanzgleichheit via Permutations-/Grand-Product-Argument
### 6.1 Ziel
Nachweis der Multiset-Gleichheit `{ a_in(0), …, a_in(N_in−1) } = { a_out(0), …, a_out(N_out−1) } ∪ { Fee }`.

### 6.2 Transcript-Challenges & Domain-Tags
- Ziehe Challenges `β`, `γ` aus dem Transcript (Phase 3) und mappe sie LE→Feld.
- Definiere Domain-Tags `tag_in`, `tag_out`, `tag_fee` als feste, disjunkte Feldkonstanten zur Domänentrennung.
- Produkte:
  - `P_L = ∏_{i=0}^{N_in−1} (β + a_in(i) + γ · tag_in)`
  - `P_R = (∏_{j=0}^{N_out−1} (β + a_out(j) + γ · tag_out)) · (β + Fee + γ · tag_fee)`

### 6.3 Grand-Product-Constraint
- `Z` initial: `σ_first · (Z − 1) = 0`
- Fortschritt pro Zeile (`f(i)` abhängig von Phase):
  - Input-Phase: Faktor `f_in(i) = β + a_in(i) + γ · tag_in`
  - Output-Phase: inverse Faktoren `f_out(j)^{-1}`
  - Finalize-Phase: genau einmal `f_fee^{-1}` (über `σ_fee_once` oder Randbindung gesichert)
- Übergang: `Z(next) − Z(cur) · f(i) = 0`
- Abschluss: `σ_last · (Z − 1) = 0`
- Gewährleistet `P_L = P_R` bei korrekter Platzierung des Fee-Faktors.

## 7. DEEP-Komposition & Out-of-Domain (OOD) Openings
### 7.1 Kompositionspolynom
- Constraints in kanonischer Reihenfolge: Boundary → Selektor-Gesetze → Additive Akkus → Fee/NONCE → Hash-Akkus → Range-Lookups → Grand-Product.
- Ziehe unabhängige `α`-Vektoren aus dem Transcript (Phase 3) mit separaten Gruppen für Boundary vs. Transition.
- Kompositionspolynom: `C(X) = Σ α_k · c_k(X)` mit Grad-Bound unterhalb des LDE-Bounds (profilabhängig, Phase 2/3).

### 7.2 OOD-Punkte & Öffnungen
- Mindestens zwei deterministische OOD-Punkte `{ζ_1, ζ_2}` aus dem Transcript (Phase 3).
- An jedem `ζ` öffnen:
  - `S_in`, `S_out`, `S_fee`, `S_nonce`, `H_acc` (falls geführt), `Z`
  - Kompositionswert `C(ζ)`
- Serialisierung & Reihenfolge der Openings folgen den globalen Regeln in Phase 4/5.

## 8. Commitments & Openings
- **Commitments (Phasen 4/5):**
  - Core-Gruppe: Merkle-Commitment auf LDE-Evaluierungen von `S_in`, `S_out`, `S_fee`, `S_nonce`, `H_acc`, ggf. weiteren Core-Registern.
  - Aux-Gruppe: Enthält `Z`, Zerlegungs- und Carry-Register, Lookup-Hilfen.
- **Openings:** Pro Query-Position vollständiger Zeilenvektor jeder Commitment-Gruppe (Core getrennt von Aux).
- Reihenfolgen und Indexierung folgen der festen Spaltenordnung.

## 9. Degree-Bounds
- Selektor-Gesetze, additive Akkus, Boundary: Grad ≤ 2.
- Range-Lookups: abhängig vom Lookup-Schema (typisch Grad ≤ 3).
- Grand-Product-Schritt: Grad ≤ 2.
- Poseidon-S-Box (Grad 5) wird durch Selektor-Sparsamkeit innerhalb des Bounds gehalten.
- LDE- und FRI-Parameter (Phase 2/3) werden so gewählt, dass alle Constraints unterhalb des zulässigen Bounds bleiben.

## 10. Fehlerklassen
- `ErrTxBalance` — `S_in − S_out − Fee ≠ 0` in der Schlusszeile.
- `ErrTxRange` — Betrags-/Nonce-/Fee-Range ungültig (Lookup-Fehler).
- `ErrTxPermMismatch` — Grand-Product-/Permutation-Argument inkonsistent.
- `ErrTxSelector` — Selektor-Gesetze verletzt oder Phasen überlappen.
- `ErrTxHashBind` — Hash-Akkumulator stimmt nicht mit PI-Digest überein.
- `ErrTxDegreeBound` — Effektiver Grad überschreitet konfigurierten Bound.
- `ErrTxBoundary` — Start-/Endbindungen widersprechen den Public Inputs.

## 11. Profil-Obergrenzen & Ressourcen
- Spurbreite (Core + Aux + Selector): ≤ 56 Spalten (STD-Profil).
- Schrittanzahl: ≤ 2^20 für typische Transaktions-Batches.
- HiSec-Profil: gleiche Breite, ggf. mehr Schritte; FRI-Queries auf 96, LDE-Faktor ×16.
- Throughput-Profil: reduzierte Queries (48/56), Einhaltung des Size-Budgets prüfen.

## 12. Tests (Konzeptuell, ohne Code)
- **Determinismus:** Gleiche Tx-Liste ⇒ bitidentische `proof_bytes`.
- **Bilanzfall A:** `Σ Input = Σ Output + Fee` ⇒ Accept.
- **Bilanzfall B:** Abweichung ±1 ⇒ `ErrTxBalance`.
- **Permutation:** Vertauschte Outputs ⇒ Accept; Ersatzwert ⇒ `ErrTxPermMismatch`.
- **Range:** Betrag `= 2^64` ⇒ `ErrTxRange`.
- **Selektoren:** Erzwungene Phasenüberlappung ⇒ `ErrTxSelector`.
- **Boundary:** Manipulierte Fee/Nonce in PIs ⇒ `ErrTxBoundary`.
- **Poseidon-Bindung:** Falscher Digest ⇒ `ErrTxHashBind` (wenn aktiviert).
- **Degree-Budget:** Profilwechsel STD → HiSec ändert `ParamDigest`; alter Proof wird abgelehnt.

## 13. Sicherheitsrationale
- Permutation-Argument mit Transcript-Challenges `β`, `γ` verhindert strukturelle Kollisionen und Grinding.
- Domain-Tags `tag_in`, `tag_out`, `tag_fee` trennen Multisets innerhalb der gleichen Spur.
- Range-Zerlegung garantiert `u64`-Gültigkeit und Nichtnegativität.
- Boundary-Anker koppeln PIs an die Spur; Replay wird durch Transcript-Kontext (z. B. Blockhöhe) verhindert.
- FRI/LDE-Parameter (Phasen 2/3) liefern die gewünschte Sicherheit.
