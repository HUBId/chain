# Pruning AIR Specification Skeleton

## 0. Ziel & Scope
- Beweise, dass Pruning eine deterministische Transformation vom alten Snapshot `old` zum neuen Snapshot `new` durchführt.
- Die Partitionierung erfüllt `old = keep ⊎ drop`, `new = keep`, und alle entfernten Elemente werden verlustfrei in einem Recovery-Anchor aggregiert: `anchor = Agg(drop)`.
- Bindung der Public Inputs und externen Commitments über Transcript-/Commitment-Digests (Phase 3/5) ohne direkte BLAKE3-Simulation in der AIR.

## 1. Public Inputs (Little-Endian, Reihenfolge fix)
Die Public Inputs liegen im Proof-Envelope-Header (Phase 5) und werden mittels Boundary-Polynomen an die Spur gebunden.

| Feld | Größe | Beschreibung |
| --- | --- | --- |
| `OldPruneDigest` | 32 B | Digest des ungeprunten Snapshots. |
| `NewPruneDigest` | 32 B | Digest des geprunten Snapshots. |
| `RecoveryAnchor` | 32 B | Aggregierter Digest der entfernten Elemente. |

## 2. Trace-Layout (column-major, dicht)
### 2.1 Registerklassen
**Core-Register (≤ 40 Spalten empfohlen)**
- `A_old`: Arithmetischer Akkumulator für `old`.
- `A_new`: Arithmetischer Akkumulator für `new`.
- `A_anchor`: Arithmetischer Akkumulator für den Recovery-Anchor.
- `E_key`: Feldkodierter Schlüssel des aktuellen Elements.
- `E_val`: Feldkodierter Wert bzw. Metadaten des Elements.
- `keep_flag`, `drop_flag`: Affine Flags zur Partitionierung.

**Auxiliary-Register (≤ 24 Spalten empfohlen)**
- Zerlegungen (`Limbs`) von `E_key`, `E_val` in Basis `B ∈ {2^16, 2^32}`.
- Format-/Range-Flags sowie strukturierende Tag-Register.
- Grand-Product-/Permutation-Hilfsregister (siehe Abschnitt 6).

**Selector-Register (≤ 6 Spalten empfohlen)**
- `σ_first`, `σ_last`: Start-/Endmarker.
- `σ_filter`: Selektor für Elementverarbeitung.
- `σ_finalize`: Selektor für das Abschlussfenster.

### 2.2 Zeilensemantik & Phasen
- Dichte Spur mit Schrittweite 1.
- **Filter-Phase (`σ_filter = 1`)**: Jede Zeile verarbeitet genau ein Element aus `old` und bestimmt deterministisch `keep` oder `drop`.
- **Finalize-Phase (`σ_finalize = 1`)**: Keine neuen Elemente; Akkumulatoren bleiben konstant, Boundary- und Permutationsabschlüsse werden erzwungen.

## 3. Parameter & Kodierung
- Elementdarstellung: `(E_key, E_val)` als Feld-Tuple oder dokumentierte feste Struktur (z. B. `(shard, key_hi, key_lo, val_tag, val_data, …)`).
- Flags: `keep_flag`, `drop_flag ∈ {0,1}` mit `keep_flag + drop_flag = 1`.
- Akkumulator-Abbildung: deterministische lineare/affine Mappings `φ_old`, `φ_new`, `φ_anchor` für die Einspeisung von Elementen.
- Optional: Poseidon-basierter Hash-Akkumulator zur Spiegelung externer Strukturen.

## 4. Selektor-Definitionen (semantisch)
Für Zeilenindex `i` mit Gesamtlänge `T`:
- `σ_first(i) = 1 ⇔ i = 0`.
- `σ_last(i) = 1 ⇔ i = T − 1`.
- `σ_filter(i) + σ_finalize(i) = 1` und `σ_filter(i) · σ_finalize(i) = 0`.
- Erste Zeile liegt in der Filter-Phase: `σ_first · (1 − σ_filter) = 0`.
- Letzte Zeile liegt in der Finalize-Phase: `σ_last · σ_finalize = σ_last`.

## 5. Constraints
### 5.1 Boundary-Constraints (Bindung an Public Inputs)
**Startanker (`σ_first`):**
- `σ_first · (A_old − OldPruneDigest_arith_init) = 0`.
- `σ_first · (A_new − NewPruneDigest_arith_init) = 0`.
- `σ_first · (A_anchor − RecoveryAnchor_arith_init) = 0`.

**Endanker (`σ_last`):**
- `σ_last · (A_old − OldPruneDigest_arith_final) = 0`.
- `σ_last · (A_new − NewPruneDigest_arith_final) = 0`.
- `σ_last · (A_anchor − RecoveryAnchor_arith_final) = 0`.

Init- und Finalwerte sind arithmetische Spiegel der gleichen PI-Werte; die Finalize-Phase erzwingt die Stabilität der Akkumulatoren.

### 5.2 Transition-Constraints (Filter vs. Finalize)
**Partitionierung:**
- `keep_flag · drop_flag = 0`.
- `keep_flag + drop_flag = 1`.
- `σ_filter · (keep_flag + drop_flag − 1) = 0`.
- `σ_finalize · keep_flag = 0`, `σ_finalize · drop_flag = 0`.

**Akkumulator-Fortschreibung (nur Filter):**
- `σ_filter · (A_old(next) − A_old(cur) − φ_old(E_key, E_val)) = 0`.
- `σ_filter · (A_new(next) − A_new(cur) − keep_flag · φ_new(E_key, E_val)) = 0`.
- `σ_filter · (A_anchor(next) − A_anchor(cur) − drop_flag · φ_anchor(E_key, E_val)) = 0`.

**Konstanz (Finalize):**
- `σ_finalize · (A_old(next) − A_old(cur)) = 0`.
- `σ_finalize · (A_new(next) − A_new(cur)) = 0`.
- `σ_finalize · (A_anchor(next) − A_anchor(cur)) = 0`.

**Format-/Range-Regeln:**
- `E_key`, `E_val` erfüllen strukturierte Lookups/Range-Constraints (siehe Abschnitt 7).

## 6. Multiset-/Permutation-Argumente
### 6.1 Ziele
- Partitionierung: `old = keep ⊎ drop`.
- Konsistenz des neuen Snapshots: `new = keep`.

### 6.2 Challenges & Tags
- Transcriptgebundene Challenges `β`, `γ`, `δ` (LE → Feldelemente).
- Map-Funktion `ψ(E) = β + E_key + γ · E_val + δ · tag`.
- Disjunkte Domain-Tags `tag_old`, `tag_keep`, `tag_drop`, `tag_new` zur Trennung der Multisets.

### 6.3 Grand-Product-Spalte `Z`
- Initialisierung: `σ_first · (Z − 1) = 0`.
- Filter-Phase: Links (old) multipliziert inverse Faktoren `ψ_old(E)^{-1}`, rechts (keep/drop) multipliziert regulär mit `keep_flag · ψ_keep(E) + drop_flag · ψ_drop(E)`.
- Rekurrenz pro Zeile: `Z(next) − Z(cur) · ((ψ_keep(E))^{keep_flag} · (ψ_drop(E))^{drop_flag} · (ψ_old(E))^{−1}) = 0`.
- Finalize-Phase: `σ_finalize · (Z(next) − Z(cur)) = 0`.
- Abschluss: `σ_last · (Z − 1) = 0`.

Damit gilt `∏_{keep} ψ_keep · ∏_{drop} ψ_drop = ∏_{old} ψ_old` und erzwingt die Partition.

### 6.4 Konsistenz „new = keep“
- Optional zweites Grand-Product `Z2`, das `ψ_new` gegen `ψ_keep` vergleicht.
- Empfohlen: Verzicht auf `Z2`, sofern `A_new` ausschließlich `keep_flag · φ_new(E)` absorbiert und über Boundary an `NewPruneDigest` gebunden ist.

## 7. Lookups & Formatregeln
- Key-Format: Tag-/Längen-/Shard-Felder mit Range-Lookups auf Limbs.
- Value-Format: Typ-Tag, zulässige Ranges; eindeutige Nullrepräsentation (z. B. `val = 0` unzulässig, wenn „leer“ kodiert).
- Policy-Regeln: deterministische Abbildung (public/challenge-getrieben) von Elementfeldern zu `keep_flag`/`drop_flag`.
- Flag-Kohärenz: Lookups/Constraints stellen sicher, dass `keep_flag = 1` genau dann, wenn die Policy erfüllt ist; ansonsten `drop_flag = 1`.

## 8. DEEP-Komposition & Out-of-Domain (OOD)
### 8.1 Kompositionspolynom
- Kanonische Ordnung der Constraints: Boundary (`A_old`, `A_new`, `A_anchor`) → Selektor-Gesetze → Partitionierungs-Flags → Akkumulator-Fortschreibung → Format-/Range-Lookups → Grand-Product → optional Hash-Akkumulator.
- Unabhängige `α`-Gruppen (Boundary vs. Transition) mit Degree-Bound unterhalb des LDE-Bounds (profilabhängig).

### 8.2 OOD-Punkte & Öffnungen
- Mindestens zwei OOD-Punkte `{ζ₁, ζ₂}`.
- An jedem `ζ` öffnen: `A_old`, `A_new`, `A_anchor`, `Z` (Grand-Product), optional `H_acc`, sowie den Kompositionswert `C(ζ)`.
- Reihenfolge/Serialisierung folgen der globalen Proof-Konfiguration (Phasen 4/5).

## 9. Degree-Bounds
- Selektor-/Boundary-/Akkumulator-Gleichungen: Grad ≤ 2.
- Flags/Format-/Range-Lookups: Grad ≤ 3 (schemaabhängig).
- Grand-Product-Schritt: Grad ≤ 2.
- Optional Poseidon-S-Box: Grad 5, dünn belegt via Selektor.
- Gesamter Degree-Bound bleibt innerhalb des LDE-Budgets (Profil STD, HiSec mit Reserve).

## 10. Commitments & Openings
- **Commitments (Phasen 4/5):**
  - Core-Gruppe: LDE-Evaluierungen von `A_old`, `A_new`, `A_anchor`, `E_key`, `E_val`, `keep_flag`, `drop_flag`, optional `H_acc`.
  - Aux-Gruppe: Zerlegungen/Range-/Format-Hilfen und `Z` (Grand-Product).
- **Openings:** Pro Query-Position vollständiger Zeilenvektor je Gruppe; Reihenfolgen folgen der festen Spaltenordnung.

## 11. Fehlerklassen
- `ErrPruneBoundary` — Akkumulatoren passen nicht zu den PIs (`OldPruneDigest`, `NewPruneDigest`, `RecoveryAnchor`).
- `ErrPrunePartition` — Flags verletzen Disjunktheit oder Summe = 1.
- `ErrPruneFormat` — Key-/Value-Format oder Range fehlerhaft.
- `ErrPrunePolicy` — Flag-Berechnung widerspricht der dokumentierten Policy.
- `ErrPrunePermutation` — Grand-Product inkonsistent (`old ≠ keep ⊎ drop`).
- `ErrPruneSelector` — Selektor-Gesetze verletzt.
- `ErrPruneDegreeBound` — Gradbudget überschritten.

## 12. Profil-Obergrenzen & Ressourcen
- Spurbreite (Core + Aux + Selector): ≤ 48 (Profil STD).
- Schrittanzahl: ≤ 2^21 (abhängig von der Elementanzahl).
- HiSec-Profil: gleiche Breite, Queries ↑ (96), LDE ×16.
- Throughput-Profil: reduzierte Queries (48/56), Size-Budget beachten.

## 13. Tests (konzeptuell, ohne Code)
- **Determinismus:** Gleiche `old`-Liste + deterministische Policy ⇒ identische `proof_bytes`.
- **Partition-Korrektheit:** Korrekte Aufteilung ⇒ Accept; vertauschtes Element ⇒ `ErrPrunePermutation`.
- **New-Bindung:** Manipuliertes `NewPruneDigest` in den PIs ⇒ `ErrPruneBoundary`.
- **Anchor-Konsistenz:** Manipulation eines Drop-Elements ⇒ `ErrPruneBoundary` oder `ErrPrunePermutation` (je nach Manipulation).
- **Flags/Policy:** `keep_flag = drop_flag = 1` ⇒ `ErrPrunePartition`; falsche Policy-Abbildung ⇒ `ErrPrunePolicy`.
- **Format/Range:** Unzulässiger Key-/Value-Tag ⇒ `ErrPruneFormat`.
- **Degree-Budget:** Profilwechsel STD→HiSec erzeugt neuen `ParamDigest`; alte Proofs werden korrekt abgelehnt.

## 14. Sicherheitsrationale
- Grand-Product mit transcriptgebundenen `β`, `γ`, `δ` und Domain-Tags erzwingt die korrekte Multiset-Partition.
- Akkumulator-Bindungen koppeln neue/alte/Anchor-Digests deterministisch an die Spur.
- Format-/Range-Lookups verhindern versteckte Werte und sichern Policy-Kohärenz.
- Disjunktheits-Flags & Selektor-Gesetze erzwingen saubere Phasen.
- Transcript-/Blockkontext (Phase 3) schützt vor Replay und bindet an externe Commitments.
- Konsistenz mit ParamDigest, Transcript und Proof-Envelope folgt der globalen Beweisarten-Reihenfolge (Phasen 2–5).
