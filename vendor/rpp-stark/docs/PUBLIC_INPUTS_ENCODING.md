# Public-Inputs-Encoding

## Zweck
Diese Spezifikation fixiert die kanonische Byte-Kodierung sämtlicher Public Inputs, damit externe STWO-Nodes den `public_digest` deterministisch nachrechnen können.【F:src/proof/public_inputs.rs†L1-L6】

## Allgemeine Regeln
- Alle Ganzzahlen und Feldwerte werden Little-Endian kodiert; variable Abschnitte besitzen ein vorgeschaltetes `u32`-Längenfeld.【F:src/proof/public_inputs.rs†L1-L6】【F:src/proof/ser.rs†L86-L125】
- Die Feldreihenfolge ist fix und abhängig vom Proof-Typ (`ProofKind`). Zur Laufzeit dürfen keine Sortierungen oder Umsortierungen stattfinden.【F:src/proof/public_inputs.rs†L45-L104】【F:src/proof/ser.rs†L86-L157】
- Es existiert kein Padding zwischen Feldern; Bytes werden unmittelbar hintereinander geschrieben.【F:src/proof/ser.rs†L86-L157】

## Feldtabellen
### Execution (`ProofKind::Execution`)
| Reihenfolge | Feld | Typ | Länge (Byte) | Encoding | Quelle |
|-------------|------|-----|--------------|----------|--------|
| 1 | `version` | `u8` (`V1` → `0x01`) | 1 | Wert direkt | 【F:src/proof/ser.rs†L86-L101】
| 2 | `program_digest` | Digest | 32 | Rohbytes | 【F:src/proof/ser.rs†L101-L103】
| 3 | `trace_length` | `u32` | 4 | LE | 【F:src/proof/ser.rs†L103-L105】
| 4 | `trace_width` | `u32` | 4 | LE | 【F:src/proof/ser.rs†L103-L109】
| 5 | `body_len` | `u32` | 4 | LE (vor Body) | 【F:src/proof/ser.rs†L109-L113】
| 6 | `body` | Bytes | `body_len` | Rohbytes | 【F:src/proof/ser.rs†L109-L113】

### Aggregation (`ProofKind::Aggregation`)
| Reihenfolge | Feld | Typ | Länge (Byte) | Encoding | Quelle |
|-------------|------|-----|--------------|----------|--------|
| 1 | `version` | `u8` (`V1`) | 1 | Wert direkt | 【F:src/proof/ser.rs†L113-L130】
| 2 | `circuit_digest` | Digest | 32 | Rohbytes | 【F:src/proof/ser.rs†L122-L128】
| 3 | `leaf_count` | `u32` | 4 | LE | 【F:src/proof/ser.rs†L126-L130】
| 4 | `root_digest` | Digest | 32 | Rohbytes | 【F:src/proof/ser.rs†L126-L133】
| 5 | `body_len` | `u32` | 4 | LE | 【F:src/proof/ser.rs†L133-L136】
| 6 | `body` | Bytes | `body_len` | Rohbytes | 【F:src/proof/ser.rs†L133-L136】

### Recursion (`ProofKind::Recursion`)
| Reihenfolge | Feld | Typ | Länge (Byte) | Encoding | Quelle |
|-------------|------|-----|--------------|----------|--------|
| 1 | `version` | `u8` (`V1`) | 1 | Wert direkt | 【F:src/proof/ser.rs†L136-L155】
| 2 | `depth` | `u8` | 1 | Wert direkt | 【F:src/proof/ser.rs†L146-L151】
| 3 | `boundary_digest` | Digest | 32 | Rohbytes | 【F:src/proof/ser.rs†L146-L153】
| 4 | `recursion_seed` | Digest | 32 | Rohbytes | 【F:src/proof/ser.rs†L146-L155】
| 5 | `body_len` | `u32` | 4 | LE | 【F:src/proof/ser.rs†L151-L157】
| 6 | `body` | Bytes | `body_len` | Rohbytes | 【F:src/proof/ser.rs†L151-L157】

### Post-Quantum VRF (`ProofKind::VrfPostQuantum`)
| Reihenfolge | Feld | Typ | Länge (Byte) | Encoding | Quelle |
|-------------|------|-----|--------------|----------|--------|
| 1 | `version` | `u8` (`V1`) | 1 | Wert direkt | 【F:src/proof/ser.rs†L157-L188】
| 2 | `public_key_commit` | Digest | 32 | Rohbytes | 【F:src/proof/ser.rs†L167-L177】
| 3 | `prf_param_digest` | Digest | 32 | Rohbytes | 【F:src/proof/ser.rs†L167-L177】
| 4 | `rlwe_param_id` | 32-Byte-Identifier | 32 | Rohbytes | 【F:src/proof/ser.rs†L177-L183】【F:src/vrf/mod.rs†L34-L63】
| 5 | `vrf_param_id` | 32-Byte-Identifier | 32 | Rohbytes | 【F:src/proof/ser.rs†L177-L183】【F:src/vrf/mod.rs†L44-L63】
| 6 | `transcript_version_id` | Digest | 32 | Rohbytes | 【F:src/proof/ser.rs†L183-L188】【F:src/config/mod.rs†L104-L114】
| 7 | `field_id` | `u16` | 2 | LE | 【F:src/proof/ser.rs†L183-L188】【F:src/vrf/mod.rs†L18-L27】
| 8 | `context_digest` | Digest | 32 | Rohbytes | 【F:src/proof/ser.rs†L183-L188】
| 9 | `body_len` | `u32` | 4 | LE | 【F:src/proof/ser.rs†L188-L193】
| 10 | `body` | Bytes | `body_len` | Rohbytes | 【F:src/proof/ser.rs†L188-L193】

## Digest-Berechnung
Der Public-Inputs-Digest wird strikt als `public_digest = Blake2s("RPP-PI-V1" || kind.code() || encode(public_inputs))` berechnet; `Hasher::finalize()` liefert dabei ein 32-Byte-Ergebnis. Alle Teilnehmer müssen denselben Präfix (`"RPP-PI-V1"`) und Proof-Kind-Code verwenden.【F:src/proof/aggregation.rs†L185-L194】【F:src/hash/deterministic.rs†L134-L167】

## Golden Check
Um einen Digest zu prüfen, führt der Node folgende Schritte aus:
1. Public-Input-Felder gemäß obigen Tabellen in ein Byte-Array serialisieren.
2. Body-Längenfelder (`u32` LE) setzen und anschließend die Body-Bytes anhängen.
3. Den Proof-Kind-Code (`ProofKind::code()`) als einzelnes Byte voranstellen.【F:src/proof/public_inputs.rs†L23-L40】【F:src/proof/aggregation.rs†L185-L194】
4. Den Präfix `"RPP-PI-V1"` voranstellen und alles mit Blake2s (32-Byte-Ausgabe) hashen.【F:src/proof/aggregation.rs†L185-L194】【F:src/hash/deterministic.rs†L134-L167】
5. Das Ergebnis muss mit dem im Proof gelieferten `public_digest` übereinstimmen; Abweichungen führen zu `PublicDigestMismatch` im Verifier.【F:README.md†L392-L399】

## Kompatibilität & Versionierung
Eine Änderung der Feldreihenfolge, Feldtypen oder Hash-Parameter ändert den Digest und erfordert einen `PROOF_VERSION`-Bump sowie aktualisierte Snapshots laut Änderungspolitik.【F:src/proof/types.rs†L11-L36】【F:README.md†L934-L938】
