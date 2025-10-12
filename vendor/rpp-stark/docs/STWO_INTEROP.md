# STWO-Interoperabilität

## Zweck & Geltungsbereich
Dieses Dokument beschreibt, wie ein externer STWO-Node die von `rpp-stark` erzeugten Beweise bytegenau reproduzieren und prüfen kann. Der Fokus liegt auf Hash- und Merkle-Parametern, Transcript-Orchestrierung, Public-Digest-Bindungen, Size-Gates sowie der Bereitstellung künftiger Golden-Vector-Artefakte.【F:src/transcript/mod.rs†L1-L27】【F:README.md†L374-L408】

## Digest-Familie & Länge
Alle transcript- und Merkle-bezogenen Hashes verwenden den deterministischen Blake2s-Backend `Hasher<Blake2sInteropHasher>`, der immer 32-Byte-Digests liefert. Adapter für Poseidon oder Rescue re-exportieren weiterhin exakt 32 Byte, so dass alle extern sichtbaren Roots und Digests STWO-kompatibel bleiben.【F:src/hash/deterministic.rs†L134-L167】【F:src/hash/deterministic.rs†L211-L337】

## Domain-Separation
- **Merkle-Leaf/Node:** Vor jedem Hash wird ein Node-Tag (`0x00` für Leaves, `0x01` für innere Knoten) vorangestellt; anschließend folgt `domain_sep` aus den STARK-Parametern.【F:src/merkle/mod.rs†L5-L16】
- **Trace-/Composition-Merkle-Kontexte:** Spezifische Transcript-Kontexte `MerkleTrace` und `MerkleComp` liefern 8-Byte-LE-Tags (`0x5250505f54524345`, `0x5250505f4d455243`) und trennen Trace- bzw. Composition-Flows.【F:src/transcript/types.rs†L10-L39】
- **FRI-Kontext:** Der Transcript-Kontext `Fri` (Tag `0x5250505f4652495f`) isoliert FRI-spezifische Bindungen.【F:src/transcript/types.rs†L10-L39】
- **Transcript-Labels:** Jede Absorption nutzt feste 16-Byte-Tags je Label (`ParamsHash`, `ProtocolTag`, `Seed`, `PublicInputsDigest`, `TraceRoot`, `CompRoot`, `FriRoot(i)`, `FriFoldChallenge(i)`, `QueryCount`, `QueryIndexStream`, `ProofClose`); Versionierung erfolgt über `PROOF_VERSION`。【F:src/transcript/types.rs†L62-L124】【F:src/proof/types.rs†L11-L36】
- Alle Tags sind fixiert und versioniert; Änderungen erfordern einen `PROOF_VERSION`-Bump laut Änderungspolitik.【F:README.md†L934-L938】

## Merkle-Parameter
- **Arity:** Standard ist binär; quaternäre Bäume sind zulässig und behalten Rightmost-Child-Duplication bei ungerader Blattzahl.【F:src/merkle/mod.rs†L5-L16】
- **Leaf-Layout:** Jedes Leaf besteht aus `leaf_width` Feldelementen in Little-Endian Byte-Reihenfolge ohne zusätzliche Präfixe. Die Reihenfolge folgt dem globalen `lde.order`-Layout (Row/Col-Major) und muss konsistent übernommen werden.【F:src/merkle/mod.rs†L8-L13】【F:README.md†L320-L325】
- **Digest-Länge:** Merkle-Digests sind 32 Byte Blake2s-Ausgaben.【F:src/hash/merkle.rs†L20-L24】

## Transcript-Reihenfolge
Der Fiat–Shamir-Transcript absorbiert und emittiert Werte strikt in der dokumentierten Reihenfolge: `ParamsHash → ProtocolTag → Seed → PublicInputsDigest → TraceRoot → TraceChallengeA → (optional) CompRoot/CompChallengeA → FRI-Layer (Root, Fold) → QueryCount → QueryIndexStream → ProofClose`. Diese Sequenz muss bei der Reproduktion exakt nachgezogen werden.【F:src/transcript/mod.rs†L7-L23】【F:README.md†L302-L311】【F:README.md†L394-L402】

## Query-Indizes
Query-Indizes werden ausschließlich lokal aus dem Transcript erzeugt. Der Verifier verwendet den FRI-Seed, rekonstruiert alle Fold-Challenges, leitet den Query-Seed ab und berechnet `q = fri.queries` Positionen innerhalb `N = 2^(domain_log2)`. Anschließend werden die Indizes in aufsteigender Reihenfolge ohne Duplikate ausgegeben; das Resultat muss exakt `openings.trace.indices` entsprechen.【F:src/proof/verifier.rs†L393-L433】【F:src/proof/verifier.rs†L604-L682】【F:src/fri/proof.rs†L360-L377】【F:README.md†L398-L404】【F:README.md†L430-L434】

## Proof-ABI Referenz
- **Proof-Layout & Fehler-Taxonomie:** README-Sektion „Proof-Envelope & Verifier“ dokumentiert Header-Reihenfolge, optionale Felder, Fehlernamen und Size-Gate-Regeln.【F:README.md†L374-L428】
- **Openings-Bundles & Query-Regeln:** README-Bereich „Query-Indizes“ wiederholt die Pflicht zur lokalen Generierung und den Abgleich mit `openings.trace.indices`. Eine konsolidierte ABI-Seite ist noch offen (`PROOF_ABI.md` TBD).【F:README.md†L430-L434】
- **Telemetry & Reporting:** README beschreibt das Reporting inklusive `ProofTooLarge`-Flag; dedizierte Telemetry-Doku wird künftig gebündelt.【F:README.md†L392-L417】

## Public-Inputs-Digest
Externe Nodes müssen die Byte-Kodierung der Public Inputs exakt nach `docs/PUBLIC_INPUTS_ENCODING.md` erzeugen und anschließend den Digest gemäß dortiger Hash-Regel berechnen. Abweichungen führen zu `PublicDigestMismatch`.【F:README.md†L302-L308】【F:README.md†L392-L399】

## Size-Gate
Proofs dürfen die in `proof.max_size_kb` hinterlegte Grenze nicht überschreiten. Die Messung basiert auf der tatsächlichen Serialisierungslänge (Header + Payload + Integritätsdigest). Siehe `docs/PROOF_SIZE_GATE.md` für das Node-Mapping zu `max_proof_size_bytes` und Fehlerverhalten (`ProofTooLarge`).【F:src/proof/envelope.rs†L228-L235】【F:src/proof/verifier.rs†L460-L463】

## Golden Vectors
### Golden Vectors (mini)
Die deterministische Mini-Fixture ist unter `vectors/stwo/mini/` abgelegt und besteht aus:

- `params.bin` – kanonische `StarkParams`-Serialisierung des Standardprofils als durchgehender Hex-String (zweistellig pro Byte, abschließendes `\n`).
- `public_inputs.bin` – Public-Inputs gemäß Encoding-Spezifikation, identisch hexkodiert; der Digest liegt in `public_digest.hex`.
- `proof.bin` – vollständiger Proof-Envelope inklusive Header, ebenfalls hexkodiert.
- `proof_report.json` – Verifier-Report mit allen Erfolgsflags und der Byte-Länge.
- `roots.json` – Trace-Root, optionaler Composition-Root sowie alle FRI-Layer-Roots.
- `challenges.json` – FRI-Fold-Challenges, Query-Konfiguration, Transcript-Tag und Seed.
- `indices.json` – lokal rekonstruierte Query-Indizes (sortiert & dedupliziert).
- `README.md` – Einstiegspunkt mit Links auf die Encoding- und Size-Gate-Dokumente.

Ein externer Node sollte beim Import folgende Gleichheiten prüfen:

1. `params.bin` → `params_hash` muss mit dem Proof-Header übereinstimmen.【F:tests/golden_vector_export.rs†L63-L78】【F:tests/golden_vector_export.rs†L106-L124】
2. `public_inputs.bin` → Digest aus `public_digest.hex` muss exakt dem Header entsprechen.【F:tests/golden_vector_export.rs†L80-L124】
3. Die aus Transcript/FRI abgeleiteten Query-Indizes müssen `indices.json` entsprechen und identisch zu `openings.trace.indices` sein.【F:tests/golden_vector_export.rs†L126-L176】【F:tests/golden_vector_export.rs†L178-L240】
4. `proof_report.json.total_bytes` muss der Byte-Länge von `proof.bin` entsprechen und alle Flags (`params_ok`, `public_ok`, `merkle_ok`, `fri_ok`, `composition_ok`) auf `true` stehen.【F:tests/golden_vector_export.rs†L90-L105】【F:tests/golden_vector_export.rs†L242-L274】

Hinweis: Für alle `*.bin`-Artefakte ist vor diesen Vergleichen der Hex-String in rohe Bytes zu dekodieren.

### CI: Golden-Vector Verify
Ein dedizierter CI-Workflow ([`interop-golden-vector.yml`](../.github/workflows/interop-golden-vector.yml)) führt Build, Tests, Clippy sowie das Prüfskript [`scripts/ci/interop_golden_check`](../scripts/ci/interop_golden_check) aus, um die Mini-Artefakte automatisiert zu verifizieren.
Dabei werden `param_digest`/Proof-Header, `public_digest`, Query-Indizes, Report-Flags und `total_bytes` bitgenau abgeglichen und Abweichungen mit klaren Hinweisen gemeldet.
Zum Abschluss startet das Skript `cargo test --tests -q` erneut, damit alle Dateien deterministisch und unverändert bleiben.

## Änderungspolitik
Jede Änderung an Digest-Familie, Domain-Tags, Transcript-Sequenz oder am Proof-ABI erzwingt einen `PROOF_VERSION`-Bump sowie eine dokumentierte Snapshot-Aktualisierung im CHANGELOG. Diese Disziplin ist bereits in README und CHANGELOG verankert.【F:src/proof/types.rs†L11-L36】【F:README.md†L934-L938】【F:CHANGELOG.md†L1-L34】
