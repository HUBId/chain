# ADR 0002: Plonky3-Schlüssel-Schemata und Metadaten

## Status

Accepted – die Schemata werden ab sofort für Artefakt-Freigaben verwendet.

## Kontext

Die Plonky3-Setup-Artefakte enthalten inline codierte Prüf- und Verifikations-
schlüssel. Bisher war die Struktur der JSON-Dokumente implizit, was Tooling,
Audits und Hash-Validierungen erschwert hat. Zudem fehlte eine deterministische
Referenz für `ProofMetadata`, obwohl das Backend bereits die Hashes in jedem
Proof validiert.

## Entscheidung

* **Deterministische JSON-Schemata.** `plonky3_backend::VerifyingKey`,
  `ProvingKey` und `ProofMetadata` liefern jetzt explizite Schemata gemäß Draft
  2020-12. Die Hilfsfunktionen stellen sicher, dass Reihenfolge und Feldnamen
  stabil bleiben und zusätzliche Felder abgelehnt werden.【F:prover/plonky3_backend/src/lib.rs†L24-L236】【F:prover/plonky3_backend/tests/keys.rs†L33-L106】
* **Decoder-Hilfsfunktionen.** Neue Konstruktoren validieren Base64/Gzip-Inputs
  und verifizieren den BLAKE3-Hash der resultierenden Bytes, wodurch externe
  Tools unkompliziert Inline-Schlüssel prüfen können.【F:prover/plonky3_backend/src/lib.rs†L56-L104】
* **Dokumentation.** Die Setup-Anleitung verweist auf die Schemata und fasst das
  finale Feldset der Artefakte zusammen, inklusive optionaler `hash_blake3`
  Felder und des `compression`-Schalters.【F:config/plonky3/setup/README.md†L24-L44】

## Konsequenzen

* Revisionssichere Artefakte: Auditor:innen können das Schema sowie die
  Hash-Validierungen reproduzieren, Tests sichern die Stabilität der Schemata
  ab.【F:prover/plonky3_backend/tests/keys.rs†L13-L106】
* Tooling und Skripte können Inline-Artefakte mit einer einzigen Funktion
  dekodieren, ohne das vollständige Loader-Subsystem zu importieren.【F:prover/plonky3_backend/src/lib.rs†L56-L104】
* Künftige Änderungen an den Artefakten müssen das Schema aktualisieren und
  werden dadurch automatisch von den Roundtrip-Tests erfasst.【F:prover/plonky3_backend/tests/keys.rs†L13-L106】
