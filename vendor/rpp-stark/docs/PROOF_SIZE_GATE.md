# Proof-Size-Gate

## Zweck
Das Größen-Gate schützt Verifier und Nodes vor DoS durch übergroße Proofs. Es vergleicht die tatsächliche Serialisierungslänge eines Proofs mit der konfigurierten Obergrenze `proof.max_size_kb` und spiegelt das Ergebnis über `VerifyError::ProofTooLarge` wider.【F:src/proof/envelope.rs†L228-L235】【F:src/proof/types.rs†L1240-L1268】

## Messmethode
1. Proof wird vollständig serialisiert: Header-Bytes, Payload-Bytes sowie das 32-Byte-Integritätsdigest werden summiert (`bytes_total`).【F:src/proof/envelope.rs†L220-L235】
2. Der Grenzwert `limit_bytes = max_size_kb × 1024` wird aus den STARK-Parametern entnommen.【F:src/proof/envelope.rs†L228-L235】【F:src/params/types.rs†L338-L349】
3. Überschreitet `bytes_total` den Grenzwert, schlägt der Builder/Verifier mit `ProofTooLarge { max_kb, got_kb }` fehl; die Kilobyte-Werte sind aufgerundet (`div_ceil(1024)`).【F:src/proof/envelope.rs†L228-L235】【F:src/proof/verifier.rs†L460-L463】

## Node-Mapping
- Die Node-Konfiguration hält denselben Grenzwert in Bytes (`limits.max_proof_size_bytes`). Profile binden diese Ressourcengrenzen an das ParamDigest, wodurch beide Seiten dieselbe Obergrenze teilen.【F:src/config/mod.rs†L268-L324】
- Beim Prover wird `max_proof_size_bytes` in Kibibyte umgerechnet (`bytes_to_kib`) und als `proof.max_size_kb` in den Proof-Parametern gespeichert.【F:src/proof/prover.rs†L278-L305】
- Der Verifier vergleicht erneut `total_bytes` mit `limits.max_proof_size_bytes`, wodurch Node- und Proof-Konfiguration konsistent bleiben.【F:src/proof/verifier.rs†L460-L463】

## Grenzfälle
- Proofs unterhalb der Grenze (z. B. 511 KiB bei `max_size_kb = 512`) werden akzeptiert; `got_kb` entspricht der aufgerundeten Größe und bleibt ≤ `max_kb`.
- Proofs oberhalb der Grenze (z. B. 513 KiB bei `max_size_kb = 512`) lösen deterministisch `ProofTooLarge` aus; die Differenz wird durch das aufgerundete `got_kb` signalisiert.

## Fehlerverhalten & Logging
- Der Verifier meldet den Fehler über `VerifyError::ProofTooLarge { max_kb, got_kb }`; Tests prüfen, dass das Flag `verification_report_flags_proof_size_overflow` gesetzt wird und `got_kb > max_kb` ist.【F:README.md†L124-L135】【F:tests/proof_lifecycle.rs†L914-L947】
- Nodes sollen den Fehler protokollieren und entsprechende Metriken setzen. Weitere Logging-Vorgaben werden im Node-Handbuch ergänzt (TBD, Quelle: README Hinweis auf Mapping `max_proof_size_bytes`).【F:README.md†L1011-L1011】
