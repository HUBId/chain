# ZK-Backends

## rpp-stark (stable)

### Aktivierung

- Optionales Feature `backend-rpp-stark` aktivieren, z. B. `cargo build --features backend-rpp-stark`.
- Die Node-Konfiguration muss `max_proof_size_bytes` setzen (Standard: 4 MiB). Der Wert wird beim Bootstrapping an den Verifier weitergereicht.
- `ProofVerifierRegistry::with_max_proof_size_bytes` initialisiert den `RppStarkVerifier` mit der konfigurierten Grenze und blockiert Starts mit übergroßen Limits (> `u32::MAX`).

### Interop-Test

- Golden Vectors liegen unter `vendor/rpp-stark/vectors/stwo/mini/`.
- Testaufruf: `cargo test --features backend-rpp-stark --test interop_rpp_stark`.
- Prüft Digest, Stage-Flags (`params`, `public`, `merkle`, `fri`, `composition`), Proof-Länge und Trace-Indizes.

### Public-Inputs-Encoding

- Byte-Layout ist in `vendor/rpp-stark/docs/PUBLIC_INPUTS_ENCODING.md` dokumentiert.
- Der Adapter `src/zk/rpp_adapter/public_inputs.rs` nutzt dieselbe Little-Endian-Kodierung und Hashing-Strategie.

### Size-Gate-Mapping

- Proof-Header speichern die Obergrenze in KiB; der Node überträgt `max_proof_size_bytes` an den Verifier, der das Mapping mittels `ensure_proof_size_consistency` verifiziert.
- `ProofVerifierRegistry` konvertiert das Node-Limit in Bytes → KiB und lehnt Werte ab, die nicht in `u32` passen.
- Überlange Artefakte werden als `ChainError::Crypto` verworfen; Logs und Telemetrie melden `proof_backend="rpp-stark"`, `valid=false` und das beobachtete Bytevolumen.

### Fehlerbehandlung & Telemetrie

- `NodeInner::verify_rpp_stark_with_metrics` ruft den Registry-Helper auf und emittiert strukturierte Logs (`valid`, `proof_bytes`, `verify_duration_ms`, Stage-Flags) mit Label `proof_backend="rpp-stark"` und `proof_kind` (z. B. `"transaction"`).
- Fehlerpfade nutzen `emit_rpp_stark_failure_metrics`, das Byte-Größen sowie den Fehlertext protokolliert und `valid=false` setzt.
- Bei blockbezogenen Prüfungen werden Berichte ausgewertet, Size-Gates geprüft und ungültige Proofs sanktioniert (`punish_invalid_proof`).
- `RppStarkProofVerifier` mappt Backend-Fehler (`VerificationFailed`, Size-Mismatch) auf `ChainError::Crypto` und hängt den strukturierten Report an die Log-Nachricht an.
