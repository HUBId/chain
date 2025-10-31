# ZK-Backends

## rpp-stark (stable)

### Aktivierung

- Optionales Feature `backend-rpp-stark` aktivieren, z. B. `cargo build --features backend-rpp-stark`.
- Die Node-Konfiguration muss `max_proof_size_bytes` setzen (Standard: 4 MiB). Der Wert wird beim Bootstrapping an den Verifier weitergereicht.
- `ProofVerifierRegistry::with_max_proof_size_bytes` (siehe `rpp/proofs/proof_system/mod.rs`) initialisiert den `RppStarkVerifier` mit der konfigurierten Grenze und blockiert Starts mit übergroßen Limits (> `u32::MAX`).

### Interop-Test

- Golden Vectors liegen unter `vendor/rpp-stark/vectors/stwo/mini/`.
- Testaufruf: `cargo test --features backend-rpp-stark --test interop_rpp_stark`.
- CI-Absicherung: Der GitHub-Actions-Workflow `nightly-simnet` (Job `simnet`) führt den Test als Teil seiner Matrix-Läufe bei jedem nächtlichen Durchlauf aus.
- Prüft Digest, Stage-Flags (`params`, `public`, `merkle`, `fri`, `composition`), Proof-Länge und Trace-Indizes.

### Public-Inputs-Encoding

- Byte-Layout ist in `vendor/rpp-stark/docs/PUBLIC_INPUTS_ENCODING.md` dokumentiert.
- Der Adapter `rpp/chain/src/zk/rpp_adapter/public_inputs.rs` nutzt dieselbe Little-Endian-Kodierung und Hashing-Strategie.

### Size-Gate-Mapping

- Proof-Header speichern die Obergrenze in KiB; der Node überträgt `max_proof_size_bytes` an den Verifier, der das Mapping mittels `ensure_proof_size_consistency` verifiziert.
- `ProofVerifierRegistry` konvertiert das Node-Limit in Bytes → KiB und lehnt Werte ab, die nicht in `u32` passen.
- Überlange Artefakte werden als `ChainError::Crypto` verworfen; Logs und Telemetrie melden `proof_backend="rpp-stark"`, `valid=false` und das beobachtete Bytevolumen.

### Fehlerbehandlung & Telemetrie

- `NodeInner::verify_rpp_stark_with_metrics` (implementiert in `rpp/runtime/node.rs`) ruft den Registry-Helper auf und emittiert strukturierte Logs (`valid`, `proof_bytes`, `verify_duration_ms`, Stage-Flags) mit Label `proof_backend="rpp-stark"` und `proof_kind` (z. B. `"transaction"`).
- Zusätzlich landen die Kennzahlen auf dem `telemetry`-Target. Erfolgreiche Prüfungen loggen `params_ok`, `public_ok`, `merkle_ok`, `fri_ok`, `composition_ok` sowie `params_bytes`, `public_inputs_bytes` und `payload_bytes`.
- Fehlerpfade nutzen `emit_rpp_stark_failure_metrics` (`rpp/runtime/node.rs`), das Byte-Größen sowie den Fehlertext protokolliert und `valid=false` setzt.
- Beispielausgaben:

  ```text
  INFO telemetry proof_backend="rpp-stark" proof_kind="transaction" valid=true params_ok=true public_ok=true merkle_ok=true fri_ok=true composition_ok=true proof_bytes=1234 params_bytes=256 public_inputs_bytes=64 payload_bytes=914 verify_duration_ms=42 "rpp-stark proof verification"
  WARN telemetry proof_backend="rpp-stark" proof_kind="transaction" valid=false proof_bytes=1234 params_bytes=256 public_inputs_bytes=64 payload_bytes=914 verify_duration_ms=42 error="cryptography error: verification failed" "rpp-stark proof verification failed"
  ```
- Zusätzlich zu den Logs werden Prometheus-kompatible Metriken über das `metrics`-Crate gemeldet:
  - Histogramme `rpp_stark_verify_duration_seconds`, `rpp_stark_proof_total_bytes`, `rpp_stark_params_bytes`, `rpp_stark_public_inputs_bytes` und `rpp_stark_payload_bytes` (Labels: `proof_backend`, `proof_kind`).
  - Counter `rpp_stark_stage_checks_total` mit Labels `proof_backend`, `proof_kind`, `stage` (`params`, `public`, `merkle`, `fri`, `composition`) und `result` (`ok`/`fail`).
  - Fehlerpfade aktualisieren dieselben Byte-Histogramme, sodass Ausreißer sichtbar bleiben.
- `TelemetrySnapshot` (`rpp/runtime/node_runtime/node.rs`) trägt die `verifier_metrics.per_backend`-Aggregationen weiter, womit Exporter den aktuellen Stand der Backend-Verifikationen ohne zusätzlichen RPC abrufen können.
- Beispiel-`scrape_config` für Prometheus (bei aktivem `metrics-exporter-prometheus` auf Port `9797`):

  ```yaml
  scrape_configs:
    - job_name: rpp-node
      honor_labels: true
      static_configs:
        - targets: ["rpp-node:9797"]
      metrics_path: /metrics
      relabel_configs:
        - source_labels: [__address__]
          target_label: instance
  ```
- Bei blockbezogenen Prüfungen werden Berichte ausgewertet, Size-Gates geprüft und ungültige Proofs sanktioniert (`punish_invalid_proof`).
- `RppStarkProofVerifier` mappt Backend-Fehler (`VerificationFailed`, Size-Mismatch) auf `ChainError::Crypto` und hängt den strukturierten Report an die Log-Nachricht an.
