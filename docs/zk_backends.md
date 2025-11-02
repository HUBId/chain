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
- Beispiel-`scrape_config` für Prometheus (wenn `rollout.telemetry.metrics.listen = "127.0.0.1:9797"` konfiguriert ist):

  ```yaml
  scrape_configs:
    - job_name: rpp-node
      honor_labels: true
      static_configs:
        - targets: ["rpp-node:9797"]
      metrics_path: /metrics
      # Optional, falls rollout.telemetry.metrics.auth_token gesetzt ist
      authorization:
        credentials: Bearer change-me
      relabel_configs:
        - source_labels: [__address__]
          target_label: instance
  ```
- Bei blockbezogenen Prüfungen werden Berichte ausgewertet, Size-Gates geprüft und ungültige Proofs sanktioniert (`punish_invalid_proof`).
- `RppStarkProofVerifier` mappt Backend-Fehler (`VerificationFailed`, Size-Mismatch) auf `ChainError::Crypto` und hängt den strukturierten Report an die Log-Nachricht an.

## plonky3 (vendor backend)

### Aktivierung

- Optionales Feature `backend-plonky3` aktivieren, z. B. `cargo build --features backend-plonky3` oder `scripts/build_release.sh` mit `RPP_RELEASE_BASE_FEATURES="prod,backend-plonky3"`. Das Feature schaltet den vendorisierten Prover/Verifier frei und kann parallel zu STWO eingesetzt werden; der Guard blockiert weiterhin Kombinationen mit `prover-mock`.【F:scripts/build_release.sh†L1-L118】【F:rpp/node/src/feature_guard.rs†L1-L5】
- Der Prover lädt vendorisierte Parameter, generiert echte Proofs für alle Circuit-Familien und persistiert die Schlüssel im Cache (`backend_health.plonky3.*`).【F:rpp/proofs/plonky3/prover/mod.rs†L19-L520】
- Keine zusätzlichen CLI-Schalter notwendig; Laufzeit und Wallet greifen automatisch auf das Plonky3-Backend zu, sobald das Feature aktiv ist.【F:rpp/node/src/lib.rs†L240-L360】【F:rpp/runtime/node.rs†L161-L220】

### Test- und Interop-Abdeckung

- `scripts/test.sh --backend plonky3 --unit --integration` erzeugt und verifiziert Vendor-Proofs für alle Circuit-Familien.【F:scripts/test.sh†L1-L220】
- Regressionstests (`plonky3_transaction_roundtrip`, `plonky3_recursion`) prüfen Witness-Kodierung, Rekursion und Tamper-Rejection gegen das echte Backend.【F:tests/plonky3_transaction_roundtrip.rs†L1-L200】【F:tests/plonky3_recursion.rs†L1-L360】
- Das Simnet-Szenario `consensus-quorum-stress` misst Prover/Verifier-Latenzen, Tamper-Rejections und Proof-Größen; Nightly CI bricht bei Grenzwertüberschreitungen ab.【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】【F:scripts/analyze_simnet.py†L1-L200】

### Telemetrie & API-Oberfläche

- `Plonky3Prover` aktualisiert Telemetrie (`cached_circuits`, `proofs_generated`, `failed_proofs`, Zeitstempel) auf Basis realer Läufe.【F:rpp/proofs/plonky3/prover/mod.rs†L19-L520】
- `/status/node` liefert produktive Prover-/Verifier-Snapshots unter `backend_health.plonky3.*`; die Validator-UI rendert die Werte direkt aus diesen Feldern.【F:rpp/runtime/node.rs†L161-L220】【F:validator-ui/src/types.ts†L140-L220】
- Grafana-Panels in `docs/dashboards/consensus_proof_validation.json` zeigen p50/p95-Latenzen, Proof-Größen und Tamper-Rejections, unterstützt durch Nightly-Stresstests.【F:docs/dashboards/consensus_proof_validation.json†L1-L200】【F:docs/performance/consensus_proofs.md†L1-L200】

### Offene Aufgaben

- GPU-Benchmarks ausrollen und zusätzliche Nightly-Profile aufnehmen.
- Key-Distribution-Automatisierung für Multi-Region-Deployments ausarbeiten (siehe Runbook-Follow-ups).【F:docs/runbooks/plonky3.md†L1-L200】
