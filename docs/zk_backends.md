# ZK-Backends

> **Breadcrumbs:** [Operator documentation index](./README.md) › [Zero-knowledge backend procedures](./README.md#zero-knowledge-backend-procedures) › ZK-backends
>
> **Complementary guides:** [Observability runbook](./runbooks/observability.md),
> [Security policy & reporting](../SECURITY.md),
> [RPP vendor refresh procedure](./operations/rpp_vendor_update.md),
> [Incident response runbook](./operations/incidents.md)

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
- Die Backend-Unit-Suite schreibt die Checksummen der Golden-Vector-Artefakte sowie die verifizierte Proof-Länge, Stage-Flags und Telemetrie (falls vorhanden) nach `logs/rpp_golden_vector_checksums.log` und vergleicht sie in CI gegen die Basislinie `tests/baselines/rpp_golden_vector_checksums.log`. Drift blockiert den Lauf; legitime Updates werden über `tools/update_rpp_golden_vector_baseline.sh` übernommen.
- Die Pruning-Snapshot-Replays unter `wallet_snapshot_round_trip_*` (siehe `tests/pruning_cross_backend.rs`) hängen eine zk-Validierung an: der Default-Backend-Lauf erzeugt eine STWO-Transaktionsprobe, während der `backend-rpp-stark`-Zweig den Golden Vector verifiziert, nachdem WAL-Inhalte und Snapshots wiederhergestellt wurden. Beide Pfade laufen im CI-Job `pruning-checkpoints` mit `--features prover-stwo` bzw. `--features backend-rpp-stark`.

### Public-Inputs-Encoding

- Byte-Layout ist in `vendor/rpp-stark/docs/PUBLIC_INPUTS_ENCODING.md` dokumentiert.
- Der Adapter `rpp/chain/src/zk/rpp_adapter/public_inputs.rs` nutzt dieselbe Little-Endian-Kodierung und Hashing-Strategie.

### Proof-ABI-Versionierung & Guardrails

- `PROOF_VERSION` ist in `vendor/rpp-stark/src/proof/types.rs` hinterlegt und steuert den Serialisierungsvertrag für Header,
  Transcript-Labels und Merkle-Bundles. Jede Änderung an `rpp/chain/src/zk/`, `rpp/proofs/`, den Prover-Backends unter
  `prover/` (inklusive `params/`-Artefakten) oder den Golden-Vectors in `vendor/rpp-stark/` erfordert einen Versionssprung.
- Auch testgetriebene Layout-Änderungen – z. B. angepasste Snapshots (`tests/snapshots/proof_*`), Fail-Matrix-Fakes oder neue
  Interop-Vektoren – müssen mit einem `PROOF_VERSION`-Bump und dokumentiertem Proof-Metadata-Update gekoppelt werden.
- Änderungen an Circuit-Artefakten (`prover/plonky3_backend/params/`, `prover/prover_stwo_backend/params/`) verlangen neben dem
  Versionssprung auch einen CHANGELOG-Eintrag mit explizitem PROOF_VERSION-Hinweis; der Guard schlägt fehl, sobald Circuit-Diffs
  ohne Versionserhöhung oder Changelog-Anker auftreten.
- Der Befehl `cargo xtask proof-version-guard --base origin/main` prüft diese Pfade und bricht ab, wenn die Konstanten nicht
  angepasst wurden. Nutze `--base <ref>`, wenn der Release-/Feature-Branch von einem anderen Stand als `origin/main` abzweigt.
  Der Guard liest beide Stände aus Git und gleicht die Werte aus `vendor/rpp-stark/src/proof/types.rs` und `firewood/src/proofs.rs`
  miteinander ab. Jeder Vendor-Refresh unter `vendor/rpp-stark/` (inklusive `vectors/` und Verifier-Code) gilt als proof-affecting
  und erfordert zwingend einen Bump; der CI-Job `proof-version-policy` bricht andernfalls ab.【F:xtask/src/release.rs†L1-L209】
- `cargo xtask proof-version-metadata` validiert zusätzlich, dass die Circuit-Metadaten für beide Backends die aktuelle
  `PROOF_VERSION` widerspiegeln: STWO liest `version` aus `prover/prover_stwo_backend/params/vk.json`, Plonky3 erwartet
  `metadata.proof_version` in den Setup-Dateien. Der CI-Job `proof-version-policy` führt den Check automatisch aus und
  blockiert Merges bei Drift.【F:xtask/src/release.rs†L1-L217】【F:xtask/src/main.rs†L3589-L3634】【F:xtask/src/main.rs†L5932-L6020】
- Pull-Requests, die Proof- oder ZK-Module anfassen, laufen automatisch durch den CI-Job `proof-version-policy`, der denselben
  Guard via `cargo xtask proof-version-guard` ausführt und bei Verstößen das Review blockiert.【F:.github/workflows/ci.yml†L1-L80】
- Dokumentiere jeden Bump in den Release Notes (`docs/release_notes.md`) und aktualisiere bei Bedarf zusätzliche Artefakte wie
  Telemetrie-Mappings oder Operator-Guides, damit Auditor:innen den ABI-Wechsel nachvollziehen können.

### Lasttests & Durchsatzgrenzen

- `cargo test -p rpp-chain --features "prover-stwo backend-rpp-stark" --test zk_load -- --nocapture` erzeugt parallelisierte
  Proof-Batches über STWO- und RPP-STARK-Artefakte, misst Latenzen/Throughput und erzwingt die erwarteten Size-Gate-Fehler bei
  übergroßen Beweisen (`RppStarkVerifyFailure::ProofTooLarge`). Die Suite nutzt einen STWO-Prover-Semaphor mit zwei gleichzeitigen
  Jobs sowie drei parallele RPP-Verifier-Läufe; der minimale Durchsatz-Floor liegt bei 0,1 Proofs/Sekunde und wird als Test-Assert
  geprüft.【F:tests/zk_load.rs†L1-L204】
- Nightly-CI führt die Suite automatisch im Job `zk-load-harness` aus, damit Größe- und Parallelitäts-Grenzen regressionssicher
  bleiben.【F:.github/workflows/nightly.yml†L168-L201】
- Wallet-Prover-Failover: Setze optional `wallet.prover.fallback_backend = "mock"` (oder einen anderen aktivierten Backendnamen)
  in der Wallet-Konfiguration, um Überlastungen des Primärbackends transparent auf einen sekundären Pfad umzulenken. Fallbacks
  werden nur bei Überlast-Signalen (`busy`, `timeout`) aktiviert und lassen Witness-Size-Grenzen unangetastet; Telemetrie
  (`wallet.prover.fallback{primary=…,fallback=…,stage=…,reason=…}`) und Warn-Logs markieren jeden Umschaltvorgang. Die neuen
  Fallback-Tests unter `rpp/wallet/src/engine/signing/prover.rs` simulieren Überlast auf `prepare`- und `prove`-Pfaden und
  verifizieren, dass die Sekundär-Backends greifen, während Size-Gates weiter enforced bleiben
  (`cargo test -p rpp-wallet --features prover-mock fallback_router_ -- --nocapture`).【F:rpp/wallet/src/engine/signing/prover.rs†L996-L1060】
- Die Drill `zk-penalty-guardrails` lässt sowohl RPP-STARK- als auch STWO-Backends eine verpasste Slot- und Double-Sign-Sequenz
  durchlaufen, verifiziert die Proofs und prüft, dass die Konsensus-Logs `applied slashing penalty` mit dem aktiven Backend labeln.
  Alarme müssen nach dem nächsten Blockabschluss wieder auf Grün springen; schlagen sie fehl, folge den unterstehenden
  Incident-Schritten zur Backend-Isolation.【F:tests/consensus/censorship_inactivity.rs†L222-L306】【F:.github/workflows/nightly.yml†L208-L224】

### Size-Gate-Mapping

- Proof-Header speichern die Obergrenze in KiB; der Node überträgt `max_proof_size_bytes` an den Verifier, der das Mapping mittels `ensure_proof_size_consistency` verifiziert.【F:tests/rpp_verifier_smoke.rs†L35-L66】【F:tests/rpp_verifier_smoke.rs†L107-L152】
- `ProofVerifierRegistry` konvertiert das Node-Limit in Bytes → KiB und lehnt Werte ab, die nicht in `u32` passen.【F:tests/rpp_verifier_smoke.rs†L35-L66】【F:tests/rpp_verifier_smoke.rs†L154-L183】
- Die Byte-Histogramme werden in fünf Buckets eingeteilt: `≤512 KiB`, `≤1 MiB`, `≤2 MiB`, `≤4 MiB`, `>4 MiB`. Sowohl erfolgreiche Prüfungen als auch Fehlversuche (inkl. Size-Gate-Fehler) aktualisieren `rpp_stark_proof_total_bytes{,_by_result}`, `rpp_stark_params_bytes`, `rpp_stark_public_inputs_bytes` und `rpp_stark_payload_bytes`, sodass Oversize-Versuche messbar bleiben.【F:rpp/runtime/node.rs†L120-L213】【F:rpp/runtime/node.rs†L4526-L4720】
- Überlange Artefakte liefern `RppStarkVerifyFailure::ProofTooLarge{max_kib,got_kib}`; Logs/Telemetrie enthalten `proof_bytes`, `size_bucket`, Parameter- und Payload-Größen. Beobachte `rpp_stark_proof_total_bytes_by_result{result="fail",proof_kind="consensus",le=…}` für Ausreißer oberhalb von 4 MiB.【F:rpp/runtime/node.rs†L4526-L4720】【F:rpp/runtime/node.rs†L4674-L4720】

### Fehlerbehandlung & Telemetrie

> **Alerting shortcut:** Der dedizierte Operations-Guide bündelt empfohlene
> Prometheus-Queries, Alertmanager-Regeln und Grafana-Panels für das
> `backend-rpp-stark`-Monitoring. Siehe
> [RPP-STARK Verifier Alert Operations](operations/zk_backends.md).

- `NodeInner::verify_rpp_stark_with_metrics` (implementiert in `rpp/runtime/node.rs`) ruft den Registry-Helper auf und emittiert strukturierte Logs (`valid`, `proof_bytes`, `verify_duration_ms`, Stage-Flags) mit Label `proof_backend="rpp-stark"` und `proof_kind` (z. B. `"transaction"`).
- Zusätzlich landen die Kennzahlen auf dem `telemetry`-Target. Erfolgreiche Prüfungen loggen `params_ok`, `public_ok`, `merkle_ok`, `fri_ok`, `composition_ok` sowie `params_bytes`, `public_inputs_bytes` und `payload_bytes`.
- Fehlerpfade nutzen `emit_rpp_stark_failure_metrics` (`rpp/runtime/node.rs`), das Byte-Größen sowie den Fehlertext protokolliert und `valid=false` setzt. Oversize- und Limit-Mismatch-Fälle tragen dieselben Byte-Felder und Buckets, wodurch Alerting-Regeln auf `result="fail"` aufsetzen können.【F:rpp/runtime/node.rs†L4526-L4720】【F:rpp/runtime/node.rs†L4649-L4720】
- Beispielausgaben:

  ```text
  INFO telemetry proof_backend="rpp-stark" proof_kind="transaction" valid=true params_ok=true public_ok=true merkle_ok=true fri_ok=true composition_ok=true proof_bytes=1234 params_bytes=256 public_inputs_bytes=64 payload_bytes=914 verify_duration_ms=42 "rpp-stark proof verification"
  WARN telemetry proof_backend="rpp-stark" proof_kind="transaction" valid=false proof_bytes=1234 params_bytes=256 public_inputs_bytes=64 payload_bytes=914 verify_duration_ms=42 error="cryptography error: verification failed" "rpp-stark proof verification failed"
  ```
- Zusätzlich zu den Logs werden Prometheus-kompatible Metriken über das `metrics`-Crate gemeldet:
  - Histogramme `rpp_stark_verify_duration_seconds`, `rpp_stark_proof_total_bytes`, `rpp_stark_params_bytes`, `rpp_stark_public_inputs_bytes` und `rpp_stark_payload_bytes` (Labels: `proof_backend`, `proof_kind`).
  - Counter `rpp_stark_stage_checks_total` mit Labels `proof_backend`, `proof_kind`, `stage` (`params`, `public`, `merkle`, `fri`, `composition`) und `result` (`ok`/`fail`).
  - Fehlerpfade aktualisieren dieselben Byte-Histogramme, sodass Ausreißer sichtbar bleiben.
- Gossip-Proof-Caches werden per Backend-Fingerprint namespacet; sobald ein Node mit einem anderen aktiven Backend startet, loggt er `p2p.proof.cache` mit `expected`/`previous` und leert die persistierten Digests, damit eingehende Proofs erneut gegen das frische Backend verifiziert werden.【F:rpp/p2p/src/pipeline.rs†L356-L425】【F:rpp/runtime/node_runtime/tests/gossip_bridge.rs†L100-L161】
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

### Proof-Cache-Sizing & Telemetrie

- Die Gossip-Proof-Persistenz ist auf 1 024 Einträge pro Backend limitiert (`PersistentProofStorage::with_capacity`), das älteste Element wird bei Überlauf im FIFO-Modus entfernt.【F:rpp/p2p/src/pipeline.rs†L831-L846】 Der Pfad bleibt über `config.proof_cache_dir` konfigurierbar, sodass Betreiber den Cache auf ein separates Volume legen können, falls größere Retentionswerte gebaut werden.
- Die Runtime exportiert `rpp.runtime.proof.cache.{hits,misses,evictions}` mit Label `cache=gossip-proof-cache`, womit Dashboards (Cache-Efficiency) und Alerts (`ProofCacheThrash` in `ops/alerts/zk/rpp_stark.yaml`) einen Thrash-Alarm auslösen, sobald die Hit-Rate unter 50 % sinkt und Evictions anziehen.【F:telemetry/schema.yaml†L21-L32】【F:telemetry/prometheus/cache-rules.yaml†L16-L37】【F:ops/alerts/zk/rpp_stark.yaml†L46-L71】

### Verifier-Stage-Flags & Gegenmaßnahmen

| Stage-Flag | Bedeutung | Typische Fehlersignale | Priorisierte Gegenmaßnahmen |
| --- | --- | --- | --- |
| `params_ok` | Hashvergleich zwischen Proof-Header und erwarteter Backend-Konfiguration (Parameter-Digest). | Log- bzw. Telemetrie-Einträge mit `error="...ParamsHashMismatch"` oder `params_ok=false`. | Prüfe Release-Artefakte (`scripts/build_release.sh` + `RPP_RELEASE_BASE_FEATURES`) und stelle sicher, dass die Binary mit den richtigen Features (`backend-rpp-stark`/`backend-plonky3`) gebaut wurde. Vergleiche `proof_version` und Parameter-Hashes mit `cargo xtask proof-metadata --format json`; der Test `cargo test --features backend-rpp-stark --test rpp_verifier_smoke -- --nocapture error_mapping_is_stable_display` reproduziert den Fehlerfall.【F:tests/rpp_verifier_smoke.rs†L73-L105】 |
| `public_ok` | Bindet kanonische Public Inputs an den Transcript-/Digest-Check. | `PublicInputMismatch`/`PublicDigestMismatch` im Fehlertext oder `public_ok=false`. | Extrahiere den Payload-Abschnitt aus dem Log (Hex/Base64) und spiele `cargo test --features backend-rpp-stark --test rpp_fail_matrix -- --nocapture public_digest_mismatch_maps_to_public_failure`, um Layout-Regressionen mit den Fail-Matrix-Fakes zu überprüfen. Validierte Public-Inputs-JSON (`vendor/rpp-stark/docs/PUBLIC_INPUTS_ENCODING.md`) gegen die betreffende Proof-Klasse.【F:tests/rpp_fail_matrix.rs†L100-L122】 |
| `merkle_ok` | Prüft Trace- und Composition-Merkle-Pfade gegen die im Header gemeldeten Wurzeln. | `MerkleVerifyFailed`/`TraceLeafMismatch` im Report, `merkle_ok=false`, oder Trace-Indizes (`trace_query_indices`) in der Telemetrie. | Sichere den Proof aus `/status/mempool` (`payload_bytes`) und führe `cargo test --features backend-rpp-stark --test rpp_fail_matrix -- --nocapture merkle_path_tampering_maps_to_trace_commit_failure` aus, um Merkle-Path-Tampering lokal zu vergleichen. Verifiziere, dass `proof_cache_dir` intakt ist und kein Dritt-Tool Pfade überschreibt.【F:tests/rpp_fail_matrix.rs†L70-L98】 |
| `fri_ok` | Ergebnis des FRI-Verifiers inkl. Query- & Layer-Budgets. | `FriVerifyFailed{issue=...}` im Report oder `fri_ok=false`. | Prüfe `max_proof_size_bytes` und FRI-Parameter via `ProofVerifierRegistry::with_max_proof_size_bytes`. Führe `cargo test --features backend-rpp-stark --test rpp_fail_matrix -- --nocapture fri_payload_offset_mismatch_maps_to_serialization_error` oder `scripts/test.sh --backend rpp-stark --integration` aus, um Query-Budgets gegen Golden Vectors zu vergleichen. Bei Vendor-Backends GPU-Override (`PLONKY3_GPU_DISABLE=1`) testen, um Hardware-Probleme auszuschließen.【F:tests/rpp_fail_matrix.rs†L124-L151】【F:scripts/test.sh†L44-L120】 |
| `composition_ok` | Vergleicht Composition-Polynome gegen deklarierte Commitments/Degrees. | `CompositionLeafMismatch`/`CompositionInconsistent` bzw. `composition_ok=false`. | Bewahre das Incident-Proof-Bundle, validiere die Witness-Dateien aus `vendor/rpp-stark/vectors/` mit `cargo test --features backend-rpp-stark --test interop_rpp_stark -- --nocapture interop_verify_golden_vector_ok` und fordere gegebenenfalls aktualisierte Circuit-Vektoren beim Release-Team an.【F:tests/interop_rpp_stark.rs†L1-L80】 |

*Hinweis:* Die Stage-Flags stammen aus dem strukturierten `VerifyReport` und werden unverändert an Log- und Telemetrieschichten weitergereicht. Bei Teilausfällen liefert `trace_query_indices` die FRI-Abfragepositionen, sodass Wiederholungen gezielt nachvollzogen werden können.【F:rpp/chain/src/zk/rpp_verifier/report.rs†L1-L86】【F:vendor/rpp-stark/src/proof/types.rs†L1138-L1224】 

### Proof-Replay & Backend-Umschaltung

- **Proof erneut ausführen:** Sichere den Proof-Blob (`payload_bytes`) aus den Incident-Logs und führe `cargo test --features backend-rpp-stark --test interop_rpp_stark -- --nocapture interop_verify_golden_vector_ok` aus, um denselben Beweis gegen die eingebetteten Golden Vectors zu prüfen. Die Test-Harness lädt `vendor/rpp-stark/vectors/stwo/mini/` und repliziert Stage-Checks lokal.【F:tests/interop_rpp_stark.rs†L1-L80】【F:vendor/rpp-stark/src/proof/mod.rs†L40-L160】【F:vendor/rpp-stark/tests/proof_lifecycle.rs†L16-L140】
- **Golden-Vectors und Regressionen:** `scripts/test.sh --backend rpp-stark --unit --integration` verifiziert alle Circuit-Familien inkl. Negativpfade. Verwende `--backend plonky3` analog für den Vendor-Pfad, falls ein Backend-Wechsel evaluiert wird.【F:scripts/test.sh†L44-L120】【F:scripts/test.sh†L286-L352】
- **Backend-Switch vorbereiten:** Baue alternative Artefakte mit `RPP_RELEASE_BASE_FEATURES="prod,backend-plonky3" scripts/build_release.sh` oder `cargo build --features backend-plonky3`. Deployments übernehmen den Wechsel nach einem kontrollierten Neustart; dokumentiere den Feature-Flip im Incident-Log.【F:scripts/build_release.sh†L10-L118】【F:scripts/build_release.sh†L204-L214】
- **Runtime-Parameter anpassen:** Passe `max_proof_size_bytes` oder `rollout.feature_gates.consensus_enforcement` in `config/node.toml` an und starte den Dienst neu, um neue Limits bzw. temporäre Enforcement-Ausnahmen zu übernehmen. Setze Schalter nach der Störung zurück und bestätige die Wirkung über `/status/node` (`backend_health.*`).【F:config/node.toml†L5-L71】【F:rpp/runtime/node.rs†L5043-L5164】【F:rpp/runtime/node.rs†L5416-L5460】

### Zero-data-loss backend switch procedure

**Prerequisites**

- Stelle sicher, dass der alternative Backend-Build mit den richtigen Feature-Flags vorliegt (z. B. `backend-plonky3` oder `backend-rpp-stark`) und ein Integrationslauf (`scripts/test.sh --backend <target> --unit --integration`) ohne Fehlermeldungen durchläuft.
- Prüfe, dass die aktiven Limits (`max_proof_size_bytes`, `rollout.feature_gates.consensus_enforcement`) in `config/node.toml` mit den Ziel-Artefakten kompatibel sind und dokumentiere den aktuellen Wert im Incident-Log, um spätere Rollbacks nachvollziehen zu können.【F:config/node.toml†L5-L71】
- Stelle sicher, dass Validatoren finalisiert haben und keine ungeprüften Proofs im Mempool hängen, indem du `/status/mempool` und `backend_health.*` prüfst. So vermeidest du, dass unbestätigte Artefakte während des Wechsels verworfen werden.【F:rpp/rpc/api.rs†L1440-L2406】【F:rpp/runtime/node.rs†L5416-L5460】

**Schritte für kontrollierten Neustart**

1. **Konfigurationsänderung vorbereiten:** Passe den Backend-Feature-Flip in der Build- oder Deployment-Pipeline an (z. B. `RPP_RELEASE_BASE_FEATURES="prod,backend-plonky3"`) und lege eine Kopie der aktuellen `config/node.toml` mit Versions-Hash im Change-/Incident-Log ab.【F:scripts/build_release.sh†L10-L118】
2. **Node sauber stoppen:** Stoppe den Validator nach Abschluss des aktuellen Slots/Heights (z. B. via Service-Manager), damit gepufferte Proofs persistiert sind.
3. **Binary/Container austauschen:** Rolle das neue Artefakt aus und stelle sicher, dass der Dienst mit den aktualisierten Feature-Flags startet.
4. **Konfiguration anwenden:** Lade die angepasste `config/node.toml` (inkl. aktualisiertem `max_proof_size_bytes` falls nötig) und führe einen Neustart durch. Verifiziere unmittelbar nach dem Start, dass `backend_health.<target>.verifier.accepted` ansteigt und `valid=true`-Logs für neue Proofs erscheinen.【F:rpp/runtime/node.rs†L5416-L5460】
5. **Post-Checks & Dokumentation:** Erfasse `GET /status/node` und relevante Telemetrie-Panels als Artefakte, notiere die Slot-/Height-Marke des Wechsels und aktualisiere das Incident-Log mit dem erfolgreichen Flip. Führe unmittelbar nach dem Neustart `tools/backend_switch_check.sh --url http://<host>:<port> --backend <ziel>` aus, um sicherzustellen, dass `backend_health.<ziel>.verifier` steigt und neue Proofs tatsächlich auf dem frischen Backend landen. Alternativ lässt sich derselbe Check automatisiert über `cargo test --features integration --test node_lifecycle -- backend_switch_routes_proofs_to_active_backend` ausführen, falls eine lokale Simnet-Umgebung zur Verfügung steht.

**Rolling Deploy ohne Datenverlust**

1. **Canary-Knoten aktualisieren:** Wähle einen Validator oder ein kleines Shard-Subset, deploye das neue Backend und verifiziere Proof-Akzeptanz (`backend_health.<target>.verifier.accepted` steigt, keine `valid=false`-Spitzen).
2. **Staggered rollout:** Aktualisiere die übrigen Nodes in kleinen Batches; zwischen den Batches sicherstellen, dass Finality-Gaps stabil bleiben und keine Mempool-Drops auftreten (Monitor `finality_lag_slots` und `backend_health.*`).
3. **Cluster-weite Bestätigung:** Nach Abschluss bestätigen, dass alle Nodes denselben Backend-Status melden und die Telemetrie-Histogramme (`*_proof_total_bytes`, `*_verify_duration_seconds`) keine Regressionen zeigen.

**Rollback**

- Halte den vorherigen Build und die gesicherte `config/node.toml` bereit. Wenn Proof-Rejections oder Finality-Gaps nach dem Flip auftreten, stelle den vorherigen Binary-Stand wieder her, setze die Konfiguration zurück und starte den Dienst neu. Validere, dass `backend_health.<previous>.verifier.accepted` erneut steigt und dokumentiere den Zeitpunkt des Rollbacks im Incident-Log.
- Bei Rolling Deployments sofort zum letzten stabilen Backend zurückkehren, falls der Canary Fehler zeigt; stoppe weitere Batches und verwirf nur den canary-spezifischen Proof-Cache, um Datenverlust zu vermeiden.

### Incident Runbook: rpp-stark verification failures

#### Detection

- Warnungen mit `proof_backend="rpp-stark"` und `valid=false` markieren fehlgeschlagene Prüfungen direkt im Logstream sowie im Telemetrie-Target und enthalten Stage-Flags bzw. Fehlermeldung für das On-Call-Playbook.【F:docs/zk_backends.md†L29-L43】
- `/status/node` zeigt unter `backend_health.rpp-stark.verifier.rejected` den Zähler für verworfene Beweise; die Werte stammen aus dem `VerifierMetricsSnapshot` und steigen bei jedem Fehlversuch.【F:rpp/runtime/node.rs†L5416-L5460】【F:rpp/proofs/proof_system/mod.rs†L328-L392】
- Die Prometheus-Metriken `rpp_stark_stage_checks_total{result="fail"}` und `rpp_stark_verify_duration_seconds` liefern Stage-spezifische Fehler- und Latenzsignale, die auch für Alerting-Regeln genutzt werden können.【F:rpp/runtime/telemetry/metrics.rs†L476-L520】

#### Manual mitigation

1. Hole das aktuelle Proof-Backlog über `GET /status/mempool`, ermittle Hash, Backend und Payload-Größe des betroffenen Artefakts und vergleiche sie mit den Logeinträgen – so lässt sich feststellen, ob der Fehler reproduzierbar ist oder bereits aus dem Mempool verschwunden ist.【F:rpp/rpc/api.rs†L1440-L2406】【F:rpp/runtime/node.rs†L5461-L5537】
2. Prüfe die lokale Konfiguration auf ein zu niedriges `max_proof_size_bytes`. Der Parameter wird beim Start in den Verifier übertragen; sobald Beweise die Grenze überschreiten, blockiert `ensure_proof_size_consistency` den Start oder markiert eingehende Artefakte als zu groß. Passe den Wert in der Node-Konfiguration an (z. B. `config/node.toml`) und starte den Dienst neu, damit der Verifier das neue Limit übernimmt.【F:config/node.toml†L5-L25】【F:rpp/runtime/config.rs†L1529-L1964】【F:rpp/proofs/proof_system/mod.rs†L360-L412】【F:tests/node_lifecycle.rs†L120-L192】
3. Dokumentiere den Vorfall im Incident-Log und beobachte `backend_health.rpp-stark.verifier.accepted` sowie die Stage-Counter, um zu bestätigen, dass nach der Anpassung wieder erfolgreiche Verifikationen eintreffen.【F:rpp/runtime/node.rs†L5416-L5460】【F:rpp/proofs/proof_system/mod.rs†L328-L392】【F:rpp/runtime/telemetry/metrics.rs†L476-L520】

#### Fallback paths

- **Switch to the vendor backend:** Baue oder deploye eine Binary mit `--features prod,backend-plonky3` (bzw. setze `RPP_RELEASE_BASE_FEATURES="prod,backend-plonky3"` für das Release-Skript), stoppe den Dienst und starte ihn mit dem neuen Artefakt. Der Operator-Guide beschreibt die Build-Schritte; dokumentiere den Wechsel im Change-Log und überwache anschließend `backend_health.plonky3.*` für die Erfolgsquoten.【F:docs/rpp_node_operator_guide.md†L1-L68】
- **Temporarily disable proof enforcement:** Setze `rollout.feature_gates.consensus_enforcement = false` in der aktiven Konfiguration, speichere die Datei und führe einen kontrollierten Neustart durch. Dadurch überspringt die Runtime Sanktionen und Validierungen, bis der Fix bereitsteht. Nach Abschluss der Nacharbeiten muss der Schalter wieder auf `true` stehen, gefolgt von einem erneuten Neustart, um die Verifikation zu reaktivieren.【F:config/node.toml†L57-L71】【F:rpp/runtime/node.rs†L5043-L5164】【F:tests/node_lifecycle.rs†L120-L192】
- **Escalate to release engineering:** Wenn weder Parameter-Anpassungen noch Backend-Wechsel helfen, eskaliere an das Release-Team und lass Hotfix-Builds mit aktualisierten Circuit-Vektoren signieren. Halte das Playbook gemeinsam mit `RELEASE.md` synchron, damit neue Proof-Versionen inklusive Artefakt-Hashes und Checksummen ausgerollt werden können.

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
- Die Wallet-Prover-Queues emittieren das Gauge `wallet.prover.queue.depth{backend}` (inklusive `backend="mock"`/`"stwo"`) und blockieren neue Jobs bei ausgeschöpften Semaphoren (`wallet.prover.max_concurrency`). Alerts feuern bei einer Tiefe > 2 über 10 Minuten, p95-Latenz > 3 Minuten oder Fehlerraten > 20 % pro Backend; sobald das Backlog abgearbeitet ist, fällt das Gauge wieder auf 0.【F:rpp/wallet/src/engine/signing/prover.rs†L271-L338】【F:tests/zk_alert_probe.rs†L32-L73】【F:ops/alerts/zk/stwo.yaml†L31-L83】
- Ressourcengrenzen lassen sich per `wallet.prover.cpu_quota_percent` (CPU-Kontingent in %) und `wallet.prover.memory_quota_bytes` (Bytes; `0` nutzt den aktiven cgroup-Limit-Wert) erzwingen. `wallet.prover.limit_warn_percent`, `.limit_backoff_ms` und `.limit_retries` steuern Warnschwellen, Backoff und maximale Drosselversuche; Warnungen und Throttles landen als `wallet.prover.resource.warning`/`wallet.prover.resource.throttled` im Metrics-Endpunkt, bevor neue Jobs mit `Busy` abbrechen.【F:rpp/wallet/src/engine/signing/prover.rs†L19-L188】【F:rpp/wallet/src/config/wallet.rs†L262-L334】【F:rpp/wallet/src/config/wallet.rs†L480-L555】
- Runbook-Hinweis: Bei Queue- oder Latenz-Alerts blockierte Drafts prüfen, Backend-Logs auf Dauercodes sichten, `wallet.prover.max_concurrency` temporär senken bzw. `wallet.prover.timeout_secs` erhöhen und die Wallet mit geleertem Entwurfs-Cache neu starten. Hält der Alarm länger als 15 Minuten an, Backend wechseln oder an das Release-Team eskalieren.【F:ops/alerts/zk/stwo.yaml†L31-L83】【F:rpp/wallet/src/engine/signing/prover.rs†L271-L338】

### Offene Aufgaben

- GPU-Benchmarks ausrollen und zusätzliche Nightly-Profile aufnehmen.
- Key-Distribution-Automatisierung für Multi-Region-Deployments ausarbeiten (siehe Runbook-Follow-ups).【F:docs/runbooks/plonky3.md†L1-L200】
