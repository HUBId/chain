# `rpp-node` Operator Guide

This guide documents the CLI tooling that ships with the repository. The
`rpp-node` binary hosts the runtime launchers for every supported mode and the
validator maintenance subcommands. Operators should run `cargo run -p rpp-chain
-- …` for configuration checks, dry-run validation, and validator tooling—the
stub binary exercises the shared CLI surface without booting the runtime. The
`rpp-node` binary and its mode-specific entry points remain reserved for
production deployments and on-host supervisors. No standalone `rpc-cli` tool
exists in this workspace—the shipped operator interface is the unified CLI plus
the REST/RPC workflows exposed by the running node.

> **Phase 2 update:** The `backend-plonky3` feature now enables the vendor
> Plonky3 prover/verifier pipeline. Production builds may target either the
> STWO (`prover-stwo`/`prover-stwo-simd`) or Plonky3 backend; only the
> deterministic mock backend remains blocked in release artefacts. Use the
> release pipeline checklist to verify that binaries are compiled with one of
> the production backends and that mock features are absent from build metadata.
> [`feature_guard.rs`](../rpp/node/src/feature_guard.rs) ·
> [`build_release.sh`](../scripts/build_release.sh) ·
> [`verify_release_features.sh`](../scripts/verify_release_features.sh) ·
> [`ensure_prover_backend`](../rpp/node/src/lib.rs) ·
> [Release pipeline checklist](../RELEASE.md#release-pipeline-checklist) ·
> [Phase‑2 Acceptance Checklist](./runbooks/phase2_acceptance.md)
> · [Plonky3 runbook](./runbooks/plonky3.md)
> · [Incident Runbook: rpp-stark verification failures](./zk_backends.md#incident-runbook-rpp-stark-verification-failures)

## Build and install the CLI

Compile the binary with the release profile and select the backend that matches
the deployment tier. The build installs the multiplexer binary at
`target/release/rpp-node` and enables validator functionality required in
staging and production deployments.【F:docs/validator_quickstart.md†L24-L56】

```sh
# STWO backend
cargo build --release -p rpp-node --no-default-features --features prod,prover-stwo

# Plonky3 backend
cargo build --release -p rpp-node --no-default-features --features prod,backend-plonky3
```

The automated release pipeline exports `RPP_RELEASE_BASE_FEATURES` before
invoking `scripts/build_release.sh`. Point the variable to
`"prod,prover-stwo"`, `"prod,prover-stwo-simd"`, or `"prod,backend-plonky3"`
depending on the backend you intend to ship; the script always forces
`--no-default-features --features "$RPP_RELEASE_BASE_FEATURES"` so every
published artifact includes a production prover and the mock backend remains
disabled.【F:.github/workflows/release.yml†L115-L158】【F:scripts/build_release.sh†L1-L118】
Local builds should mirror the same flag set shown in
`scripts/build_release.sh` to avoid shipping binaries that fail at runtime due
to a missing production backend.

The helper `scripts/verify_release_features.sh` checks the compiled metadata and
fails when the mock prover slips into the feature list; run it as part of
pre-release validation. The compile-time guard mirrors this behaviour by
preventing `backend-plonky3` and `prover-mock` from being enabled at the same
time.【F:scripts/verify_release_features.sh†L1-L146】【F:rpp/node/src/feature_guard.rs†L1-L5】

Keep the repository cloned on the host to rebuild quickly when upgrades ship.

## Runtime launchers

The `rpp-node` binary dispatches to four runtime modes and accepts the shared
runtime options (configuration paths, telemetry overrides, dry runs, log
formatting, and networking flags).【F:rpp/node/src/main.rs†L28-L75】【F:rpp/node/src/lib.rs†L35-L314】

```text
rpp-node node [runtime options]
rpp-node wallet [runtime options]
rpp-node hybrid [runtime options]
rpp-node validator [runtime options] [validator subcommand]
```

Pass `--config`/`--wallet-config` to target custom configuration files or rely
on the precedence chain described in the validator quickstart when the defaults
are sufficient.【F:docs/validator_quickstart.md†L62-L111】 Use `cargo run -p
rpp-chain -- <mode> --dry-run --config <path>` to validate configuration without
starting long-running tasks; the CLI exits after bootstrap so operators can gate
deployments in CI while the production binary stays reserved for supervisors and
release artefacts.【F:docs/validator_quickstart.md†L195-L210】

> **Networking reminder:** Whenever a runtime mode changes the node profile,
> re-apply the [gossip tuning checklist](./networking.md#gossip-tuning-checklist)
> to confirm that gossip bandwidth, allowlists, and replay windows align with
> the new configuration before promoting the change to staging or production.

### Plonky3 backend (Phase 2)

`backend-plonky3` aktiviert jetzt den produktiven Plonky3-Prover und -Verifier.
Die Wallet- und Node-Adapter erzeugen und prüfen Vendor-Beweise über dieselben
Traits wie das STWO-Backend, sodass Keygen-, Prover- und Verifier-Hooks im
Produktionspfad identisch orchestriert werden.【F:rpp/proofs/plonky3/prover/mod.rs†L19-L520】【F:rpp/proofs/plonky3/verifier/mod.rs†L1-L212】

Das [Plonky3-Runbook](./runbooks/plonky3.md) beschreibt den vollständigen
Operator-Workflow:

- Circuit-Caches vorbereiten (`rpp-node` legt Proving-/Verifying-Keys im
  Artefaktverzeichnis ab und spiegelt den Zustand über
  `backend_health.plonky3.*`).
- Proof-Generierung und -Verifikation überwachen (`rpp.runtime.proof.generation.duration`
  / `.size` / `.count` mit `backend="plonky3"`, `proof_kind="transaction|state|pruning|consensus"`
  sowie `rpp_stark_verify_duration_seconds` und die zugehörigen Byte-Histogramme
  mit `proof_kind="*"`).【F:rpp/runtime/telemetry/metrics.rs†L426-L520】
- Acceptance-Kriterien prüfen: die Phase‑2-Grenzwerte orientieren sich an den
  Messwerten aus `tools/simnet/scenarios/consensus_quorum_stress.ron` und sind in
  `performance/consensus_proofs.md` dokumentiert.

Das Nightly-Szenario `consensus-quorum-stress` treibt den Prover mit hoher
Validator- und Witness-Last sowie absichtlich manipulierten VRF-/Quorum-Daten
an. `scripts/analyze_simnet.py` wertet die JSON-Summary aus, bricht bei
Überschreitung der p95-Grenzen ab und meldet unerwartete Tamper-Erfolge. Die
Gegenüberstellung von Erfolgs- und Fehlerpfaden ist ebenfalls im Runbook
festgehalten.【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】【F:scripts/analyze_simnet.py†L1-L200】【F:docs/performance/consensus_proofs.md†L1-L160】

Die Konsensus-Beweise werden zusätzlich softwareseitig gehärtet: `ConsensusCircuit`
im Backend bindet VRF-Ausgaben, -Beweise und Quorum-Digests an den Block-Hash,
die Wallet-Adapter lassen nur valide Zeugen in die Prover-Pipeline, und der
Verifier rekonstruiert die Bindings vor der Proof-Prüfung. Regressionstests in
`tests/consensus/plonky3_consensus.rs` sowie im Backend sichern diese Checks gegen
Regressionen.【F:prover/plonky3_backend/src/circuits/consensus.rs†L1-L245】【F:rpp/proofs/plonky3/prover/mod.rs†L123-L520】【F:rpp/proofs/plonky3/verifier/mod.rs†L1-L212】【F:tests/consensus/plonky3_consensus.rs†L1-L134】

Grafana-Panels unter `docs/dashboards/consensus_proof_validation.json`
visualisieren diese Kennzahlen (Latenzen, Fehlerraten, Circuit-Cache-Größe) für
Plonky3 und werden vom CI-Dashboard-Lint überprüft. Binde die Panels in das
Produktions-Dashboard ein, um Phase‑2-Abnahmekriterien sichtbar zu machen.【F:docs/dashboards/consensus_proof_validation.json†L1-L120】

Kombiniere `backend-plonky3` nicht mit dem `prover-mock`-Feature; der Guard
erzwingt weiterhin die Trennung zwischen deterministischen Test-Fixtures und
produktiven Vendor-Artefakten.【F:rpp/node/src/feature_guard.rs†L1-L5】

## Validator tooling

Invoke validator-specific helpers through `cargo run -p rpp-chain -- validator`.
Subcommands cover
VRF rotation, telemetry diagnostics, and uptime proof management, all backed by
the active node configuration.【F:rpp/node/src/main.rs†L48-L183】 Detailed
workflows—including sample invocations and expected output—live in the
[validator tooling guide](./validator_tooling.md).【F:docs/validator_tooling.md†L14-L137】

### Snapshot streaming CLI

`cargo run -p rpp-chain -- validator snapshot` wraps the `/p2p/snapshots` RPCs so operators can
start, resume, inspect, and cancel consumer sessions without constructing HTTP
requests by hand. The CLI resolves the active validator configuration, derives
the RPC base URL from `network.rpc.listen`, and automatically attaches the
configured bearer token unless an explicit `--auth-token` override is provided.

```text
$ cargo run -p rpp-chain -- validator snapshot start --peer 12D3KooWexamplePeer
snapshot session started:
  session: 42
  peer: 12D3KooWexamplePeer
  root: deadbeefcafebabe
  last_chunk_index: none
  last_update_index: none
  last_update_height: none
  verified: unknown
  error: none

$ cargo run -p rpp-chain -- validator snapshot status --session 42
snapshot status:
  session: 42
  peer: 12D3KooWexamplePeer
  root: deadbeefcafebabe
  last_chunk_index: none
  last_update_index: none
  last_update_height: none
  verified: unknown
  error: none

$ cargo run -p rpp-chain -- validator snapshot resume --session 42 --peer 12D3KooWexamplePeer --plan-id plan-2024-05-18
snapshot session resumed:
  session: 42
  peer: 12D3KooWexamplePeer
  root: deadbeefcafebabe
  last_chunk_index: 12
  last_update_index: 3
  last_update_height: 256
  verified: false
  error: none

$ cargo run -p rpp-chain -- validator snapshot cancel --session 42
snapshot session 42 cancelled
```

Errors propagate directly from the RPC surface so operators receive the HTTP
status code and body when a request fails (for example: `RPC returned 500:
intentional failure`). The behaviour replaces the manual `curl` workflows, adds
token management, and prints structured output for incident logs and the
Phase‑3 artefaktablage.【F:rpp/node/src/main.rs†L118-L310】【F:docs/runbooks/phase3_acceptance.md†L8-L62】 Dokumentiere jede
Snapshot-Intervention im [On-Call-Handbuch](./runbooks/oncall.md#snapshot-recovery)
und halte die Metriken parallel über das [Observability-Runbook](./runbooks/observability.md#snapshot-cli-diagnose) fest, damit
Audit- und Dashboard-Belege synchron bleiben.【F:docs/runbooks/oncall.md†L21-L56】【F:docs/runbooks/observability.md†L6-L170】 Die Panels aus
`pipeline_overview.json`, `pipeline_proof_validation.json` und `vrf_overview.json`
visualisieren dieselben Fortschritts- und Fehlerindikatoren, die die CLI als
Text ausgibt, und sind verpflichtende Artefakte für die Phase‑3-Abnahme.【F:docs/dashboards/pipeline_overview.json†L200-L260】【F:docs/dashboards/pipeline_proof_validation.json†L1-L60】【F:docs/dashboards/vrf_overview.json†L1-L60】

### Snapshot verification CLI

`cargo run -p rpp-chain -- validator snapshot verify` kapselt den Offline-Verifier aus
`tools/snapshot-verify` und nutzt die Validator-Konfiguration, um Manifest,
Signatur, Chunk-Verzeichnis und Verifierschlüssel automatisch aufzulösen. Ohne
Overrides liest der Befehl `<snapshot_dir>/manifest/chunks.json`, erwartet die
Signatur nebenan als `chunks.json.sig`, prüft `<snapshot_dir>/chunks` und leitet
den Ed25519-Schlüssel aus `timetoke_snapshot_key_path` ab. Optional kannst du
`--manifest`, `--signature`, `--chunk-root`, `--output` und `--public-key`
verwenden, um einzelne Pfade bzw. einen alternativen Public Key zu setzen.【F:rpp/node/src/main.rs†L140-L227】 Für eine praktische
Übung inklusive Smoke-Fixtures und Artefakt-Checks folge dem
[Phase‑A Operator Lab](training/phaseA_operator_lab.md).

> **Hinweis:** Die Runtime streamt keine Snapshots mehr, wenn die
> zugehörige `.sig`-Datei fehlt oder kein gültiges Base64 enthält. Stelle bei
> jeder Veröffentlichung sicher, dass Payload und Signatur gemeinsam rotiert
> werden (z. B. durch `rename(2)` auf ein vorbereitetes Verzeichnis), damit
> Konsumenten keine unsignierten Manifeste sehen.

```text
$ cargo run -p rpp-chain -- validator snapshot verify --config config/validator.toml
{
  "manifest_path": "./data/snapshots/manifest/chunks.json",
  "signature_path": "./data/snapshots/manifest/chunks.json.sig",
  "public_key_path": "./keys/timetoke_snapshot.toml",
  "chunk_root": "./data/snapshots/chunks",
  "signature": {
    "algorithm": "ed25519",
    "manifest_digest": "…",
    "public_key_fingerprint": "…",
    "signature_valid": true,
    "error": null
  },
  "summary": {
    "segments_total": 1,
    "verified": 1,
    "checksum_mismatches": 0,
    …
  },
  "errors": []
}
```

Bei einer Abweichung liefert der Befehl weiterhin den JSON-Report, beendet sich
aber mit Exit-Code `3`, sodass CI-Jobs und Runbooks zwischen Signaturfehlern
(Exit-Code `2`) und tatsächlichen Chunk-Abweichungen unterscheiden können.【F:rpp/node/src/main.rs†L210-L227】【F:rpp/node/tests/snapshot_verify.rs†L1-L123】 Dokumentiere die Reports als Teil der
Snapshot-Abnahme und bewahre sie gemeinsam mit den Release-Artefakten auf.

### Consensus proof metadata expectations

Finality proofs now encode the epoch/slot context, VRF proofs, and quorum
evidence roots inside the public inputs. Operators must ensure that
`consensus.metadata` in block production includes:

- `epoch`/`slot` counters that match the fork-choice state machine.
- Hex-encoded `quorum_bitmap_root` and `quorum_signature_root` digests from the
  aggregated vote sets.
- Vollständige `vrf_entries` inklusive Randomness, Pre-Output, Proof, Public
  Key sowie Poseidon-Metadaten (`Digest`, `Last Block Header`, `Epoch`,
  `Tier Seed`) für jede Validator:in im Zertifikat. `Last Block Header` muss dem
  Zertifikats-`block_hash` entsprechen und die `Epoch`-Zeichenkette dem
  exportierten `epoch`-Zähler. Ältere Clients können die bisherigen
  `vrf_outputs`/`vrf_proofs` aus diesen Einträgen ableiten, solange sie das
  Version-Flag `version=2` setzen.

Setze bei RPC-Checks nach Möglichkeit `version=3`, um die strukturierten
Einträge inklusive Public Keys und Poseidon-Digests zu erhalten. Temporäre
Kompatibilitäts-Pipelines dürfen weiterhin `version=2` anfordern, sollten aber
das Downstream-Mapping aus `vrf_entries` dokumentieren, um den Wechsel
nachvollziehbar zu halten.

Missing or inconsistent values cause the verifier to reject the consensus proof
bundle. The host now rejects VRF proof strings that do not expand to exactly
`crate::vrf::VRF_PROOF_LENGTH` bytes before the prover is invoked, so truncated
or padded transcripts surface as immediate metadata errors. Double-check the
witness payload when diagnosing failed block imports.【F:docs/consensus/finality_proof_story.md†L33-L44】

Release-Builds listen Circuit-Versionen, Constraint-Zählungen und unterstützte Backends
in den [Release-Notizen](release_notes.md); ziehe die Tabelle bei Audits oder
Rollback-Plänen hinzu, um sicherzustellen, dass Operator:innen identische Proof-Artefakte
ausrollen.【F:docs/release_notes.md†L1-L160】

### Snapshot verifier workflow

Nutze zwei Pfade, um Snapshot-Bundles vor der Freigabe zu prüfen:

1. **CI/Smoke-Run:** `cargo xtask snapshot-verifier` erzeugt ein synthetisches
   Bundle unter `target/snapshot-verifier-smoke/`, signiert das Manifest und
   führt `snapshot-verify` samt Aggregationsreport aus. Der Job `snapshot-verifier`
   im CI spiegelt denselben Ablauf und lädt das Artefakt (`snapshot-verify-report.json` +
   `.sha256`) hoch, damit Reviewer:innen den Gate-Status nachvollziehen können.【F:xtask/src/main.rs†L220-L318】【F:.github/workflows/ci.yml†L369-L397】
2. **Produktives Release:** Beim Verpacken laufen `scripts/build_release.sh` und der
   Release-Workflow `Build <target>` automatisch `snapshot-verify` für jedes reale
   Manifest. Stelle den Verifierschlüssel via `SNAPSHOT_MANIFEST_PUBKEY_HEX` bereit und
   finde die Reports anschließend unter `dist/artifacts/<target>/snapshot-verify-report.json`
   inklusive `.sha256`. Vergleiche den Hash (`sha256sum .../snapshot-verify-report.json`)
   mit dem Eintrag im Release-Notes-Abschnitt „Snapshot verifier attestation“.【F:scripts/build_release.sh†L273-L348】【F:.github/workflows/release.yml†L150-L233】

Bewahre die Einzelreports (`*-verify.json`) gemeinsam mit dem Aggregat auf, damit
Auditor:innen das Ergebnis pro Manifest nachvollziehen können.

### WORM export validation

Der Audit-Log-Export lässt sich lokal und in CI verifizieren:

- `cargo xtask test-worm-export` erzeugt unter `target/worm-export-smoke/`
  einen signierten Audit-Eintrag (`worm/*.json`), die Retention-Metadaten und die
  Summary `worm-export-summary.json`. Die Summary bestätigt, dass jede Signatur
  mit dem erzeugten Key-Set überprüft wurde (`signature_valid=true`).【F:xtask/src/main.rs†L120-L318】
- CI (`worm-export-smoke`) und Nightly (`worm-export`) veröffentlichen das
  Artefakt `worm-export-smoke` mitsamt Summary, damit Auditor:innen Signaturen,
  Retention-Fenster und erzeugte JSON-Objekte prüfen können.【F:.github/workflows/ci.yml†L360-L387】【F:.github/workflows/nightly.yml†L10-L24】

Vor Produktionsexports: Stimme die endgültigen WORM-Endpoints mit Security &
Compliance ab und dokumentiere die Objekt-Storage-Konfiguration in den
Freigabeunterlagen.

### Phase 2 consensus proof validation checks

Phase 2 verlangt nachvollziehbare Belege, dass manipulierte VRF-/Quorum-Daten an
der Validator-Schnittstelle scheitern. Nutze zusätzlich die
[Plonky3 Production Validation Checklist](./testing/plonky3_experimental_testplan.md#4-production-sign-off-checklist),
um die erforderlichen Artefakte für das Freigabeprotokoll abzuhaken.【F:docs/testing/plonky3_experimental_testplan.md†L1-L121】

#### Known-good vs. tampered replay drill

Nutze den Phase‑2-Workflow, um sowohl einen gültigen Block als auch abgelehnte
Manipulationen zu dokumentieren:

1. **Bekannten guten Block erzeugen.** `cargo xtask test-consensus-manipulation`
   (Phase‑2-Neuzugang im CLI) baut zunächst ein Konsenszertifikat mit gültigem
   Witness, verifiziert den Proof gegen den aktiven Backend-Verifier und nutzt
   erst danach Mutationen. Aktiviere die gewünschten Backends mit
   `--features backend-plonky3 --no-default-features` bzw.
   `XTASK_NO_DEFAULT_FEATURES=1 XTASK_FEATURES="prod,prover-stwo"`. Der Lauf
   muss die "baseline consensus proof should verify"-Assertions erreichen – sie
   bestätigen, dass der Drill mit einem bekannten guten Block startet, bevor
   Manipulationen injiziert werden.【F:xtask/src/main.rs†L144-L190】【F:tests/consensus/consensus_certificate_tampering.rs†L110-L198】

2. **Manipulierten Replay auslösen.** Im Anschluss permutiert der Test
   automatisch VRF-Einträge sowie die Quorum-Roots und erwartet Verifier-Fehler.
   Alternativ lässt sich das Phase‑2-Simnet-Szenario `consensus_quorum_stress`
   per `cargo run -p simnet -- --scenario ... --artifacts-dir ...` starten, um
   valide und manipulierte Blöcke unter Produktionslast gegeneinander antreten
   zu lassen.【F:tests/consensus/consensus_certificate_tampering.rs†L128-L222】【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】

3. **Logs und RPCs auswerten.** Tamper-Erfolge müssen mit Fehlern wie
   `consensus witness participants do not match commit set` und
   `local consensus proof rejected by verifier` im Log enden; die Simnet-Läufe
   schreiben sie nach `target/simnet/consensus-quorum/node.log`.
   Ergänzend zeigt `GET /status/consensus`, ob der Drill einen gültigen Block
   (`quorum_reached=true`, monotone `round`) oder eine Ablehnung
   (`quorum_reached=false`, Fehlergrund in den Logs) produziert hat.【F:rpp/runtime/types/block.rs†L2280-L2314】【F:rpp/runtime/node.rs†L6323-L6466】【F:rpp/rpc/api.rs†L2336-L2344】

4. **Metriken und Nachweise sichern.** Exportiere Prometheus/Grafana-Schnappschüsse
   für `consensus_vrf_verification_time_ms` und
   `consensus_quorum_verifications_total`, um Phase‑2-Limits zu belegen. Das
   Observability-Runbook führt die erforderlichen Artefakte auf.【F:rpp/runtime/telemetry/metrics.rs†L60-L339】【F:docs/dashboards/consensus_grafana.json†L1-L200】【F:docs/runbooks/observability.md†L27-L69】

5. **Freigabe-Checkliste abhaken.** Ergänze die Ergebnisse im
   [Phase‑2 Acceptance Checklist](./runbooks/phase2_acceptance.md), damit
   Auditor:innen vor Release-Promotion prüfen können, ob alle Guardrails greifen.
   Die Checkliste erwartet verlinkte Logs, RPC-Snapshots und Dashboard-Beweise
   für jede Manipulationsprüfung.【F:docs/runbooks/phase2_acceptance.md†L1-L39】

> 💡 Ergänze jeden Testlauf in der [Observability-Checkliste](./runbooks/observability.md#phase-2-consensus-proof-audits)
> und verlinke die Log-/Dashboard-Screenshots, damit Auditor:innen die Belege
> schnell nachvollziehen können.

Common tasks include:

```sh
# Rotate VRF keys using the configured secrets backend
cargo run -p rpp-chain -- validator vrf rotate --config config/validator.toml

# Inspect collector health by querying the validator telemetry endpoint
cargo run -p rpp-chain -- validator telemetry --rpc-url http://127.0.0.1:7070 --auth-token $RPP_RPC_TOKEN --pretty

# Submit and inspect uptime proofs via the validator RPC
cargo run -p rpp-chain -- validator uptime submit --wallet-config config/wallet.toml --auth-token $RPP_RPC_TOKEN
cargo run -p rpp-chain -- validator uptime status --rpc-url http://127.0.0.1:7070 --auth-token $RPP_RPC_TOKEN --json
```

**OTLP failover:** Set `rollout.telemetry.failover_enabled = true` and populate
`secondary_endpoint`/`secondary_http_endpoint` to keep exporters online when the
primary collector is misconfigured. The runtime logs `failed over to secondary`
per sink and increments `telemetry_otlp_failures_total{phase="init_failover"}`
so dashboards can distinguish successful failovers from hard failures. TLS
material is validated before attempting the primary endpoint; malformed
certificates trigger the failover path while keeping the node running.【F:rpp/runtime/config.rs†L3633-L3699】【F:rpp/node/src/lib.rs†L1644-L1725】【F:tests/observability_otlp_failures.rs†L109-L212】

Verwende für `/state-sync`-Operationen die Snapshot-Subcommands statt ad-hoc
`curl`-Aufrufen. `cargo run -p rpp-chain -- validator snapshot status --session <id>` spiegelt die
Light-Client-SSE-Header, sodass Du den Ablauf direkt in der CLI nachvollziehen
kannst. Das Runbook [`network_snapshot_failover`](./runbooks/network_snapshot_failover.md)
führt Peer-Rotation und Failover-Schritte aus, während die
[Phase‑3-Checkliste](./runbooks/phase3_acceptance.md#snapshot-slis--replay-evidenz)
die notwendigen Artefakte sammelt.【F:rpp/node/src/main.rs†L118-L310】【F:docs/runbooks/network_snapshot_failover.md†L1-L176】

## RPC authentication & rate limiting

Node RPC endpoints support optional bearer-token authentication and per-client
rate limiting. Supply the configured token with the `--auth-token` flag when
using CLI helpers or add an `Authorization: Bearer <token>` header to curl
requests.【F:docs/API_SECURITY.md†L10-L37】【F:rpp/node/src/main.rs†L101-L178】 The
flag must match the token configured for the active RPC endpoint; omit it only
when authentication is disabled. Secure configurations should rotate tokens
alongside other secrets and audit usage via reverse-proxy logs.

Expose the RPC to browser dashboards by setting `network.rpc.allowed_origin` in
configuration. Use `--rpc-allowed-origin` for one-off overrides (pass an empty
string to clear the allow-list) and restart without the flag to fall back to the
profile defaults.【F:docs/API_SECURITY.md†L38-L58】

When automation calls the REST endpoints directly, reuse the same tokens and
respect the configured request limits. A `429` response indicates that the node's
rate limiter rejected the request; retry with exponential backoff or throttle
callers as described in the [deployment & observability playbook](./deployment_observability.md).【F:docs/deployment_observability.md†L1-L61】

## Example RPC workflows

Automation typically interacts with the node via authenticated HTTP requests.
The pruning runbook outlines the snapshot APIs, including example `curl`
invocations that enqueue pruning work and inspect receipts.【F:docs/runbooks/pruning.md†L1-L102】
Additional operational runbooks cover startup validation, telemetry wiring, and
upgrade procedures when rolling new binaries into service.【F:docs/runbooks/startup.md†L1-L40】【F:docs/runbooks/observability.md†L1-L120】【F:docs/runbooks/upgrade.md†L1-L60】

Pair this guide with the validator quickstart and troubleshooting references to
fully provision and maintain a production node.【F:docs/validator_quickstart.md†L1-L238】【F:docs/validator_troubleshooting.md†L1-L140】
