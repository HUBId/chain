# Phase‑A Acceptance Checklist

Phase A tracks the external hardening deliverables for pruning snapshots. This
checklist lists the artefacts reviewers must inspect before signing off the
milestone.

## Snapshot provenance

- [ ] **Manifest signature validated.** Run `snapshot-verify` against each
      pruning snapshot bundle and record the resulting JSON report. The command
      requires the detached signature, the manifest path, the `chunks/`
      directory, and the Ed25519 verifying key in hex/base64 form:
      ```bash
      cargo run --locked --package snapshot-verify -- \
        --manifest dist/artifacts/<target>/snapshots/manifest/chunks.json \
        --signature dist/artifacts/<target>/snapshots/manifest/chunks.json.sig \
        --public-key ~/keys/snapshot-manifest.hex \
        --chunk-root dist/artifacts/<target>/snapshots/chunks \
        --output dist/artifacts/<target>/snapshots/manifest/chunks-verify.json
      ```
      Archive the generated `*-verify.json` report together with the release or
      nightly artefacts so auditors can confirm the validation timestamp and the
      signature fingerprint.
- [ ] **CI report linked.** The release and nightly pipelines publish
      `snapshot-manifest-verify.json` when the CLI runs in CI. Link the relevant
      workflow run (and the uploaded report) to the acceptance record for traceability.

## Exit-Kriterien

Phase A ist abgeschlossen, sobald beide Kontrollkästchen oben mit Artefakten
unterlegt sind **und** die folgenden Bedingungen erfüllt werden:

- ✅ **Exit-Code 0:** Jeder `snapshot-verify` Lauf beendet sich mit Exit-Code 0.
  Ein Exit-Code 2 signalisiert eine ungültige Signatur, Exit-Code 3 weist auf
  fehlende oder manipulierte Segmente hin, und Exit-Code 1 markiert einen
  I/O-/Decode-Fehler. Alle Fehlerzustände müssen analysiert und behoben sein
  (z. B. erneute Artefakterstellung), bevor die Phase freigegeben wird.
- ✅ **Berichte versioniert:** Die JSON-Reports liegen im Artefakt-Storage oder
  Repository (z. B. `dist/artifacts/<target>/snapshots/manifest/chunks-verify.json`) und
  sind im Freigabeprotokoll verlinkt.

Erst wenn alle Bedingungen erfüllt sind und die Prüflinks zugänglich bleiben,
ist die Phase offiziell abgeschlossen.
