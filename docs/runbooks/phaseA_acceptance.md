# Phase‑A Acceptance Checklist

Phase A tracks the external hardening deliverables for pruning snapshots. This
checklist lists the artefacts reviewers must inspect before signing off the
milestone.

## Snapshot provenance

- [ ] **Aggregated verifier report vorhanden.** Führe `scripts/build_release.sh`
      mit gesetztem `SNAPSHOT_MANIFEST_PUBKEY_HEX` für jedes Release-Target aus
      (oder verweise auf den Release-Workflow `Build <target>`). Der Lauf erzeugt
      pro Manifest `*-verify.json` sowie das Bündel
      `snapshot-verify-report.json` und `snapshot-verify-report.json.sha256`
      unter `dist/artifacts/<target>/`. Hinterlege die JSON- und SHA256-Datei als
      Pflichtartefakte und archiviere die Einzelberichte für spätere Audits.【F:scripts/build_release.sh†L273-L348】【F:.github/workflows/release.yml†L122-L209】
      Validiere den JSON-Inhalt zusätzlich lokal via
      `cargo xtask verify-report --report dist/artifacts/<target>/snapshot-verify-report.json`
      – das Kommando prüft sowohl die Aggregation als auch Einzelreports gegen
      `docs/interfaces/snapshot_verify_report.schema.json`. Führe das Ergebnis im
      Übergabeprotokoll auf.【F:xtask/src/main.rs†L1594-L1677】【F:docs/interfaces/snapshot_verify_report.schema.json†L1-L173】
- [ ] **CLI-Verifikation nachvollzogen.** Dokumentiere mindestens einen Lauf von
      `rpp-node validator snapshot verify --config <pfad>` gegen das produktive
      Bundle. Der Report muss `signature_valid=true` und keine Chunk-Abweichungen
      melden; bei Fehlern liefert das CLI Exit-Code `2` (Signatur) oder `3`
      (Segmentabweichungen). Hänge den JSON-Output an die Übergabeunterlagen, damit
      Reviewer:innen die lokale Prüfung nachverfolgen können.【F:rpp/node/src/main.rs†L140-L227】【F:rpp/node/tests/snapshot_verify.rs†L1-L123】
- [ ] **SHA256 im Freigabeprotokoll festgehalten.** Die Release Notes enthalten
      den Abschnitt „Snapshot verifier attestation“ mit den Hashes aus den
      `.sha256`-Dateien. Vergleiche mindestens einen Wert lokal via
      `sha256sum dist/artifacts/<target>/snapshot-verify-report.json` und
      dokumentiere den Abgleich im Freigabeprotokoll.【F:.github/workflows/release.yml†L210-L233】
- [ ] **CI/Nightly-Referenzen verlinkt.** Verweise auf den CI-Job
      `snapshot-verifier`, der das synthetische Prüfbündel unter
      `target/snapshot-verifier-smoke/` erzeugt, sowie auf die Release-Artefakte
      `snapshot-verifier-<target>` im Actions-Tab. So lässt sich das Ergebnis
      reproduzieren, ohne die produktiven Artefakte neu zu signieren.【F:.github/workflows/ci.yml†L369-L397】【F:.github/workflows/release.yml†L150-L209】

## WORM export audit trail

- [ ] **Nightly smoke erfolgreich.** Der Nightly-Job `worm-export` führt
      `cargo xtask test-worm-export` gegen den Append-only-Stub aus, erzeugt die
      exportierten JSON-Objekte plus `worm-export-summary.json` und lädt das
      Artefakt `worm-export-smoke` hoch. Verlinke den Lauf und prüfe, dass die
      Summary `signature_valid=true` meldet.【F:.github/workflows/nightly.yml†L10-L24】【F:xtask/src/main.rs†L120-L318】
- [ ] **Evidence-Bundle aktualisiert.** Bestätige, dass
      `cargo xtask collect-phase3-evidence` die WORM-Logs (`target/worm-export-smoke`)
      samt Signaturen ins Bundle kopiert und die Manifestdatei die Quellen
      aufführt. Dokumentiere Speicherort und Prüfsumme im Freigabeprotokoll.【F:xtask/src/main.rs†L1516-L1584】【F:xtask/src/main.rs†L1606-L1644】
- ✅ **Bootstrap-Guard aktiv.** Produktions-Release-Channels (`canary`/`mainnet`)
  verweigern den Start, wenn `network.admission.worm_export` keinen S3-Endpoint,
  Zugangsdaten und ein Retention-Fenster setzt. Der Guard schreibt einen
  Bootstrap-Fehler und erhöht die Metrik `worm_export_misconfigured_total`; prüfe
  Logs und Prometheus-Export beim Abbruch.【F:rpp/node/src/lib.rs†L520-L590】

## Exit-Kriterien

Phase A ist abgeschlossen, sobald beide Kontrollkästchen oben mit Artefakten
unterlegt sind **und** die folgenden Bedingungen erfüllt werden:

- ✅ **Snapshot-Verifier grün:** Sowohl `snapshot-verify-report.json` meldet
  `"all_passed": true` als auch alle Einzelreports zeigen `signature_valid=true`
  ohne fehlende Segmente. Auftretende Fehlerzustände (Exit-Code 2/3 oder
  `status=false`) sind vor Freigabe zu beheben.
- ✅ **Berichte versioniert:** Die JSON-Reports und `.sha256`-Dateien liegen im
  Artefakt-Storage oder Repository (z. B.
  `dist/artifacts/<target>/snapshot-verify-report.json`) und sind im
  Freigabeprotokoll verlinkt.
- ✅ **WORM-Smoke dokumentiert:** Das Nightly-Artefakt
  `worm-export-smoke` enthält das signierte Export-Objekt sowie die Summary
  (`signature_valid=true`) und ist in der Acceptance-Dokumentation referenziert.

Erst wenn alle Bedingungen erfüllt sind und die Prüflinks zugänglich bleiben,
ist die Phase offiziell abgeschlossen.
