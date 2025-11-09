# Phase‑A Operator Lab

Dieses Übungsskript führt Operator:innen Schritt für Schritt durch die Verifikation eines Snapshot-Bundles, die Prüfung der WORM-Exports und die Validierung der zugehörigen CI-Artefakte. Ziel ist es, die Phase‑A-Nachweise lokal nachzustellen und sauber zu dokumentieren.

## Ziele

- `rpp-node validator snapshot verify` mit einem reproduzierbaren Test-Bundle ausführen und den JSON-Report bewerten.
- Das WORM-Export-Smoke-Paket erzeugen, Signaturen überprüfen und die Retention-Metadaten nachvollziehen.
- CI-Artefakte (`snapshot-verifier-smoke`, `worm-export-smoke`) auf Vollständigkeit prüfen und die Ergebnisse im Statusreport protokollieren.

## Voraussetzungen

- Rust-Werkzeuge (`cargo`, `rustup`) und das Repository ausgecheckt.
- Der Operator-CLI-Build (`cargo build --release -p rpp-node --no-default-features --features prod,prover-stwo`) steht unter `target/release/rpp-node` bereit.
- Das `gh`-CLI ist konfiguriert (GitHub-Token mit `actions:read`).
- Lokaler Speicherplatz für Trainingsartefakte (`target/snapshot-verifier-smoke/`, `target/worm-export-smoke/`).

> 💡 Die Trainingsdaten werden on demand erzeugt. Das bedeutet, dass kein grosses Artefakt eingecheckt werden muss – `cargo xtask snapshot-verifier` und `cargo xtask test-worm-export` generieren identische Pakete wie die CI-Smoke-Jobs und dienen als Test-Snapshot-Paket bzw. WORM-Fixture.

## 1. Workspace vorbereiten

```sh
# optional: alte Trainingsartefakte entfernen
rm -rf target/snapshot-verifier-smoke target/worm-export-smoke

# synthetisches Snapshot-Bundle und Aggregationsreport erstellen
cargo xtask snapshot-verifier

# WORM-Export-Fixture erzeugen (Append-only Stub + Summary)
cargo xtask test-worm-export
```

Nach dem Lauf liegen folgende Verzeichnisse vor:

- `target/snapshot-verifier-smoke/`
  - `chunks/` (einzelnes Snapshot-Segment `chunk-000`)
  - `manifest/chunks.json` + Signatur `chunks.json.sig`
  - `snapshot-verify-report.json` (Aggregationsreport)
  - `snapshot-key.hex`, Checksummen (`*.sha256`)
- `target/worm-export-smoke/`
  - `worm-export.jsonl` (Audit-Log-Ausschnitt)
  - `worm-export-summary.json` (Aggregat mit Signaturen & Retention)
  - `worm-export.toml` (Trainings-Schlüsselmaterial)

Diese Fixtures entsprechen den CI-Smoke-Artefakten und bilden die Grundlage für alle folgenden Übungen.

## 2. Snapshot-Verifikation mit `rpp-node`

1. **CLI ausführen:**
   ```sh
   target/release/rpp-node validator snapshot verify \
     --manifest target/snapshot-verifier-smoke/manifest/chunks.json \
     --signature target/snapshot-verifier-smoke/manifest/chunks.json.sig \
     --public-key target/snapshot-verifier-smoke/snapshot-key.hex \
     --chunk-root target/snapshot-verifier-smoke/chunks \
     --output target/snapshot-verifier-smoke/training-report.json
   ```
2. **Report bewerten:** Öffne `training-report.json` und bestätige:
   - `signature.signature_valid` == `true`
   - `summary.verified == summary.segments_total`
   - Keine Fehlzähler (`checksum_mismatches`, `missing_files`, …) > 0
3. **Aggregation gegen Schema prüfen (optional):**
   ```sh
   cargo xtask verify-report --report target/snapshot-verifier-smoke/snapshot-verify-report.json
   ```
4. **Ergebnis dokumentieren:** Notiere Manifestpfad, Hash (`sha256sum training-report.json`) und Exit-Code des CLI in deinem Trainingsprotokoll.

## 3. WORM-Export-Smoke analysieren

1. **Summary inspizieren:**
   ```sh
   jq '.signer_key_id, .retention, .entries[0].signature_valid' \
     target/worm-export-smoke/worm-export-summary.json
   ```
   Erwartung: `signature_valid` ist `true`, `retention` enthält `mode`, `duration_days` und `legal_hold`.
2. **Signaturen prüfen:**
   ```sh
   cargo xtask test-worm-export -- --verify-only
   ```
   Der zusätzliche Lauf validiert die bestehenden Artefakte und bestätigt, dass keine neuen Dateien erzeugt werden müssen.
3. **Retention-Log öffnen:**
   - `worm-export.jsonl` enthält Append-only Audit-Ereignisse.
   - `worm-export.toml` dokumentiert den temporären Schlüssel (für Trainingszwecke gedacht, produktiv nicht wiederverwenden).
4. **Ergebnis dokumentieren:** Halte fest, dass `worm-export-summary.json` die erwarteten Felder enthält (`audit_log`, `export_root`, `entries[*].export_object`) und dass der Verifikationslauf ohne Fehler endet.

## 4. CI-Artefakte nachvollziehen

1. **Letzten erfolgreichen `ci.yml`-Run ermitteln:**
   ```sh
   gh api repos/<org>/<repo>/actions/workflows/ci.yml/runs \
     -f branch=<branch> -f status=success -F per_page=1 --jq '.workflow_runs[0].id'
   ```
2. **Artefakte prüfen:**
   ```sh
   gh api repos/<org>/<repo>/actions/runs/<run-id>/artifacts --jq '.artifacts[].name'
   ```
   Stelle sicher, dass `snapshot-verifier-smoke` und `worm-export-smoke` gelistet werden.
3. **Artefakte herunterladen und vergleichen:**
   ```sh
   gh run download <run-id> -n snapshot-verifier-smoke -D training_artifacts/
   gh run download <run-id> -n worm-export-smoke -D training_artifacts/
   diff -qr training_artifacts/snapshot-verifier-smoke target/snapshot-verifier-smoke
   diff -qr training_artifacts/worm-export-smoke target/worm-export-smoke
   ```
   Die `diff`-Ausgabe sollte leer sein; Differenzen dokumentierst du im Trainingslog.
4. **Fehlende Artefakte eskalieren:** Wenn eines der Artefakte fehlt oder abgelaufen ist, verweise im Incident-Log auf das Runbook [„WORM-Export fehlerhaft“](../runbooks/incident_response.md#worm-export-fehlerhaft) bzw. [„Snapshot-Verifier schlägt fehl“](../runbooks/incident_response.md#snapshot-verifier-schlägt-fehl).

## 5. Abschluss & Statusreport

- Dokumentiere Datum, Teilnehmer:innen und Ergebnisse (Hash- und Signaturprüfungen, Artefaktvergleich) im Statusreport.
- Verlinke das lokale Trainingsprotokoll sowie die heruntergeladenen Artefakte in der Tabelle „Trainings & Labs“ (siehe `docs/status/weekly.md`).
- Notiere offene Fragen oder Abweichungen als Follow-up für das Operator-Enablement-Team.

Mit dieser Übung besitzen Operator:innen eine vollständige Referenz, um Phase‑A-Nachweise lokal zu reproduzieren und Audit-fähig zu dokumentieren.
