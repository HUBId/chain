# Staging Soak Orchestrator

Das Staging-Soak-Setup wird über `cargo xtask staging-soak` ausgeführt. Der Befehl bündelt
Snapshot-Health-Checks, den Timetoke-SLO-Report sowie die Admission-Reconciliation und legt
sämtliche Artefakte unter `logs/staging-soak/<YYYY-MM-DD>/<timestamp>/` ab. Die GitHub-Action
[`staging-soak`](../../.github/workflows/nightly.yml) ruft den Task täglich auf und erstellt
bei SLO-Verletzungen automatische Issues.

## Lokale Ausführung

```bash
cargo xtask staging-soak \
  --output-dir logs/staging-soak \
  --snapshot-config config/validator.toml
```

Optionale Flags ermöglichen das Setzen eigener RPC-URLs, Tokens oder Pfade. Die Summary-
Datei (`summary.json`) enthält die aggregierten Statuswerte (`snapshot.ok`, `timetoke.ok`,
`admission.ok`) und sollte gemeinsam mit den Detail-Reports archiviert werden.
