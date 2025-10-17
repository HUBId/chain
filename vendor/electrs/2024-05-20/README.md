# Electrs Vendor Snapshot (2024-05-20)

- **Upstream-Quelle:** `vendor/electrs-master.zip`
- **Referenz-Commit:** `4a5af61668a1414f112fe8b07b23bff554779a4f`
- **Importumfang:** `src/chain.rs`, `src/types.rs`

## Aktualisierungsschritte

1. Lade das gewünschte Upstream-Archiv (z. B. über `curl`/`wget`) in `vendor/electrs-master.zip`.
2. Prüfe den Commit-Hash (der GitHub-Archive im Dateikopf ausgeben) und dokumentiere ihn in
   [`manifest/upstream_commit.txt`](manifest/upstream_commit.txt).
3. Entpacke die benötigten Dateien in `src/` und passe Importe sowie Modul-Pfade an die
   RPP-spezifischen Typen (`rpp-ledger`).
4. Ergänze ggf. TODO-Stubs, damit `cargo check --features vendor_electrs` erfolgreich durchläuft.
5. Formatiere die Änderungen mit `cargo fmt --all`.
6. Vergleiche die modifizierten Dateien mit dem Upstreamstand, z. B. über `diff -u` oder `git difftool`,
   um Abweichungen nachvollziehen zu können.

## Diff-Empfehlung

Um lokale Anpassungen sichtbar zu machen, empfiehlt sich eine Referenzkopie der entpackten Dateien:

```bash
TMP_DIR=$(mktemp -d)
unzip vendor/electrs-master.zip 'electrs-master/src/chain.rs' 'electrs-master/src/types.rs' -d "$TMP_DIR"
diff -u "$TMP_DIR"/electrs-master/src/chain.rs vendor/electrs/2024-05-20/src/chain.rs
```

Auf diese Weise bleiben Upstream-Änderungen transparent und können in zukünftigen Updates gezielt
übernommen werden.
