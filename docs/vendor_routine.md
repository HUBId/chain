# Vendor-Integrationsroutine

Diese Routine beschreibt eine wiederholbare Abfolge von Schritten, um die im Verzeichnis `vendor/` abgelegten ZIP-Archive kontrolliert in lokale Kopien der externen Crates zu überführen. Sie stellt sicher, dass alle Teams denselben Prozess nutzen, und ermöglicht eine schrittweise, batchweise Abarbeitung.

## Zielsetzung

* Konsistente Ordnerstruktur für alle lokal gepflegten Vendor-Kopien.
* Reproduzierbare Extraktion mit minimalem manuellem Aufwand.
* Frühes Erkennen fehlender oder redundanter Archive.

## Verzeichnisstruktur

1. **Basisverzeichnis:** `vendor/`
2. **Pro Crate:** Unterordner nach Schema `vendor/<crate-name>/<crate-version>/`
3. **Inhalt:** Vollständige, extrahierte Quellen (Dateien, `Cargo.toml`, `LICENSE`, etc.).
4. **Optional:** Für Crates ohne Versionssuffix (z. B. bei lokalen Patches) `vendor/<crate-name>/local/`.

> **Hinweis:** Sollte das Vendor-Archiv bereits eine Cargo-Vendor-Struktur enthalten, wird diese beim Entpacken beibehalten. Abweichungen werden im Batch-Protokoll dokumentiert.

## Standardisierte Arbeitsschritte

1. **Batch auswählen:** Den nächsten, priorisierten Batch aus der übergreifenden Integrationsplanung entnehmen (z. B. Batch 1: Fundament & Fehlerbehandlung).
2. **Archive identifizieren:** Für jedes Crate des Batches sicherstellen, dass ein ZIP-Archiv im `vendor/`-Verzeichnis vorhanden ist. Fehlende Archive werden in einer To-do-Liste vermerkt.
3. **Zielordner vorbereiten:** Falls der Zielordner `vendor/<crate>/<version>/` bereits existiert, prüfen, ob ein Update ansteht. Bei Updates den bestehenden Ordner nach `vendor/<crate>/<version>-old/` verschieben, bis der neue Stand validiert ist.
4. **Archiv entpacken:**
   * Befehl: `unzip -q vendor_archiv.zip -d vendor/<crate>/<version>/`
   * Archive mit oberster Ordnerstruktur (`crate-name/…`) werden direkt entpackt; andernfalls den Ordnernamen beim Entpacken erzwingen (z. B. `mkdir -p vendor/<crate>/<version>/` und anschließend alle Dateien hineinverschieben).
5. **Integritätscheck durchführen:**
   * Existiert eine `Cargo.toml` im Zielordner?
   * Stimmen `name` und `version` mit der erwarteten Abhängigkeit überein?
   * Sind Lizenzdateien vorhanden?
6. **Konfigurationsreferenz prüfen:** Sicherstellen, dass `.cargo/config.toml` (oder äquivalent) den Pfad `vendor/<crate>/<version>/` für das entsprechende Crate referenziert. Bei fehlenden Einträgen ergänzen.
7. **Batch-Testlauf:** Nach Abschluss aller Crates eines Batches `cargo check` ausführen. Bei Fehlern zurück zum betroffenen Crate, Struktur oder Versionsangabe anpassen.
8. **Dokumentation aktualisieren:**
   * Batch-Protokoll um Datum, verantwortliche Person, Besonderheiten erweitern.
   * Fehlende Archive oder manuelle Eingriffe notieren.

## Automatisierungsskript (optionale Vorlage)

Die folgenden Pseudocode-Schritte können für ein Shell- oder Python-Skript genutzt werden, um die Routine zu automatisieren:

```
for crate in batch_list:
    archive = find_vendor_archive(crate)
    assert archive.exists(), "Archiv fehlt"

    target = make_target_path(crate.name, crate.version)
    prepare_target_dir(target)

    unzip(archive, target)
    validate_cargo_toml(target)
    record_result(crate, target)

after_batch:
    run("cargo check")
    update_log(batch_id, status)
```

## Batch-1-Implementierungsplan (Fundamentale Utility-Crates)

Der erste Batch dient dazu, den Gesamtprozess mit vier zentralen, wenig abhängigen Bibliotheken zu verifizieren. Für jede Bibliothek werden dieselben Schritte ausgeführt, sodass spätere Batches lediglich skaliert werden müssen.

### Übersicht Batch 1

| Crate            | Erwartete Version | Vendor-Archiv             | Besonderheiten |
|------------------|-------------------|---------------------------|----------------|
| `anyhow`         | 1.0.x             | `vendor/anyhow-master-1.zip` | Prüfen, ob Unterordner bereits `anyhow-1.0.*` heißt. |
| `thiserror`      | 1.0.x             | `vendor/thiserror-master.zip` | Build-Skripte nicht erwartet; Fokus auf `src/error.rs`. |
| `serde`          | 1.0.x             | `vendor/serde-master-1.zip` | Enthält optionale Feature-Ordner (`derive`). |
| `serde_json`     | 1.0.x             | _Archiv klären_            | Sicherstellen, dass kein Fremdprojekt entpackt wird. |

### Schrittfolge für Batch 1

1. **Vorbereitung**
   * `docs/vendor_log.md` (oder gleichwertiges Protokoll) anlegen bzw. aktualisieren, um den Fortschritt festzuhalten.
   * In `.cargo/config.toml` sicherstellen, dass der Pfad `vendor/` global eingebunden ist, damit zusätzliche Crates automatisch aufgelöst werden.

2. **Crate `anyhow`**
   1. Archiv `anyhow-master-1.zip` verifizieren (`unzip -l`), um den enthaltenen Stammordner zu identifizieren.
   2. Zielverzeichnis `vendor/anyhow/1.0.x/` anlegen; `x` mit tatsächlicher `Cargo.toml`-Version ersetzen.
   3. Archiv entpacken und Struktur bereinigen (überflüssige `tests/` oder `.github/` optional entfernen, sofern nicht benötigt).
   4. `Cargo.toml` und Lizenz (`LICENSE-MIT`/`LICENSE-APACHE`) prüfen und im Protokoll abhaken.

3. **Crate `thiserror`**
   1. Archiv entpacken nach `vendor/thiserror/1.0.x/`.
   2. Prüfen, dass `impl`-Module vollständig sind (`src/lib.rs`, `src/display.rs`).
   3. Sicherstellen, dass `Cargo.toml` keine nicht unterstützten Features aktiviert; ggf. dokumentieren.

4. **Crate `serde`**
   1. Archiv entpacken nach `vendor/serde/1.0.x/`.
   2. Feature-Verzeichnis `serde_derive` separat prüfen und im Zielordner belassen, falls benötigt.
   3. Bei vorhandenen `build.rs`-Dateien sicherstellen, dass sie in die Zielstruktur übernommen werden.

5. **Crate `serde_json`**
   1. Vor dem Entpacken verifizieren, dass das vorhandene Archiv tatsächlich `serde_json` enthält; bei Unsicherheit neues Archiv beschaffen.
   2. Nach `vendor/serde_json/1.0.x/` entpacken und `Cargo.toml` auf Abhängigkeiten (`itoa`, `ryu`) prüfen.
   3. Fehlende Archive für diese Transitiv-Abhängigkeiten sofort in die Batch-2-Vorbereitung aufnehmen.

6. **Abschlussprüfung Batch 1**
   * `cargo check -p <lokales Projekt>` ausführen, um sicherzustellen, dass die Pfade korrekt aufgelöst werden.
   * Im Protokoll festhalten, welche Archive erfolgreich integriert wurden, welche Anpassungen nötig waren und ob Nacharbeiten offen sind (z. B. `serde_json`-Archiv ersetzen).
   * Alte Archive oder Zwischenordner nach erfolgreicher Validierung löschen bzw. archivieren.

Mit einem dokumentierten und erfolgreichen Batch 1 existiert ein erprobtes Muster, das für die nachfolgenden Batches (Async, Netzwerk, Kryptografie usw.) nahezu unverändert übernommen werden kann.

## Pflege & Governance

* Nach jedem Batch prüfen, ob redundante Archive (`vendor/<crate>/<version>-old/`) gelöscht werden können.
* Regelmäßige Integritätsprüfung mittels Hashes (z. B. `sha256sum`) kann optional ergänzt werden, um unbeabsichtigte Änderungen an Vendor-Dateien aufzuspüren.
* Änderungen am Prozess werden im selben Dokument nachgeführt, damit alle Teams auf einen gemeinsamen Stand zugreifen.

