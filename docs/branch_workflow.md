# Canonical Branch Workflow

Diese Anleitung beschreibt einen defensiven, wiederholbaren Workflow für Branches in diesem Repository. Ziel ist es, einen klaren "Wahrheits-Branch" (Canonical Branch) zu definieren und Branch-Chaos zu vermeiden.

## Canonical Branch
- Der Canonical Branch ist die einzige, verlässliche Quelle für stabile, integrierte Änderungen.
- Standardmäßig entspricht er dem Default-Branch des Repos (aktuell `main`).
- Der Branch kann per Umgebungsvariable `CANONICAL_BRANCH`, per Argument des Audit-Tools oder über `tools/branch_audit/config.toml` überschrieben werden.

## Neue Arbeit starten
1. Auf den Canonical Branch wechseln und aktualisieren:
   ```bash
   git checkout <CANONICAL_BRANCH>
   git pull
   ```
2. Feature-Branch anlegen:
   ```bash
   git checkout -b feature/<kurzer-name>
   ```
3. Experimente/Spikes klar benennen, z. B. `experiment/<idee>` oder `spike/<problem>`.
4. Hotfixes für dringende Themen unter `hotfix/<beschreibung>` erstellen.

## Pull Requests & Merges
- Jeder Feature-/Bugfix-Branch führt zu einem PR gegen `<CANONICAL_BRANCH>`.
- Große Themen-Branches sollten regelmäßig mit `<CANONICAL_BRANCH>` synchronisiert werden, um Konflikte klein zu halten.
- Nach erfolgreichem Merge sollte der Branch gelöscht werden. Empfehlung: GitHub-Setting „Automatically delete head branches after pull requests are merged“ aktivieren.

## Branch-Lebensdauer & Aufräumen
- Feature-Branches sollten kurzlebig sein (Tage/Wochen, nicht Monate).
- `experiment/*` und `spike/*` Branches werden regelmäßig (monatlich/quartalsweise) per Audit überprüft und aufgeräumt.
- Das Branch-Audit-Tool (`tools/branch_audit/audit.py`) sollte mindestens monatlich laufen, um Reports + Skripte zu aktualisieren.

## Typische Workflows
- **Neues Feature starten:** Von `<CANONICAL_BRANCH>` abzweigen, klar benennen, kurze Lebensdauer anstreben.
- **PR erstellen & mergen:** PR gegen `<CANONICAL_BRANCH>`, regelmäßiges Rebase/Merge aus dem Canonical Branch, nach Merge Branch löschen.
- **Branch nach Merge löschen:** Entweder automatisches Löschen durch die Plattform oder manuell `git push origin --delete <branch>`.
- **Alte Branches aufräumen:** Audit-Tool ausführen, Report prüfen, Delete-/Merge-Vorschläge aus den generierten Skripten selektiv anwenden.

## Schutz von langfristigen Branches
- System-/Release-/Staging-Branches (`main`, `dev`, `release/*`, `staging/*`, `infra/*`) dürfen nicht automatisch gelöscht werden.
- Themen-Branches mit längerer Laufzeit sollten dokumentiert sein und regelmäßig mit `<CANONICAL_BRANCH>` abgeglichen werden.
