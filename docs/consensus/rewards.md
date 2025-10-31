# Timetoke-Reward-Pools und Governance-Steuerung

Die Reward-Verteilung für Timetoke-Leader und -Witnesses lässt sich nun über
`node.toml` steuern. Die neue Konfigurationssektion
`[governance.timetoke_rewards]` definiert, ob die Ausschüttung aktiv ist, wie der
Reward-Pool zwischen Leader- und Witness-Anteilen aufgeteilt wird und ab welcher
Timetoke-Balance Teilnehmer berücksichtigt werden.【F:config/node.toml†L36-L41】
Beim Laden der Konfiguration prüft `GovernanceConfig`, dass die Gewichte im
zulässigen Bereich liegen, und erzeugt daraus die
`TimetokeRewardGovernance`-Policy, die der Konsenscode konsumiert.【F:rpp/runtime/config.rs†L174-L205】【F:rpp/runtime/config.rs†L1186-L1312】

## Governance-Policy

`TimetokeRewardGovernance` kapselt die Governance-Regeln. Sie validiert die
Leader-/Witness-Gewichte, erzwingt eine Mindestbalance und berechnet aus dem
Block-Reward die Budgets für Leader-, Witness- und Rest-Pool. Das Restbudget kann
Operatoren in Treasury- oder Burn-Konten verschieben.【F:rpp/consensus/src/governance.rs†L1-L126】

## Reward-Berechnung

`distribute_timetoke_rewards` wendet die Governance-Regeln auf die aktuellen
Timetoke-Records an. Für jede Poolart werden die Timetoke-Balances gefiltert,
nach Identität deterministisch sortiert und proportional zum Gesamtgewicht
verteilt; verbleibende Reste fließen in den letzten Eintrag, so dass die Summe
immer mit dem Budget übereinstimmt.【F:rpp/consensus/src/timetoke/rewards.rs†L1-L89】

## Tests

Die neue Integrationssuite `tests/consensus/timetoke_rewards.rs` prüft die
Goverance-Splitts sowie die Filterung von Teilnehmern unterhalb der
Mindestbalance. Zusätzlich decken Unit-Tests in `governance.rs` und
`timetoke/rewards.rs` Validierungsfehler sowie die Poolverteilung ab.【F:tests/consensus/timetoke_rewards.rs†L1-L40】【F:rpp/consensus/src/governance.rs†L128-L158】【F:rpp/consensus/src/timetoke/rewards.rs†L91-L107】
