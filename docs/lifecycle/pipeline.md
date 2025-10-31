# Pipeline Lifecycle

Dieser Leitfaden beschreibt die End-to-End-Pipeline des Knotens vom Wallet bis zur Firewood-Commitment-Schicht und dokumentiert die dazugehörigen Hooks sowie den Smoke-Test.

## Stufenübersicht

| Phase | Orchestrator-Stage | Beschreibung |
| --- | --- | --- |
| Wallet | `GossipReceived` | Der Orchestrator registriert einen neuen Proof-Bundle-Eingang und verfolgt den Flow weiter. |
| Proof | `MempoolAccepted` | Der Bundle wurde vom Node verifiziert und in den lokalen Mempool übernommen. |
| BFT | `BftFinalised` | Malachite BFT hat den Block mit der Transaktion finalisiert. |
| Firewood | `FirewoodCommitted` | Der Firewood-Speicher hat den Blockzustand persistiert und ein Commit-Height gesetzt. |

Die Stufen werden vom `PipelineDashboardSnapshot` veröffentlicht und sind über RPC (Dashboard und SSE) sowie die neuen Hooks zugänglich.【F:rpp/runtime/orchestration.rs†L36-L115】【F:rpp/runtime/orchestration.rs†L697-L713】

## Hooks für Tests & Observability

Der Node initialisiert beim Start Pipeline-Hooks, welche jedes beobachtete Dashboard-Update auf neue Stufen prüfen und als strukturierte Events veröffentlichen.【F:rpp/node/src/lib.rs†L1-L4】【F:rpp/node/src/lib.rs†L586-L642】【F:rpp/node/src/pipeline/mod.rs†L1-L104】 Die Events enthalten Stage, Hash, Zeitstempel (`observed_ms`) sowie optional die Commit-Höhe und werden auf dem `pipeline.hooks`-Logging-Target ausgegeben und per `broadcast`-Kanal an Abonnenten weitergereicht.【F:rpp/node/src/pipeline/mod.rs†L13-L163】 Tests können mit `rpp_node::pipeline::subscribe_stage_events()` auf diese Events hören und die Sequenz validieren.【F:rpp/node/src/pipeline/mod.rs†L68-L70】

## Smoke-Test

Der Smoke-Test `tests/pipeline/end_to_end.rs` startet eine Prozess-Cluster-Umgebung, sendet eine Wallet-Transaktion und überprüft die Stufensequenz Wallet → Proof → BFT → Firewood sowohl über `wait_for_stage` als auch über den SSE-Stream.【F:tests/pipeline/end_to_end.rs†L1-L122】 Zusätzlich prüft der Test, dass das Dashboard alle Stufen markiert und Firewood eine Commit-Höhe liefert.【F:tests/pipeline/end_to_end.rs†L94-L109】 Der Test kann lokal mit `cargo test --test pipeline -- wallet_proof_bft_firewood_pipeline_reaches_all_stages` ausgeführt werden und dient als Regressionstest für Pipeline-Regressionen.

## Auswirkungen auf Dashboards und CI

Durch die Hooks stehen Observability-Feeds bereit, ohne zusätzliche RPC-Aufrufe zu benötigen. Sobald die CI den Smoke-Test ausführt, dokumentiert der Blueprint den erfolgreichen Abschluss der Pipeline-Hooks und die gesicherte Stage-Sequenz. Siehe Abschnitt 6 im Blueprint `docs/blueprints/rpp_stark_integration.md` für den aktualisierten Status.【F:docs/blueprints/rpp_stark_integration.md†L118-L150】
