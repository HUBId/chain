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

Zusätzlich schreibt der Hook jede Beobachtung in die Telemetrie: `PipelineMetrics::record_stage` aktualisiert die Histogramme `rpp.node.pipeline.stage_latency_ms`, den Zähler `rpp.node.pipeline.stage_total` und das Commit-Histogramm `rpp.node.pipeline.commit_height`, wodurch Dashboards Verzögerungen, Durchsatz und Firewood-Persistenz nachvollziehen können.【F:rpp/node/src/pipeline/mod.rs†L137-L164】【F:rpp/node/src/telemetry/pipeline.rs†L1-L66】 Die Orchestrator-Stages `GossipReceived`, `MempoolAccepted`, `BftFinalised` und `FirewoodCommitted` werden damit automatisch etikettiert und stehen auch externen Abonnenten zur Verfügung.【F:rpp/runtime/orchestration.rs†L34-L88】【F:rpp/node/src/pipeline/mod.rs†L10-L35】

## Smoke-Test

Der Smoke-Test `tests/pipeline/end_to_end.rs` startet eine Prozess-Cluster-Umgebung, sendet eine Wallet-Transaktion und überprüft die Stufensequenz Wallet → Proof → BFT → Firewood sowohl über `wait_for_stage` als auch über den SSE-Stream.【F:tests/pipeline/end_to_end.rs†L1-L122】 Zusätzlich prüft der Test, dass das Dashboard alle Stufen markiert, Firewood eine Commit-Höhe liefert und die Telemetrie-Hooks Ereignisse emittieren, bevor das Szenario beendet wird.【F:tests/pipeline/end_to_end.rs†L94-L117】 Der Test kann lokal mit `cargo test --test pipeline -- wallet_proof_bft_firewood_pipeline_reaches_all_stages` ausgeführt werden und dient als Regressionstest für Pipeline-Regressionen.

## Auswirkungen auf Dashboards und CI

Durch die Hooks stehen Observability-Feeds bereit, ohne zusätzliche RPC-Aufrufe zu benötigen. Die registrierten Metriken erscheinen direkt in den Pipeline-Dashboards (`docs/observability/pipeline.md`) und spiegeln die Stage-Ereignisse aus dem Hook wider.【F:docs/observability/pipeline.md†L1-L74】【F:rpp/node/src/telemetry/pipeline.rs†L1-L66】 Sobald die CI den Smoke-Test ausführt, dokumentiert der Blueprint den erfolgreichen Abschluss der Pipeline-Hooks und die gesicherte Stage-Sequenz. Siehe Abschnitt 6 im Blueprint `docs/blueprints/rpp_stark_integration.md` für den aktualisierten Status.【F:docs/blueprints/rpp_stark_integration.md†L118-L150】
