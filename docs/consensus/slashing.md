# Slashing-Pipeline und Telemetrie

Diese Dokumentation beschreibt die priorisierte Verarbeitung von Slashing-Evidence in der
Konsens-Engine sowie die dazugehörigen Heuristiken und Telemetrie-Signale. Die Umsetzung
folgt den Anforderungen des Blueprint-Eintrags `bft.evidence_slashing`.

## Priorisierte Evidence-Pipeline

* **Quelle:** `rpp/consensus/src/evidence/mod.rs`
* **Kategorien:**
  * `EvidenceKind::DoubleSign` für Prevote-/Precommit-Doppel-Signaturen
  * `EvidenceKind::Availability` für `FalseProof`-Meldungen (Availability-Verstöße)
  * `EvidenceKind::Witness` für `VoteWithholding`-Ereignisse und Witness-Berichte
* **Datenstruktur:** `EvidencePipeline`
  * FIFO-Queues pro Kategorie, Drain/Iter liefern immer Double-Signs → Availability → Witness
  * `counts()` liefert einen dreiteiligen Snapshot, `drain()` erhält die Priorisierung.

Die Pipeline wird von `ConsensusState::record_evidence` genutzt; alle eingehenden Meldungen
werden über `EvidenceType::kind()` kategorisiert. Tests in
`tests/consensus/evidence_slashing.rs` decken die Priorisierung ab.

## Slashing-Heuristiken

* **Quelle:** `rpp/consensus/src/reputation/slashing.rs`
* **Aggregat:** `SlashingHeuristics`
  * Speichert kumulative Zähler (`SlashingSnapshot`) für alle Kategorien
  * Hält die letzten 64 Ereignisse (`drain_recent()` für Telemetrie/Export)
  * `observe_evidence` erzeugt `SlashingEvent` inklusive Reporter, Accused und Detail-String
  * `observe_trigger` klassifiziert Reputation-basierte Trigger als Witness-Ereignisse
* **Integration:**
  * `ConsensusState::record_evidence` ruft `observe_evidence`
  * `ConsensusState::ingest_uptime_observation` ruft `observe_trigger`

Die Tests validieren sowohl die Snapshot-Aktualisierung als auch die Event-Historie.

## Telemetrie

* **Quelle:** `rpp/node/src/telemetry/slashing.rs`
* **Metriken:**
  * `rpp.node.slashing.events_total` (`Counter`, Attribute `kind`)
  * `rpp.node.slashing.queue_depth` (`Histogram`, Gesamtgröße der Evidence-Pipeline)
  * `rpp.node.slashing.queue_segments` (`Histogram`, Attribute `kind`)
  * `rpp.node.slashing.snapshot_total` (`Histogram`, Attribute `kind` für kumulative Zähler)
* **API:**
  * `record_event(&SlashingEvent)`
  * `record_pipeline(&EvidencePipeline)`
  * `record_snapshot(&SlashingSnapshot)`

Die Telemetrie-API ist bewusst frei von Seiteneffekten, damit Dienste (z. B. Gossip oder
Auditing) Events aus `SlashingHeuristics::drain_recent` auswerten und anschließend Metriken
anreichern können.

## Validierung & Tests

* `tests/consensus/evidence_slashing.rs`
  * Prioritätsreihenfolge der Pipeline (`EvidencePipeline::drain`)
  * Integration der Heuristiken inklusive Witness-Trigger aus Uptime-Überlappungen
* `tests/witness_incentives.rs`
  * Stellt sicher, dass Witness-Prämien mit der Pipeline kompatibel bleiben

## Weiteres Vorgehen

* Ausbau der Telemetrie-Anbindung in Node-Diensten (z. B. Witness-Gossip)
* Export der `SlashingEvent`-Historie via RPC für Auditing-Tools
