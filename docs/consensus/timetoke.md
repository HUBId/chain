# Timetoke-Snapshots und Replay-Schutz

Die Timetoke-Synchronisation koppelt das Ledger an die neuen libp2p-Snapshotstreams.
Dieser Abschnitt fasst die Producer-/Consumer-Logik sowie die Replay-Validierung
zusammen und verweist auf die Regressionstests, die den Pfad absichern.

## Snapshot-Produktion

`TimetokeSnapshotProducer` kapselt den `SnapshotStore` aus dem P2P-Stack. Beim
Veröffentlichen werden die sortierten Timetoke-Records zusammen mit dem
Ledger-Commitment (`timetoke_root`) in eine JSON-Payload serialisiert, im Store
gehashed und als `SnapshotChunkStream` bereitgestellt.【F:rpp/consensus/src/timetoke/snapshots.rs†L55-L112】
Der Handle trägt neben dem Blake3-Root auch die Chunk-Anzahl und dient den
Netzwerkdiensten als Ankündigung für die Übertragung.

## Snapshot-Konsum

`TimetokeSnapshotConsumer` überprüft jede Chunk-Lieferung auf Wurzelbindung,
korrekte Reihenfolge und konsistente Gesamtanzahl. Erst wenn alle Chunks
vorliegen und der rekonstruierte Payload-Hash mit dem erwarteten Root
übereinstimmt, wird der vollständige Snapshot zurückgegeben; Duplikate nach
Abschluss werden explizit abgelehnt.【F:rpp/consensus/src/timetoke/snapshots.rs†L114-L205】

## Replay-Validierung

`TimetokeReplayValidator` vergleicht die importierten Snapshots mit den lokalen
Ledger-Commitments und den Pruning-Receipts. Neben der Timetoke-Root werden die
Tags der Pruning-Digests (Snapshot, Segmente, Aggregate, Binding) sowie der
hashgebundene Global-State-Commitment abgeglichen, um Replay- oder Cross-Wire-
Angriffe frühzeitig zu blockieren.【F:rpp/consensus/src/timetoke/replay.rs†L15-L248】

## Tests

Die neue Testsuite deckt sowohl den Snapshot-Roundtrip als auch die
Replay-Abwehr ab: der erste Test streamt eine Beispielaufnahme über Producer
und Consumer, der zweite provoziert unterschiedliche Fehlerpfade (stale root,
Digest-Mismatch, falscher Domain-Tag).【F:tests/consensus/timetoke_snapshots.rs†L48-L168】
