# ADR 0001: ZK Backend Status and Plonky3 Graduation

## Status

Draft – wird nach Integration des echten Plonky3-Backends aktualisiert.

## Context

Earlier revisions of this ADR codified Plonky3 as an experimental backend. The
acknowledgement guard was a temporary safety rail while the prover and verifier
were still wired to deterministic shims. Diese Aktualisierung hält fest, dass der
Code weiterhin auf dem Stub-Backend basiert; echte Vendor-Proofs und -Verifier
stehen noch aus.【F:rpp/proofs/plonky3/README.md†L1-L34】 Runtime und Telemetrie
sind vorbereitet, liefern aber ausschließlich Stub-Signale.【F:rpp/runtime/node.rs†L161-L220】

## Decision

* Stub-Backend ohne Acknowledgement-Gate weiterführen, bis Vendor-Prover und
  -Verifier integriert sind. Feature-Flags bleiben bestehen, schalten aktuell
  jedoch nur die Stub-Implementierung frei.【F:rpp/proofs/plonky3/prover/mod.rs†L201-L233】【F:rpp/proofs/plonky3/verifier/mod.rs†L1-L120】
* Backend-Health als strukturierte Telemetrie beibehalten, aber klar als Stub-
  Signale markieren; produktive Alerts erst nach echter Integration aktivieren.【F:rpp/runtime/node.rs†L161-L220】【F:docs/interfaces/rpc/validator_status_response.jsonschema†L1-L220】【F:validator-ui/src/types.ts†L140-L220】
* CI- und Release-Pipelines weiterhin mit Stub-Suites betreiben und einen
  dedizierten Vendor-Lauf vorbereiten (`ci-plonky3-matrix`), sobald Artefakte
  verfügbar sind.【F:.github/workflows/release.yml†L1-L160】【F:rpp/proofs/plonky3/tests.rs†L58-L74】

## Consequences

* Operator:innen sollten Plonky3 weiterhin nicht in Produktion einsetzen; die
  Telemetrie dient vorerst nur als Vertrags-/Dashboard-Test.【F:rpp/runtime/node.rs†L161-L220】
* CI und Release-Pipelines validieren ausschließlich Stub-Artefakte. Reelle
  Regressionen werden erst nach Einbindung der Vendor-Bibliotheken sichtbar.【F:scripts/test.sh†L1-L220】【F:.github/workflows/release.yml†L1-L160】
* Dokumentation und Roadmaps wurden aktualisiert, um den Stub-Status klar zu
  kennzeichnen und offene Arbeitsschritte hervorzuheben.【F:docs/blueprint_coverage.md†L18-L120】【F:docs/rpp_node_operator_guide.md†L53-L86】

## Follow-up

* Vendor-Prover/Verifier integrieren und reale Proof-Läufe ermöglichen.
* Release-Checklisten und Alerting-Strategien mit echten Plonky3-Metriken
  aktualisieren, sobald produktive Daten vorliegen.
