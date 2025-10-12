# Blueprint für eine STWO-kompatible STARK-Library (stable-only)

## 0) Basisanforderungen (global, für das gesamte Projekt)

### Toolchain / MSRV

- Rust stable; empfohlene MSRV: 1.79.
- MSRV im Projekt fest dokumentiert (Manifeste, README, CI).

### Safety & Stil

- Kein unsafe.
- Keine Panics in Bibliothekslogik, keine impliziten Abbrüche; harte Fehler nur über definierte Fehler-Enums.
- Lint-Gate: Clippy ohne Warnungen.

### Determinismus

- Identische Inputs ⇒ bitidentische Outputs (Proof-Bytes, Roots, Indizes, Challenges).
- Keine OS-RNGs, keine Uhrzeiten; alle Pseudozufälle ausschließlich über Transcript.

### Reproduzierbarkeit

- Snapshots für Byte-Artefakte (Proof, Params, FRI-Roots, Query-Listen).
- Build/Tests deterministisch (keine Umgebungsabhängigkeiten).

### Dokumentation

- Zentrale Spezifikationsdokumente: siehe Abschnitt 12.

### Audit-Check (0)

- _[Dieser Abschnitt ist als Platzhalter für konkrete Audit-Aufgaben reserviert.]_
