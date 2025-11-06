# Plonky3 backend

Das `plonky3-backend`-Crate kapselt die in Chain integrierten Plonky3-Proof-Flows. Die
Abhängigkeiten auf die Plonky3-Kerncrates (AIR, FRI, Feld- und Kurvenimplementierungen
sowie Hilfsbibliotheken) sind explizit im `Cargo.toml` fixiert, damit die Build-Pipeline
genau die von den Vendor-Toolchains verwendete Version nutzt.

## Features

- `plonky3-cpu-only` (Standard): baut den Backend-Code ohne GPU-Abhängigkeiten. Dieses
  Profil eignet sich für CI-Läufe und lokale Entwicklung ohne dedizierte GPU.
- `plonky3-gpu`: aktiviert die optionalen GPU-Crates (`gpu-alloc`, `gpu-descriptor`) und
  initialisiert beim Start einen minimalen Ressourcenhalter (`GpuResources`). Das Flag
  kann mit `PLONKY3_GPU_DISABLE=1` zur Laufzeit übersteuert werden, um auf CPU-Fallbacks
  zu testen.

Die GPU-Initialisierung ist bewusst leichtgewichtig gehalten, sodass Builds ohne
verfügbare GPU-Hardware nicht fehlschlagen. Tests können `GpuResources::acquire()`
verwenden, um die Verfügbarkeit der GPU-Pfade sicherzustellen.
