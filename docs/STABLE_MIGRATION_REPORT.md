# Stable Migration Scan Report

- Generated: 2025-10-12 11:38:08Z
- Commit: 9288d892ee87bfa7a2e2bc9ae4462a740aef8a95
- Mode: warn (non-blocking)

## Findings

### Nightly Rust features (#![feature])
- Keine Funde.

### Unstable compiler or Cargo flags (-Z)
- Keine Funde.

### Cargo feature gates referencing "unstable"
- Keine Funde.

### Cargo manifests using "edition2024" (cargo-features)
- storage-firewood/Cargo.toml:cargo-features = ["edition2024"]
- Cargo.toml:cargo-features = ["edition2024"]
- rpp/p2p/Cargo.toml:cargo-features = ["edition2024"]

### Crates targeting edition = "2024"
- storage-firewood/Cargo.toml:edition = "2024"
- Cargo.toml:edition = "2024"
- rpp/p2p/Cargo.toml:edition = "2024"

### Cargo.lock entries requiring edition2024
- Keine Funde.

Fazit: 6 Funde – Folge-PRs für: storage-firewood, rpp/p2p, repo-root.
