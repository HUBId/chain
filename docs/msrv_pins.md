# MSRV-sensitive dependency pins

This project targets Rust 1.79.0. The following third-party crates have
experienced MSRV bumps in recent releases or have a history of adopting new
language features quickly. They are pinned to exact versions to prevent
accidental upgrades beyond the supported compiler and to keep the workspace
builds reproducible.

| Crate | Pinned version | Rationale |
| --- | --- | --- |
| `tokio` | `1.48.0` | Locks in the latest release validated with Rust 1.79 and avoids the next minor release which raises the MSRV. |
| `tokio-stream` | `0.1.17` | Matches the pinned `tokio` release and keeps macro support in sync with the MSRV. |
| `serde` | `1.0.225` | Prevents automatic upgrades to `1.0.2xx` releases that depend on language changes newer than Rust 1.79. |
| `serde_json` | `1.0.145` | Ensures the JSON stack stays aligned with the pinned `serde` version and retains the `std` feature only. |
| `fastrace` / `fastrace-macro` | `0.7.14` | Patched vendor copies cap the `rust-version` at 1.79 so tracing instrumentation builds without the upstream 1.80 MSRV bump. |
| `clap` | `4.5.50` | Freezes the CLI surface on an MSRV-tested release while disabling default features to keep the dependency tree minimal. |
| `tracing` | `0.1.41` | Explicitly enables only the `std`, `attributes`, and `log` features to preserve compatibility with the MSRV. |
| `tracing-subscriber` | `0.3.20` | Works with Rust 1.79 and avoids the optional defaults that now require newer compilers. |
| `thiserror` | `2.0.12` | Newer error-derive releases adopt recently stabilised language features; pinning keeps derives available on the MSRV. |
| `tempfile` | `3.23.0` | Later releases require a newer standard library; locking the version ensures temporary file utilities build on 1.79. |
| `bitflags` | `2.10.0` | Prevents an automatic update to `2.11+`, which depends on Rust 1.80 for `const` trait improvements. |
| `reqwest` | `0.12.24` | Holds the HTTP client on a version verified against 1.79 and disables default features that would pull in incompatible TLS stacks. |

All other workspace crates that depend on these libraries use workspace
inheritance so the pinned versions apply uniformly across every crate.
