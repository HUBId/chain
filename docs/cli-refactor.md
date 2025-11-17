# CLI Refactor Dependency Inventory

This document enumerates all `use` statements currently present in `rpp/node/src/cli.rs` (including nested modules) and assigns each dependency to one of three architectural categories:

- **CLI** – crates and modules that exist to drive the command-line interface (argument parsing, console I/O, formatting helpers, utilities).
- **Runtime-Facade** – thin layers that bridge the CLI into the broader runtime entry points exposed by `rpp` (e.g., `crate::run`, runtime configuration types, metrics handles).
- **Subsystem** – imports that connect the CLI to discrete subsystems (crypto, storage, wallet, networking, verification tooling, async runtime helpers, etc.).

## Dependency Table

| Import | Category | Rationale |
| --- | --- | --- |
| `use std::collections::HashSet;` | CLI | Local data structure needed for CLI data shaping, not tied to a specific subsystem. |
| `use std::fmt;` | CLI | Implements `Display` for CLI error reporting. |
| `use std::fs;` | CLI | Handles filesystem interactions when commands read/write configs or outputs. |
| `use std::io::{self, Write};` | CLI | Manages stdout/stderr interactions and generic IO errors surfaced to the CLI. |
| `use std::path::{Path, PathBuf};` | CLI | Models CLI path arguments passed to commands. |
| `use std::process::ExitCode;` | CLI | Translates CLI result into process exit status. |
| `use std::sync::Arc;` | Subsystem | Used to share wallet instances while generating proofs (ties into crypto/wallet subsystem). |
| `use std::time::Duration;` | CLI | Provides timeout arguments parsed from CLI options. |
| `use crate::{BootstrapError, RuntimeMode, RuntimeOptions};` | Runtime-Facade | Bridges CLI invocations into the runtime bootstrapper provided by this crate. |
| `use anyhow::{anyhow, Context, Result};` | CLI | Generic error plumbing for CLI handlers. |
| `use clap::{Args, Parser, Subcommand};` | CLI | Primary CLI parser for command/argument definitions. |
| `use hex;` | Subsystem | Utility used for crypto key material formatting (crypto subsystem concern). |
| `use reqwest::Client;` | Subsystem | RPC HTTP client for telemetry/admission/uptime subsystems. |
| `use rpp_chain::crypto::{…};` | Subsystem | Direct interaction with validator crypto keystores and VRF key material. |
| `use rpp_chain::runtime::config::{…};` | Runtime-Facade | Consumes runtime configuration structures that the CLI loads/validates. |
| `use rpp_chain::runtime::RuntimeMetrics;` | Runtime-Facade | Wires runtime metrics reporting when launching the runtime. |
| `use rpp_chain::storage::Storage;` | Subsystem | Talks to the storage subsystem when certain commands require it. |
| `use rpp_chain::wallet::Wallet;` | Subsystem | Needed for uptime proof generation via the wallet subsystem. |
| `use rpp_p2p::{…};` | Subsystem | Covers admission-policy interactions with the P2P networking subsystem. |
| `use serde::{Deserialize, Serialize};` | CLI | Enables (de)serialization of CLI payloads, responses, and reports. |
| `use serde_json::Value;` | CLI | General-purpose JSON inspection/pretty-printing for CLI responses. |
| `use snapshot_verify::{…};` | Subsystem | Pulls in snapshot verification helpers that constitute their own subsystem/tooling. |
| `use tokio::task;` | Subsystem | Executes blocking wallet work on Tokio, tying into the async runtime subsystem. |
| `use super::*;` (inside `tests` module) | CLI | Test module needs all CLI definitions for verification; treated as part of the CLI layer. |
| `use serde_json::Value;` (inside `tests` module) | CLI | Re-imported locally for JSON assertions within CLI tests. |

