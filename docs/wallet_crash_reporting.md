# Wallet crash reporting

The wallet runtime installs a panic hook and intercepts fatal signals (SIGABRT,
SIGBUS, SIGFPE, SIGILL, SIGSEGV) whenever crash reporting is enabled via the
`[wallet.telemetry]` section of `config/wallet.toml`. Crash metadata includes
only build identifiers, the OS/architecture, enabled Cargo features, redacted
stack traces, and a salted machine identifier. Wallet secrets, keystores, draft
transactions, and RPC payloads are **never** serialized.

Crash reports are written to `<wallet.engine.data_dir>/crash_reports` before any
network access occurs. The spool is capped at ~10 MiB, with the oldest entries
pruned first. Each crash report carries an `acknowledged` flag and is uploaded
only after the operator explicitly confirms it through the CLI or GUI. Uploads
use HTTPS POST requests with exponential backoff and offline retry. Operators
may disable crash reporting entirely, change the HTTPS endpoint, or rotate the
machine-id salt without touching the rest of the configuration.

CLI operators can inspect the status, enable/disable uploads, view stored
reports, and acknowledge entries via `wallet telemetry crash-reports …`. The
Iced GUI exposes the same opt-in toggle and provides a modal dialog for viewing
recent crashes from the local spool. These flows are designed so operators
retain full control over what leaves their machines.
