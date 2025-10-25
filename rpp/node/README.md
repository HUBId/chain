# rpp-node

The `rpp-node` crate bundles the binary entrypoint for running a Rollup Privacy
Project (RPP) full node. It wires the consensus, storage, P2P networking, RPC,
and telemetry subsystems into an executable that can be configured through a
TOML file or command-line flags.

## Features & dependencies

`rpp-node` re-exports most of its functionality from the `rpp-chain` crate and
shares the same dependency graph. The available cargo features toggle which
proving backend is compiled in:

| Feature            | Description                                                          | Default |
| ------------------ | -------------------------------------------------------------------- | ------- |
| `prover-stwo`      | Enables the STWO proving backend.                                     | ✅      |
| `prover-stwo-simd` | Extends `prover-stwo` with optional SIMD acceleration where available. | ⬜️      |
| `prover-mock`      | Swaps in a lightweight mock prover useful for tests and local setups. | ⬜️      |

To run with a different backend, disable the default feature and select the one
you need, e.g.:

```bash
cargo run -p rpp-node --no-default-features --features prover-mock
```

## Example configuration

Node behaviour is primarily driven by a TOML configuration. A minimal example
that showcases the most commonly tweaked values looks like this:

```toml
config_version = "1.0"
data_dir = "./data"
key_path = "./keys/node.toml"
vrf_key_path = "./keys/vrf.toml"
rpc_listen = "127.0.0.1:8545"
block_time_ms = 2000
max_block_transactions = 512
mempool_limit = 4096

[rollout.telemetry]
enabled = true
endpoint = "https://telemetry.example.com/ingest"
auth_token = "super-secret-token"
sample_interval_secs = 30

[p2p]
listen_addr = "/ip4/0.0.0.0/tcp/7600"
```

Every field in the config can be overridden at runtime through flags if you need
to make temporary changes without touching the file.

## CLI reference

The binary exposes a number of flags for common overrides:

| Flag | Purpose |
| ---- | ------- |
| `--config <PATH>` | Load configuration from the given TOML file (defaults to the built-in defaults).
| `--data-dir <PATH>` | Override `data_dir`.
| `--rpc-listen <ADDR>` | Override `rpc_listen` with a socket address such as `0.0.0.0:8545`.
| `--rpc-auth-token <TOKEN>` | Override `rpc_auth_token`. Pass an empty string to clear it.
| `--telemetry-endpoint <URL>` | Override `rollout.telemetry.endpoint`. Empty strings disable telemetry.
| `--telemetry-auth-token <TOKEN>` | Override `rollout.telemetry.auth_token`. Empty strings clear the token.
| `--telemetry-sample-interval <SECS>` | Override `rollout.telemetry.sample_interval_secs` (seconds).
| `--log-level <LEVEL>` | Override the log level (`info`, `debug`, etc.).
| `--log-json` | Emit structured JSON logs.
| `--write-config` | Persist the effective configuration to `node.toml` in the current directory.

You can inspect the full list at any time with `cargo run -p rpp-node -- --help`.

The TOML configuration exposes additional knobs for fine-tuning the telemetry pipeline:

- `rollout.telemetry.http_endpoint` selects the OTLP/HTTP collector for metrics while `endpoint` continues to control the gRPC span exporter.
- `trace_max_queue_size`, `trace_max_export_batch_size`, and `trace_sample_ratio` size the bounded exporter and sampling strategy; keeping `warn_on_drop = true` surfaces warnings when the queue overflows so operators can react before spans are lost.
- Nested `grpc_tls` and `http_tls` tables accept TLS material (`ca_certificate`, `client_certificate`, `client_private_key`, `domain_name`) when collectors require mutual authentication.【F:rpp/runtime/config.rs†L1632-L1707】【F:rpp/runtime/telemetry/exporter.rs†L21-L210】

## Logging & shutdown

On startup the node logs the configured RPC, telemetry, and P2P endpoints so you
can quickly verify that overrides have been applied. Structured JSON logs are
available via `--log-json`, otherwise human-readable logs are used.

The process listens for `CTRL+C` (and `SIGTERM` on Unix) to trigger a graceful
shutdown. When a signal is received the node stops new work, waits for the
runtime to exit cleanly, and then terminates.
