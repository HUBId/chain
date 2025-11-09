# `xtask` Docker helper

This image packages the workspace `xtask` helper so that CI jobs or local scripts can
run the same subcommands without requiring a toolchain installation. The image is built
via the multi-stage `xtask/Dockerfile` which compiles the binary with a nightly Rust
compiler and copies the resulting artefact into a minimal non-root runtime stage.

## Building the image

```bash
docker build -f xtask/Dockerfile -t chain-xtask .
```

The builder stages cache Rust dependencies by using [`cargo-chef`](https://github.com/LukeMathWalker/cargo-chef).
After the initial build, subsequent builds only recompile the helper when the crate or
its dependencies change.

## Runtime usage

The runtime stage ships only the compiled binary and creates an unprivileged `xtask`
user. The container entrypoint is set to the helper, so container invocations mirror the
local developer workflow:

```bash
# List available subcommands
docker run --rm chain-xtask --help

# Execute a workspace task
# Remember to mount the repository into the container so the helper can operate on it.
docker run --rm \
  -v "$(pwd)":/workspace \
  -w /workspace \
  chain-xtask test-unit
```

Any arguments provided after the image name are forwarded directly to the helper.

## Environment overrides

Several tasks honour environment variables that control optional behaviours. Pass them
with `-e` when invoking the container:

| Variable | Purpose |
| --- | --- |
| `XTASK_FEATURES` | Comma separated list of Cargo features forwarded to `cargo` invocations. |
| `XTASK_NO_DEFAULT_FEATURES` | When set to a non-empty value, disables default Cargo features for downstream builds. |
| `OBSERVABILITY_METRICS_*` | Configure targets, headers, authentication and timeouts for `xtask telemetry` commands. |
| `SNAPSHOT_*` | Provide snapshot metadata, RPC endpoints and auth tokens for snapshot verification helpers. |
| `ADMISSION_*` | Inject RPC endpoints, tokens and policy overrides for admission policy workflows. |
| `TIMETOKE_*` / `PROMETHEUS_*` | Control Prometheus scraping endpoints for time-to-ke metrics exporters. |
| `PLONKY3_*` | Provide signatures, toolchain revisions and filters for Plonky3 circuit verification. |

Consult the [`xtask` source code](./src) for the exhaustive list of supported variables
and semantics.

## CI integration

The image is well suited for CI pipelines that need reproducible helper invocations. A
typical job mounts the repository checkout and reuses existing caches for workspace
artifacts:

```yaml
steps:
  - uses: actions/checkout@v4
  - name: Build xtask helper image
    run: docker build -f xtask/Dockerfile -t chain-xtask .
  - name: Run unit workflow
    run: >-
      docker run --rm \
        -v "$PWD":/workspace \
        -w /workspace \
        -e XTASK_NO_DEFAULT_FEATURES=1 \
        -e XTASK_FEATURES="prod,backend-plonky3" \
        chain-xtask test-unit
```

Reuse the same image across multiple jobs to invoke other subcommands such as
`test-integration`, `simnet-smoke` or `telemetry` without re-installing Rust.
