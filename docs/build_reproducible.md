# Reproducible wallet builds

Wallet release artifacts must be reproducible so operators and auditors can
verify byte-for-byte parity between locally built bundles and the binaries
published in distribution channels. This document covers the toolchain layout,
`REPRO_MODE` build switches, the deterministic wallet bundle builder, and the
`scripts/repro_check.sh` harness that compares two fresh builds.

## Toolchains and feature gates

* Wallet crates compile on the stable toolchain recorded in
  `rust-toolchain.wallet.toml` (`channel = "1.79.0"`). `scripts/build.sh`
  automatically selects that channel when you target `rpp-wallet`,
  `rpp-wallet-lib`, `rpp-wallet-interface`, or their binaries. You can override
  the value by exporting `CHAIN_WALLET_TOOLCHAIN=<channel>`.
* STWO prover integrations stay behind the new
  `--features prover_stwo_backend` gate. The alias enables the existing
  `prover-stwo` feature so downstream crates keep their `#[cfg(feature =
  "prover-stwo")]` guards without churn. Builds that omit
  `prover_stwo_backend` stay on the stable toolchain and only include the mock
  prover.
* When you opt into STWO locally (for example during internal testing), pass
  `--cli-features "runtime,prover_stwo_backend"` /
  `--gui-features "runtime,wallet_gui,prover_stwo_backend"` to
  `cargo xtask wallet-bundle` so the nightly-only backend is explicit.

## `REPRO_MODE=1`

Setting `REPRO_MODE=1` enables deterministic build settings across the helper
scripts and xtask targets:

* `SOURCE_DATE_EPOCH` defaults to the timestamp of the latest commit (via
  `git log -1 --format=%ct`). Override it manually when you need to reproduce an
  older release.
* `RUSTFLAGS` automatically receives a consistent
  `--remap-path-prefix=/path/to/repo=/repro/workspace` entry so debug info and
  panic messages never leak local filesystem paths.
* The cargo profile defaults to `repro` (a derivative of `release` with
  `codegen-units = 1`, `lto = "fat"`, and `strip = false`). Export
  `CARGO_PROFILE`/`--profile` explicitly if you need another profile.
* The wallet bundle manifest derives `generated_at` from `SOURCE_DATE_EPOCH` so
  the timestamp cannot leak wall-clock time.

You can combine `REPRO_MODE=1` with `scripts/build.sh`, `cargo xtask wallet-
bundle`, or ad-hoc `cargo` invocations. Scripts set every environment variable
per command so other targets continue to build normally.

## Wallet bundle workflow

1. Pin your target triple and version string. For example:

   ```bash
   export TARGET_TRIPLE=x86_64-unknown-linux-gnu
   export WALLET_VERSION=v0.1.0
   ```

2. Build the CLI and GUI binaries with the stable toolchain:

   ```bash
   REPRO_MODE=1 cargo xtask wallet-bundle \
     --target "${TARGET_TRIPLE}" \
     --version "${WALLET_VERSION}" \
     --output dist/artifacts
   ```

   The command runs `cargo +1.79.0 build` under the hood, disables default
   features, and enables `runtime`, `wallet_gui`, `prover-mock`, and `backup` by
   default. Add `--cli-features`/`--gui-features` overrides as needed.

3. Inspect the output under `dist/artifacts/wallet/<target>/`—the tarball,
   manifest copy, `VERSION`, configs, and checksum manifests all derive their
   metadata from `SOURCE_DATE_EPOCH`.

## Local verification with `scripts/repro_check.sh`

`scripts/repro_check.sh` automates the two-build comparison recommended by
reproducible-builds.org:

```bash
scripts/repro_check.sh --target x86_64-unknown-linux-gnu --version v0.1.0
```

The helper:

1. Creates `target/repro-check/run{1,2}` and assigns each run its own
   `CARGO_TARGET_DIR`.
2. Exports `REPRO_MODE=1` and (if unset) `SOURCE_DATE_EPOCH` from the current
   git commit.
3. Invokes `cargo xtask wallet-bundle` twice, followed by
   `cargo xtask wallet-installer` when that subcommand exists.
4. Compares `run1/dist` and `run2/dist` recursively. Any difference produces a
   diff on stderr and a non-zero exit code.

You can forward additional options with repeated `--bundle-arg` or
`--installer-arg` flags. For example, pass `--bundle-arg --cli-features` and
`--bundle-arg runtime,prover_stwo_backend` to opt into the STWO backend in both
runs.

## Troubleshooting

* **`git log` errors:** Ensure the repository contains at least one commit and
  that you are inside the repo root. Override `SOURCE_DATE_EPOCH` manually if
  you are building from an exported archive without git metadata.
* **`tomllib` import errors:** Python 3.11+ is required for
  `scripts/build.sh`/`scripts/repro_check.sh` to parse `rust-toolchain.wallet.toml`.
  Install a recent Python or export `CHAIN_WALLET_TOOLCHAIN` with your preferred
  channel.
* **`wallet-installer not found` warning:** The reproducibility harness prints a
  warning and skips installer comparisons when the xtask subcommand is absent.
  This is expected until the installer builder lands; once it does, make sure it
  is on your `$PATH` so both bundle and installer artifacts are compared.
* **`diff` shows mismatched tarballs:** Re-run `scripts/repro_check.sh` with
  `--bundle-arg --verbose` (or any other tracing flag you add to the builders)
  to collect logs. Differences typically stem from unclean work trees, unpinned
  dependencies, or stale `SOURCE_DATE_EPOCH` values.

## CI integration

Surface mismatches in CI by adding a job that runs the helper inside a clean
container:

```yaml
- name: Wallet reproducibility check
  run: scripts/repro_check.sh --target x86_64-unknown-linux-gnu --version ${{ github.sha }}
```

The job will exit non-zero if `diff -rq` finds any difference, bubbling the
failure up to the overall workflow. Capture the emitted diff in the job logs so
maintainers can spot which file diverged. Pair this job with artifact uploads of
both `run1/dist` and `run2/dist` to aid debugging.
