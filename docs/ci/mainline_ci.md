# Mainline CI enforcement

The `Mainline CI` workflow enforces formatting, linting, security, testing, and
simulation coverage for every push to `main` and for every pull request. The
workflow fan-out produces dedicated artefacts so that regressions can be
triaged quickly and release qualification can re-use the same signals.

## Job overview

| Job name | Purpose | Notes |
| --- | --- | --- |
| `Validate dashboard exports` | Ensures Grafana JSON exports remain valid. | Runs on `ubuntu-latest`. |
| `rustfmt` | Enforces `cargo fmt --check` on stable. | Uses shared cache key `fmt`. |
| `clippy` | Runs `cargo clippy --workspace --all-targets --all-features -D warnings`. | Blocks until formatting succeeds. |
| `cargo audit` | Executes the advisory scan via `cargo audit --deny warnings` (pinned to 0.21.1 for Rust 1.79 compatibility). | Cache key `security-audit`. |
| `SBOM (CycloneDX)` | Generates a workspace SBOM (`ci-artifacts/sbom/workspace.json`). | Uploads artefact `sbom`. |
| `tests (stage • backend • os)` | Matrix job covering unit/integration suites across backends. | Currently runs on `ubuntu-latest` for `default` and `stwo` backends. Generates JUnit + JSON logs per run with retry-once logic. |
| `coverage (llvm-cov)` | Produces an `lcov.info` report using `cargo llvm-cov`. | Artefacts uploaded under `coverage`. |
| `simnet harness (stwo backend)` | Executes the deterministic libp2p simulator via `scripts/ci/sim_smoke.sh` using the pinned STWO nightly. | Artefacts uploaded under `simnet-smoke`. |
| `mainline gate` | Aggregates upstream job results and fails if any prerequisite job failed, was cancelled, or skipped. | Configure as the required status check for branch protection. |

All jobs share the global environment `CARGO_TERM_COLOR=always`. Workspace
builds and tests set `RUSTFLAGS=-D warnings` locally so that first-party code
fails on new warnings without breaking third-party cargo installs. Rust builds
use `Swatinem/rust-cache` to persist incremental artefacts between jobs.

### Test matrix details

The `tests` job runs with the following combinations:

- `unit` suite on `default` backend
- `integration` suite on `default` backend (plus targeted rerun of
  `reorg_regressions`)
- `unit` suite on `stwo` backend (pinned to `nightly-2025-07-14`)
- `integration` suite on `stwo` backend (with `reorg_regressions` focus rerun)

Each run captures the raw `cargo test --message-format json` stream and converts
it to JUnit via `cargo2junit`. The resulting directory per combination contains
both JSON logs and the corresponding JUnit XML files and is uploaded as an
artefact named `tests-<stage>-<backend>-<os>`.

### Simulator harness

The simulator job executes the libp2p harness with the deterministic `ci-sim`
feature and the STWO nightly toolchain. Artefacts from `target/sim-smoke*`
are exported to `ci-artifacts/sim-smoke` and uploaded for inspection. Set the
`CHAIN_SIM_BACKEND` environment variable to `stwo` when running locally to
mirror CI settings.

## Required status checks

Enable branch protection on `main` (and other protected branches) to require
`mainline gate` to pass before merging:

1. Navigate to **Settings → Branches → Branch protection rules**.
2. Edit the rule for `main` (or create a new rule if none exists).
3. Enable **Require status checks to pass before merging**.
4. Add `mainline gate` as a required status. GitHub will automatically expand
   the dependency chain and block merges if any upstream job is red or skipped.
5. Enable **Do not allow bypassing the above settings** and **Require branches
   to be up to date** if your compliance checklist requires them.

> ℹ️ The individual matrix children appear as distinct checks (for example,
> `tests (integration • stwo • ubuntu-latest)`), but they are already enforced
> via the aggregated `mainline gate` job. Only `mainline gate` needs to be
> explicitly required.

Once branch protection is updated, capture a screenshot of the "Branch
protection rule" dialog showing `mainline gate` as a required status and link it
from the internal runbook.

## Release parity

The `Release` workflow’s `checks` job now runs the same linters, advisory scans
(pinning `cargo-audit` to 0.21.1 for the Rust 1.79 toolchain),
and backend test suites as `Mainline CI`. It additionally executes the simulator
smoke tests under the STWO nightly toolchain before generating release artefacts
and release notes. Because release builds already invoke `cargo cyclonedx` while
assembling platform artefacts, SBOM coverage remains aligned between daily CI
and tagged releases.

## Artefact summary

- `sbom`: CycloneDX SBOM (`workspace.json`).
- `tests-*`: Per-matrix test logs (`cargo-test-attempt-*.json`) and JUnit XMLs.
- `coverage`: `lcov.info` suitable for coverage visualisation tooling.
- `simnet-smoke`: Simulator summary JSON plus deterministic harness logs.

Retain artefacts according to your compliance requirements (defaults to GitHub’s
retention policy). Attach direct links to a successful pipeline run once the new
workflow lands on `main` to document the green baseline.
