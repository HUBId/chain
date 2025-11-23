# Releasing the RPP workspace

The RPP workspace bundles the runtime (`rpp-node`, `rpp-chain`, `rpp-consensus`,
`rpp-p2p`, `rpp-pruning`), supporting cryptography crates (`rpp-crypto-vrf`,
`rpp-identity-tree`), prover backends (`prover-backend-interface`,
`plonky3-backend`, `prover_stwo_backend`), and the storage stack. This document
explains how to cut a release of that workspace. Review the companion
[secure release runbook](RELEASES.md) and [security policy](SECURITY.md) for the
CI/CD gates, signing requirements, and advisory coordination expectations that
apply to every tagged release.

## Documentation review checklist

Every release must confirm the core documentation touchpoints are up to date
before artifacts are published. At a minimum:

1. Review the [`rpp-node` operator guide](docs/rpp_node_operator_guide.md) and
   associated deployment notes to ensure CLI flags, runtime modes, and
   operational caveats match the release contents.
2. Walk through the security runbooks under [`docs/runbooks/`](docs/runbooks/)
   (incident response, snapshot recovery, Plonky3 rollout, pruning, etc.) and
   update mitigations, alert routing, and rollback procedures for any changes
   introduced this cycle.
3. Revalidate the admission and RPC policy reference
   ([`docs/network/admission.md`](docs/network/admission.md)) to capture new
   endpoints, authentication rules, rate limits, or privacy guarantees required
   by the release. Coordinate with policy approvers when changes are needed.

Capture the sign-off in the release tracking doc or PR description so the
review history is discoverable when tags are audited.

## Automated release pipeline

The release workflow defined in
[.github/workflows/release.yml](.github/workflows/release.yml) orchestrates
version tagging and artifact builds. It executes whenever a SemVer tag
(`vMAJOR.MINOR.PATCH`) is pushed or when manually triggered via the
`workflow_dispatch` input. The pipeline reruns formatting, clippy, the full
integration test suite, and `cargo audit` before producing platform-specific
artifacts. Optimised binaries for Linux (x86_64 and aarch64) and macOS (x86_64
and Apple Silicon) are packaged into tarballs for the main `rpp-node` CLI as
well as the dedicated runtime entry points (`node`, `wallet`, `hybrid`, and
`validator`). SBOMs, SHA256 manifests, cosign signatures, and provenance
attestations are published alongside the release assets.

### Support tier annotations

- Always create the canonical `vMAJOR.MINOR.PATCH` tag first so the workflow can
  build the release artifacts.
- Immediately follow with either an `lts/MAJOR.MINOR` tag (for builds covered by
  the 12-month support window) or an `exp/MAJOR.MINOR.PATCH` tag (for preview
  builds). Annotate the tag message with the rationale and a link to
  [`docs/wallet_support_policy.md`](docs/wallet_support_policy.md).
- If a Maintenance release is later promoted to LTS, reuse the same commit and
  add the `lts/MAJOR.MINOR` tag instead of rebuilding artifacts. Update the
  release body so auditors know when the promotion occurred.
- When generating artifacts outside of GitHub (for example during dry runs), set
  `SUPPORT_TIER` in the environment before invoking
  `scripts/build_release.sh`. The release manifest includes the tier value so the
  GitHub release job can mirror it in the published notes.

A dedicated `wallet-bundle` job also builds the reproducible
`wallet-bundle-<tag>-x86_64-unknown-linux-gnu.tar.gz` artifact by invoking
`cargo xtask wallet-bundle` with the pinned feature set. The job now emits
CycloneDX SBOMs for the CLI/lib/interface crates, writes
`dist/artifacts/wallet/SHA256SUMS.txt` (plus cosign signature), and attaches
per-artifact provenance statements before uploading the bundle, manifests, and
metadata so the publish step can reference the signed evidence in release
notes.【F:.github/workflows/release.yml†L214-L350】【F:.github/workflows/release.yml†L350-L420】

### Helper scripts

The workflow calls into helper utilities committed under `scripts/` so that the
same steps can be replicated locally:

- `scripts/build_release.sh` – builds and packages the binaries for a given
  target. It accepts `--target`, `--profile`, and `--tool` (either `cargo` or
  `cross`) flags and emits tarballs under `dist/artifacts/<target>/` together
  with an optional CycloneDX SBOM (`sbom-rpp-node-<target>.json`). Before the
  build starts the script runs the snapshot integrity regression test (`cargo
  test --locked --test root_corruption`) and aborts with a GitHub Actions error
  log if it fails. The script also blocks any `backend-plonky3` alias in the
  feature list, emitting `error: backend-plonky3 is experimental and cannot be
  enabled for release builds`. After the build completes, the script invokes
  `scripts/verify_release_features.sh` to guarantee that production artifacts do
  not link the mock prover backends. Set
  `RPP_RELEASE_BASE_FEATURES="--no-default-features --features prod,prover-stwo"`
  (append `,simd` to the feature list if you need SIMD locally) before calling
  the script to mirror the CI release workflow.
- `scripts/checksums.sh` – generates a sorted SHA256 manifest for a set of
  artifacts and writes it to the path supplied via `--output`.
- `scripts/verify_checksums.sh` – replays the manifest created by
  `scripts/checksums.sh` to guarantee the recorded hashes.
- `scripts/prepare_changelog.sh` – shells out to `git-cliff` for the requested
  tag and assembles release notes with required sections (features, fixes,
  breaking changes, security, upgrade notes). The script exits non-zero if the
  changelog data is missing or the tag is not SemVer compliant. When deterministic
  vectors under `vendor/rpp-stark/vectors/` change between the previous tag and
  the release candidate, the tool halts and asks maintainers to populate the new
  **🧬 ZK Vectors** section with the regeneration context before continuing.
- `scripts/provenance_attest.sh` – emits a SLSA v1 in-toto statement for the
  artifact, binds the active GitHub workflow as the builder, and signs the
  statement via cosign using GitHub OIDC credentials.
- `scripts/verify_release_features.sh` – inspects the cargo metadata and build
  fingerprints for a target triple to ensure the `backend-plonky3` and
  `prover-mock` features are never enabled when producing release binaries.
- `cargo xtask wallet-bundle` – builds the wallet CLI + GUI with reproducible
  feature sets, copies `config/wallet.toml`, writes `SHA256SUMS.txt`, and emits
  a signed manifest (`wallet-bundle-<version>-<target>-manifest.json`) next to
  the tarball.

Running the scripts locally mirrors the CI packaging process. For example, to
rehearse a Linux aarch64 release package you can execute:

```bash
cargo install --locked cargo-cyclonedx
RPP_RELEASE_BASE_FEATURES="--no-default-features --features prod,prover-stwo" \
  ./scripts/build_release.sh --target aarch64-unknown-linux-gnu --tool cross
./scripts/checksums.sh --output dist/SHA256SUMS.txt dist/artifacts/aarch64-unknown-linux-gnu/*.tar.gz dist/artifacts/aarch64-unknown-linux-gnu/*.json
./scripts/verify_checksums.sh --manifest dist/SHA256SUMS.txt
```

The release workflow consumes these same outputs, signs every artifact and
manifest with cosign, generates provenance via `scripts/provenance_attest.sh`,
and assembles the release notes generated by `scripts/prepare_changelog.sh` into
the GitHub release body.

To mirror the wallet runtime bundles produced in CI run:

```bash
cargo xtask wallet-bundle \
  --target x86_64-unknown-linux-gnu \
  --profile release \
  --version v0.1.0 \
  --output dist/artifacts
```

The command produces `dist/artifacts/wallet/x86_64-unknown-linux-gnu/` and
populates the directory with `wallet-bundle-v0.1.0-x86_64-unknown-linux-gnu.tar.gz`
plus a manifest that mirrors the one uploaded to GitHub releases. The tarball
contains `bin/rpp-wallet`, `bin/rpp-wallet-gui`, the sample config, and an
embedded `SHA256SUMS.txt` so operators can audit the bundle offline.

## Release pipeline checklist

Before publishing release artifacts, double-check the following guardrails:

1. Run `cargo test --locked --test root_corruption` and ensure the snapshot
   integrity regression passes before tagging a release. The automated workflow
   and `scripts/build_release.sh` will both exit early with an explicit error if
   this test fails.【F:.github/workflows/release.yml†L65-L106】【F:scripts/build_release.sh†L77-L102】
2. Execute the consensus manipulation regression suite via
   `cargo xtask test-consensus-manipulation` to confirm both the STWO and
   Plonky3 prover backends reject tampered VRF and quorum inputs. The release
   workflow aborts with a dedicated error if these negative tests fail so local
   runs should be clean before tagging.【F:.github/workflows/release.yml†L92-L103】
3. Run `cargo xtask proof-version-guard --base origin/main` whenever proof
   adapters, vectors, or verifier logic changed in this release. The guard
   walks the `rpp/zk/`, `rpp/proofs/`, `prover/`, and `vendor/rpp-stark/`
   directories (including golden vectors and tests) and fails if the
   corresponding `PROOF_VERSION` constants are unchanged. Pass `--base <ref>` to
   align with your release branch if it diverged from `origin/main`, and bump
   the version in `vendor/rpp-stark/src/proof/types.rs` (plus any other
   consumers) before publishing.【F:xtask/src/release.rs†L1-L208】
4. Describe any deterministic vector refreshes under
   `vendor/rpp-stark/vectors/` in the release notes. The changelog template now
   includes a dedicated **🧬 ZK Vectors** section, and `scripts/prepare_changelog.sh`
   will fail with a TODO if vector diffs are detected so you can link the
   regeneration evidence before publishing.
5. Build the workspace via `scripts/build_release.sh` with
   `RPP_RELEASE_BASE_FEATURES="--no-default-features --features prod,prover-stwo"`
   (append `,simd` if required) so the manual invocation matches CI. The script
   immediately exits if any `backend-plonky3` alias or the mock prover is
   requested via flags or environment variables.【F:scripts/build_release.sh†L80-L162】
6. Let the script run its automatic post-build verification. The bundled
   `scripts/verify_release_features.sh` inspects the generated metadata and
   fingerprints to ensure the resulting binaries did not link forbidden prover
   features.【F:scripts/build_release.sh†L160-L200】【F:scripts/verify_release_features.sh†L1-L115】
7. Produce the wallet runtime bundle via
   `cargo xtask wallet-bundle --target x86_64-unknown-linux-gnu --profile release --version <tag>`
   and verify both the embedded `SHA256SUMS.txt` and the cosign signature
   published alongside
   `wallet-bundle-<tag>-x86_64-unknown-linux-gnu-manifest.json`. After extracting
   the tarball run `sha256sum -c SHA256SUMS.txt` and verify the manifest with
   `cosign verify-blob --certificate wallet-bundle-<tag>-x86_64-unknown-linux-gnu-manifest.json.pem --signature wallet-bundle-<tag>-x86_64-unknown-linux-gnu-manifest.json.sig wallet-bundle-<tag>-x86_64-unknown-linux-gnu-manifest.json`.
8. If you are experimenting with non-default builds, rerun `cargo build` with the
   intended feature list and confirm that production profiles still refuse to
   compile when `backend-plonky3` is paired with `prod` or `validator`. The
   compile-time guard keeps the experimental stub out of production releases even
   before the packaging scripts execute.【F:rpp/node/src/feature_guard.rs†L1-L7】
9. Dry-run validator or hybrid binaries (`cargo run -p rpp-chain -- validator --dry-run` /
   `cargo run -p rpp-chain -- hybrid --dry-run`) to see the runtime guard in
   action—startup fails immediately if the STWO backend was omitted, ensuring the
   published artifacts activate the supported prover path.【F:rpp/node/src/lib.rs†L508-L536】
10. Capture the Plonky3 graduation evidence bundle: archive the
    `target/simnet/consensus-quorum` artefacts produced by the stress harness,
    export the Grafana dashboard JSON described in the Plonky3 runbook, and note
    the backout steps (feature guard, cache eviction, and incident checklist)
   referenced in the runbook/test plan so rollbacks remain auditable.【F:tools/simnet/scenarios/consensus_quorum_stress.ron†L1-L22】【F:scripts/analyze_simnet.py†L1-L200】【F:docs/runbooks/plonky3.md†L1-L200】【F:docs/testing/plonky3_experimental_testplan.md†L1-L160】

### Verifying wallet bundles

Wallet bundles published with each tag include two independent verification
paths:

1. **Embedded manifest.** The tarball contains `SHA256SUMS.txt`, which can be
   replayed via `sha256sum -c SHA256SUMS.txt` after extraction to ensure the CLI,
   GUI, and config files match the release manifest.
2. **Cosign signature.** The release uploads
   `wallet-bundle-<tag>-x86_64-unknown-linux-gnu-manifest.json` plus the
   `.sig/.pem` pair generated by the CI workflow. Consumers can run
   `cosign verify-blob --certificate wallet-bundle-<tag>-x86_64-unknown-linux-gnu-manifest.json.pem --signature wallet-bundle-<tag>-x86_64-unknown-linux-gnu-manifest.json.sig wallet-bundle-<tag>-x86_64-unknown-linux-gnu-manifest.json`
   before unpacking the tarball to ensure the manifest and the GitHub workload
   identity both verify.

## Branching and tagging

Start each release by creating a dedicated branch from `main` and naming it
with the target version. For example:

```console
$ git fetch
$ git switch -c release/v0.1.0 origin/main
branch 'release/v0.1.0' set up to track 'origin/main'.
Switched to a new branch 'release/v0.1.0'
```

Tags must continue to follow the `vMAJOR.MINOR.PATCH` pattern so the release
workflow accepts them. The tag name should match the versions written to the
crates below.

### Wallet tagging & signed bundles

Wallet releases now piggyback on the main workspace process but still publish a
wallet-specific tag for downstream automation:

1. Run `scripts/build_release.sh` with the production feature list to produce the
   Linux/macOS/Windows artifacts (as described above) and follow with
   `cargo xtask wallet-bundle --target <triple> --profile release --version <tag>`
   for each supported target so the CLI + GUI tarballs exist before tagging.【F:scripts/build_release.sh†L77-L200】【F:xtask/src/wallet_bundle.rs†L40-L220】
2. Verify the embedded `SHA256SUMS.txt` and manifest signatures for every bundle,
   then sign the Git tag locally via `git tag -s wallet-vX.Y.Z` pointing at the
   same commit as the canonical `vX.Y.Z` tag. Push both tags so GitHub releases
   can attach the wallet bundle manifests alongside the runtime artifacts.
3. Update the release notes with links to `docs/wallet_monitoring.md` and
   `docs/wallet_platform_support.md` so operators know where to find the runtime
   dashboards and cross-platform smoke tests referenced in their runbooks.

Following this checklist keeps the packaging scripts (Task 56) and tagging flow
aligned—the same artifacts you validated locally are the ones auditors download
from the published tag.

## Version management

All workspace crates shipped in the RPP release must agree on the new version.
Use the checklist below before cutting a tag:

1. Update the workspace package version in the root [`Cargo.toml`](Cargo.toml):

   ```toml
   [workspace.package]
   version = "0.1.0"
   ```

   Crates that set `version.workspace = true` (for example `rpp-chain`,
   `rpp-pruning`, the storage crates, and the legacy firewood utilities) inherit
   this value automatically.

2. Bump the standalone crates that declare their own versions:

   - `rpp/node/Cargo.toml`
   - `rpp/consensus/Cargo.toml`
   - `rpp/p2p/Cargo.toml`
   - `rpp/crypto-vrf/Cargo.toml`
   - `rpp/identity-tree/Cargo.toml`
   - `prover/plonky3_backend/Cargo.toml`
   - `prover/prover_stwo_backend/Cargo.toml`
   - `rpp/zk/backend-interface/Cargo.toml`

   These crates currently target the same SemVer line as the tag (e.g.
   `0.1.0`) except for `prover_stwo_backend`, which tracks the vendored STWO
   version and only changes when that dependency is updated. Adjust that version
   only when the vendor update requires it.

3. Refresh the shared dependency declarations in the workspace table so other
   crates pick up the new versions via `workspace = true`:

   ```toml
   [workspace.dependencies]
   # Workspace crates published with each release
   rpp-chain = { path = "rpp/chain", version = "0.1.0", default-features = false }
   rpp-crypto-vrf = { path = "rpp/crypto-vrf", version = "0.1.0" }
   rpp-identity-tree = { path = "rpp/identity-tree", version = "0.1.0" }
   rpp-pruning = { path = "rpp/pruning", version = "0.1.0" }
   prover-backend-interface = { path = "rpp/zk/backend-interface", version = "0.1.0" }
   plonky3-backend = { path = "prover/plonky3_backend", version = "0.1.0", default-features = false }
   prover_stwo_backend = { path = "prover/prover_stwo_backend", version = "1.0.0", default-features = false }
   ```

   When adding new workspace crates, ensure they appear in this table with the
   correct path and any required feature overrides so releases remain
   reproducible.

4. Verify the consuming crates inherit from the workspace table instead of
   hard-coding versions. For example `rpp-chain` illustrates the recommended
   `[package]` stanza:

   ```toml
   [package]
   name = "rpp-chain"
   version.workspace = true
   edition.workspace = true
   license-file.workspace = true
   repository.workspace = true
   ```

   This keeps downstream consumers aligned with the top-level release number and
   avoids drift.

## Changelog

To build the changelog, run `git-cliff` using the pending tag. The helper script
used by CI can also be run locally:

```sh
cargo install --locked git-cliff
./scripts/prepare_changelog.sh --tag v0.1.0 --output dist/release-notes.md
```

## Review checklist

> ❗ Ensure the workspace version, crate versions, dependency entries, and
> changelog are updated before creating a new release. Open a PR with these
> changes and merge it before tagging.

## Publish the tag

Trigger the release by pushing a signed tag that matches the updated versions:

```sh
git tag -s -a v0.1.0 -m 'Release v0.1.0'
git push origin v0.1.0
```

The CI release workflow will automatically publish a draft GitHub release that
includes the notes generated by `scripts/prepare_changelog.sh`, packaged
artifacts, SBOMs, and signatures.

## Post-release follow-up

Close the GitHub milestone for the version that was released. Create a new
milestone for the next version if one does not already exist and move any open
work forward. Coordinate staged roll-outs and monitoring according to the
[deployment runbooks](docs/deployment/staged_rollout.md).
