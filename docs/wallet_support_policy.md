# Wallet Support Policy

This policy defines the wallet configurations, release tiers, and security maintenance
expectations for the RPP stack. It complements the wallet operator guides,
release runbooks, and feature guard tests so that stakeholders know which build
combinations remain supported long term and which legacy modes are on a removal
path.

## Support tiers

| Tier | Description | Lifecycle commitment |
| --- | --- | --- |
| **Long-Term Support (LTS)** | Wallet bundles signed from `vMAJOR.MINOR.PATCH` tags that also carry an `lts/MAJOR.MINOR` annotation. LTS builds are produced by the release workflow under `.github/workflows/release.yml` and include the `prod` runtime with the STWO prover backend (`prover-stwo` or `prover-stwo-simd`). | Receives critical security fixes and compatibility updates for 12 months after the initial LTS announcement. Feature work is limited to non-breaking toggles and documentation updates. |
| **Maintenance** | Regular SemVer tags (no extra annotation) that ship once a feature is production ready but before it is promoted to LTS. These builds still require the STWO backend but may enable preview knobs such as `wallet_gui` or `wallet_hw`. | Receives security fixes and regressions for 6 months or until superseded by the next Maintenance release. |
| **Experimental** | Tags prefixed with `exp/MAJOR.MINOR.PATCH` (pushed alongside the canonical SemVer tag) or any run produced by the nightly release rehearsal workflow. These builds are intended for testnets and feature trials. | Receives best-effort support only; fixes may land exclusively in future Maintenance or LTS tags. No security SLA is provided. |

## Release tagging and CI integration

1. Every supported release pushes the canonical `vMAJOR.MINOR.PATCH` tag to trigger
   `.github/workflows/release.yml`.
2. Immediately after publishing release notes, push an annotated `lts/MAJOR.MINOR`
   or `exp/MAJOR.MINOR.PATCH` tag to describe the support tier selected for that
   build. The release job archives the annotations so auditors can confirm the
   intended tier.
3. When promoting a Maintenance release to LTS, reuse the existing Git commit but
   create the `lts/MAJOR.MINOR` tag and update the release description to link
   back to this policy. No rebuild is required as long as the original release
   artifacts remain intact.
4. For nightly or preview builds, set the `SUPPORT_TIER=experimental` environment
   variable before calling `scripts/build_release.sh` so the metadata embedded in
   `dist/artifacts/*/manifest.json` documents the tier selected. The production
   release pipeline reads the same metadata to render the release body.

## Supported configuration matrix

### Long-term commitments

| Configuration | Support tier | Notes |
| --- | --- | --- |
| Wallet runtime compiled with `--no-default-features --features prod,prover-stwo` (or `prover-stwo-simd`) paired with `[wallet.rpc.security]` and the `wallet_rpc_mtls` feature. | LTS | This is the canonical production posture. Operators may enable optional features such as `wallet_multisig_hooks` and `wallet_hw` provided the corresponding configuration scopes are set. |
| Hybrid node/wallet deployments launched via `scripts/run_hybrid_mode.sh` with embedded nodes configured under `[wallet.node]`. | Maintenance → LTS | The hybrid profile inherits the same STWO requirements as standalone nodes. Support extends to observability knobs exposed via `wallet.gui` once promoted to LTS. |
| GUI-enabled wallet bundles (`wallet_gui` feature) distributed through `cargo xtask wallet-bundle`. | Maintenance | GUI binaries remain optional but are tested in CI. Expect promotion to LTS once accessibility and localization audits complete. |

### Legacy and deprecated combinations

| Mode / feature combination | Current status | Target removal window | Migration guidance |
| --- | --- | --- | --- |
| **CLI-only wallet builds** (wallet binary compiled without RPC or GUI features and operated solely via `rpp-wallet` CLI flags). | Deprecated | Earliest removal in `v0.13` (Q4 2025). | Transition to the RPC-enabled runtime. Preserve scripts by driving the same commands through the authenticated RPC endpoints or the GUI automation hooks documented in `docs/wallet_phase4_advanced.md`. |
| **Mock prover without STWO** (`prover-mock` feature, no `prover-stwo*`). | Unsupported | Immediately blocked in CI; removal of the feature flag scheduled for `v0.12`. | Rebuild with `--features prod,prover-stwo` or `prover-stwo-simd`. CI (`scripts/verify_release_features.sh`) already rejects tags that rely on the mock backend. |
| **Bearer-token-only RPC** (authentication via `RPP_WALLET_RPC_AUTH_TOKEN` without `[wallet.rpc.security]` mTLS). | Sunsetting | Support ends when `v0.12` is released. | Enable `[wallet.rpc.security]`, set `wallet.rpc.security.mtls_required = true`, and compile with the `wallet_rpc_mtls` feature. Clients must present certificates or migrate to mutually authenticated tunnels. |
| **Mock Electrs without STWO witness tracking** (using `[wallet.watch_only]` without embedded prover features). | Deprecated | Removal targeted for `v0.14`. | Enable watch-only projections only after compiling with `wallet_zsi` and `wallet_rpc_mtls` so witness streams and identity proofs stay in sync. |

The removal windows above are communicated at least two releases in advance. If an operator needs an extension for regulatory reasons, create an issue referencing this document so the release committee can triage the request.

## Migration guidance

1. **CLI-only operators:** Run `cargo xtask wallet-bundle --features prod,prover-stwo` and switch automation to RPC calls authenticated via mTLS. The CLI will continue to exist for debugging, but unattended usage should move to the RPC server.
2. **Mock prover users:** Remove `prover-mock` from build scripts and verify the STWO backend compiles on the deployment hardware. Use the `prover-stwo-simd` variant if the CPU supports SIMD instructions; otherwise stay on the scalar backend.
3. **Bearer-token-only RPC:** Issue client certificates via your existing PKI or the sample scripts in `docs/wallet_phase4_advanced.md`. Update health probes (`RPP_WALLET_HEALTH_HEADERS`) to include the new TLS metadata.
4. **Watch-only projections without STWO:** Ensure `wallet_zsi` is compiled in before turning on `[wallet.watch_only]`. Run the ZSI smoke tests in `tests/feature_guard.rs` locally if you patch related code.

## Security update expectations

- LTS releases receive emergency security fixes, dependency updates, and critical regression patches for 12 months. Patches land on the release branch and are tagged with `vMAJOR.MINOR.PATCH+hotfix` before being merged back to `main`.
- Maintenance releases receive fixes for 6 months or until the next Maintenance tag supersedes them. Hotfixes are cherry-picked rather than rebuilt from scratch.
- Experimental builds are provided without any security SLA. Vulnerability disclosures will reference the newest Maintenance or LTS tags that carry the fix.
- All tiers rely on the security reporting workflow in `SECURITY.md`; critical CVEs are embargoed until patches are available for all supported tiers.

## Minimum system requirements

| Component | Requirement |
| --- | --- |
| Operating system | 64-bit Linux kernel 5.10+ or macOS 13+ with developer tools installed. |
| CPU | 8 physical cores with AVX2 (for SIMD-enabled STWO) or equivalent scalar performance. |
| Memory | 16 GB RAM minimum; 32 GB recommended for hybrid node/wallet deployments. |
| Storage | 250 GB NVMe SSD for Firewood state, logs, and witness caches. |
| Tooling | Rust 1.79.0 toolchain plus `protoc`, `make`, and optional `nightly-2025-07-14` when touching prover crates. |

Environments that do not meet these requirements fall outside the support scope. Operators may need to reserve additional capacity for Electrs or observability sidecars.

## Reporting

Questions about tier selection or migration timelines should be filed as GitHub issues tagged `support-policy`. Release managers should paste a link to this document in every release announcement and in the `RELEASE_NOTES.md` entry summarizing the cycle.
