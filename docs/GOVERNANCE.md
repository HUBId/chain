# Governance and release policies

This playbook captures how the Firewood maintainers govern changes, ship
releases, and coordinate incident response. It complements the operational
runbooks and the security guidance in [`SECURITY.md`](../SECURITY.md).

## Change management

- **Runtime compatibility.** Feature additions must respect the documented
  runtime modes (`node`, `wallet`, `hybrid`, `validator`) and their telemetry
  expectations. Changes that alter CLI flags or config precedence require
  updates to the operator documentation before merge.【F:rpp/node/src/main.rs†L26-L115】【F:rpp/node/src/lib.rs†L143-L216】
- **Configuration validation.** All pull requests modifying configuration or
  feature-gate logic must retain the existing validation guarantees so invalid
  telemetry, secrets, or rollout settings fail fast during bootstrap.【F:rpp/node/src/lib.rs†L993-L1080】【F:rpp/runtime/config.rs†L915-L1076】
- **Documentation linkage.** When APIs, telemetry fields, or CLI options change,
  update the relevant security documents (`THREAT_MODEL`, `KEY_MANAGEMENT`,
  `API_SECURITY`) alongside code to keep operators aligned with implementation
  reality.
- **Branch protection.** Maintainers must keep the `fmt`, `clippy`,
  `tests-default`, `tests-stwo`, `tests-rpp-stark`, `snapshot-cli`,
  `observability-snapshot`, `simnet-admission`, and `runtime-smoke` GitHub
  Actions jobs configured as required status checks on the protected branch
  (`<PRIMARY_BRANCH_OR_COMMIT>`). When onboarding a new fork or
  environment, update the branch protection rule through the repository
  settings or the GitHub CLI:

  ```sh
  gh api \
    repos/:owner/:repo/branches/<PRIMARY_BRANCH_OR_COMMIT>/protection \
    --method PUT \
    --input - <<'JSON'
  {
    "required_status_checks": {
      "strict": true,
      "contexts": [
        "fmt",
        "clippy",
        "tests-default",
        "tests-stwo",
        "tests-rpp-stark",
        "snapshot-cli",
        "observability-snapshot",
        "simnet-admission",
        "runtime-smoke"
      ]
    }
  }
  JSON
  ```

  Re-run the command whenever workflow names change so merges cannot bypass the
  formatting, linting, or STWO test gates.

## Release workflow

Firewood releases are produced by the hardened CI pipeline described in
[`RELEASE.md`](../RELEASE.md) and [`RELEASES.md`](../RELEASES.md). Key
requirements include:

1. **Repeatable builds.** Tagged releases run through the `release` workflow,
   which rebuilds from source, reruns tests, and produces signed artifacts.
2. **Supply-chain evidence.** Each target ships with cosign signatures,
   provenance attestations, and CycloneDX SBOMs emitted by the release scripts.
   Operators verify them with `cosign verify-blob` using the GitHub OIDC
   identity.【F:SECURITY.md†L16-L40】【F:scripts/build_release.sh†L27-L147】
3. **Artifact retention.** Publish the generated SBOMs, signatures, and manifests
   alongside tarballs in the release to simplify downstream validation.【F:RELEASE.md†L16-L33】【F:RELEASES.md†L30-L64】

## Operational readiness gates

Before promoting a release to production, maintainers confirm:

- **Telemetry health.** Required telemetry endpoints are enabled for the target
  runtime mode and emit the expected signals (startup banners, exporter status,
  metrics streams).【F:docs/deployment_observability.md†L18-L112】【F:rpp/runtime/config.rs†L894-L912】
- **Secrets posture.** VRF keys load successfully through the configured backend
  (filesystem or Vault) and rotations succeed via the CLI helper commands.【F:docs/validator_quickstart.md†L111-L204】【F:rpp/node/src/main.rs†L54-L199】
- **RPC security.** Authentication tokens, request limits, and allowed origins
  are configured per the environment’s threat model, matching the guidance in
  [`API_SECURITY.md`](API_SECURITY.md).【F:config/validator.toml†L1-L70】【F:rpp/rpc/api.rs†L400-L520】

## Incident response and disclosure

- **Private reporting.** Security issues are reported through the channels in
  [`SECURITY.md`](../SECURITY.md); maintainers acknowledge within two business
  days and coordinate fixes before public disclosure.【F:SECURITY.md†L4-L41】
- **Hotfix process.** Critical patches ride the same release workflow, ensuring
  SBOMs and signatures stay in sync with binaries. Update `RELEASES.md` with any
  temporary mitigations or rollout deviations.【F:SECURITY.md†L32-L44】【F:RELEASES.md†L59-L88】
- **Post-incident actions.** After remediation, update this governance guide and
  related security docs to capture new controls or lessons learned.

Cross-reference [`THREAT_MODEL.md`](THREAT_MODEL.md) for risk context,
[`KEY_MANAGEMENT.md`](KEY_MANAGEMENT.md) for secrets handling, and
[`API_SECURITY.md`](API_SECURITY.md) for endpoint protections.
