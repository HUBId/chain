# Security Policy

## Responsible Disclosure

We take the security of Firewood deployments seriously. If you believe you have
found a security vulnerability, please contact the maintainers privately at
`security@avalabs.org` or open a private report via the GitHub Security Advisory
program. Please include detailed reproduction steps, logs, and any proof of
concept material so the issue can be triaged quickly.

We aim to acknowledge new reports within **two business days** and provide an
initial assessment within **five business days**. During the investigation we
will keep you informed about remediation progress and coordinate public
disclosure so downstream operators have enough time to patch.

## Supply-Chain Verification

Release artifacts are built exclusively through the
[`.github/workflows/release.yml`](.github/workflows/release.yml) pipeline. The
workflow re-validates formatting, linting, `cargo audit`, and the full
integration test matrix before creating signed packages. Artifacts are signed
with [cosign](https://docs.sigstore.dev/cosign/) using GitHub OIDC identities
and accompanied by SBOMs and SHA256 manifests. You can verify the signatures by
running:

```bash
cosign verify-blob \
  --certificate-identity-regexp 'https://github.com/ava-labs/firewood/.+' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  --signature <artifact>.sig \
  <artifact>
```

Provenance attestations emitted by `scripts/provenance_attest.sh` bind each
artifact to the exact commit, workflow run, and build inputs.

## Audit and Advisory Handling

Security fixes must land through the protected CI/CD gates before release. All
patches—including hotfixes—run the release workflow’s checks and must ship with
updated SBOMs, cosign signatures, and provenance statements. For high-severity
findings we will prepare coordinated security advisories, draft mitigation
steps, and update the `RELEASES.md` runbook with any temporary controls or
rollbacks applied. Public advisories are published only after patched artifacts
are available and validated.

For more information about the release process and rollback/hotfix playbooks,
refer to [`RELEASES.md`](RELEASES.md).
