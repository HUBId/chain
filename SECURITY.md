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

## Incident coordination and telemetry escalation

Security liaisons participate in the production on-call rotation. When a
telemetry alert suggests compromise, follow the
[telemetry alert response procedures](docs/observability.md#telemetry-alert-response-procedures)
and request a security consult within **15 minutes** if the signal implicates
credential misuse, data exfiltration, or abusive traffic. Page the
`security-duty` escalation path in PagerDuty, reference the active incident
identifier, and capture investigative notes in the shared log. Security will
assist with containment, initiate the incident-response checklist, and maintain
communication with affected stakeholders until recovery and post-incident
reviews are complete.

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
  --certificate-identity-regexp 'https://github.com/ava-labs/chain/.+' \
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

The main CI workflow includes a **Dependency advisories** job that executes
`cargo audit --deny warnings` against `Cargo.lock`. The step installs
[`cargo-audit`](https://github.com/rustsec/rustsec/tree/main/cargo-audit),
primes the advisory database cache, and fails the run when RustSec advisories or
warnings are detected. Operators who see this job fail should review the linked
RustSec report, update or patch the affected dependency, and land the fix in the
same pull request. If the advisory is a false positive or cannot be addressed
immediately, follow the risk-acceptance process and document the justification
in the corresponding issue or release notes before applying a temporary ignore.

## Panic hygiene and invariants

Production crates deny `panic!`, `.unwrap()`, and `.expect()` through Clippy. Any
new code that needs to assume unreachable states must either return structured
errors or document why a panic is unavoidable. When an invariant must be
asserted, scope the exception narrowly with `#[allow(clippy::expect_used)]` or
`#[allow(clippy::unwrap_used)]`, include a justification comment, and prefer to
recover gracefully whenever possible. Test modules may continue to use the
operations for brevity, but the allow must remain confined to the test scope so
runtime paths stay panic-free.

For more information about the release process and rollback/hotfix playbooks,
refer to [`RELEASES.md`](RELEASES.md).

## Secret rotation and credential hygiene

The project inventories every long-lived secret stored in source control, CI,
or deployment environments and rotates them on a strict cadence. The table
below summarises the baseline schedule, supporting tooling, and accountable
roles:

| Secret class | Storage/backing | Rotation cadence | Tooling / automation | Accountable role |
| --- | --- | --- | --- | --- |
| GitHub Actions environments (CI tokens, release PATs, registry passwords) | GitHub Actions encrypted secrets | Every 90 days, or immediately after team membership changes | GitHub CLI (`gh secret set`) with workflow validation via `.github/workflows/ci.yml` dispatch runs | Security Engineering duty officer |
| Deployment keys for validator, wallet, and pipeline infrastructure | Vault KV backends or restricted filesystem stores | Every 60 days; additionally before major upgrades or cluster re-provisioning | `vault kv put` or OS key stores, with spot checks using `rpp-node` dry runs | Infrastructure/SRE rotation |
| VRF and runtime secrets (telemetry tokens, admission credentials) | Runtime secrets backend configured per validator | Every 30 days, aligned with validator maintenance windows | `cargo run -p rpp-chain -- validator vrf rotate` and REST helpers, also exercised in automation described in [`docs/validator_tooling.md`](docs/validator_tooling.md) | Validator operations rotation |

### Emergency revocation

1. Disable or delete the compromised secret in its upstream system (GitHub
   environment, Vault path, or filesystem mount) and document the incident log.
2. Trigger the relevant rotation tooling with freshly generated material. For
   VRF and runtime secrets use the CLI flows captured in the operator checklists
   (`validator vrf rotate` / `validator vrf inspect`).【F:docs/checklists/operator.md†L24-L34】【F:docs/validator_tooling.md†L5-L66】
3. In GitHub, immediately invalidate active workflow runs that depended on the
   revoked credential and re-run the `.github/workflows/ci.yml` smoke matrix to
   ensure no pipeline still references the stale value.【F:.github/workflows/ci.yml†L1-L400】
4. Notify the Security Engineering duty officer and affected service owners; if
   deployment keys are impacted, coordinate with the Infrastructure/SRE rotation
   to reprovision downstream hosts before returning them to service.

### Post-rotation verification

* **CI credentials:** Dispatch `ci.yml` and `release.yml` workflows to confirm
  GitHub secrets decrypt correctly and downstream registries accept the new
  tokens.【F:.github/workflows/ci.yml†L1-L400】【F:.github/workflows/release.yml†L1-L320】
* **Deployment keys:** Run non-destructive dry runs (`cargo run -p rpp-chain -- <mode> --dry-run`)
  against each environment to ensure secrets resolve and permission checks pass
  before opening traffic.【F:docs/checklists/operator.md†L8-L20】
* **Runtime secrets:** Inspect the rotated material with
  `cargo run -p rpp-chain -- validator vrf inspect` or the `/validator/vrf` RPC endpoint to verify
  that the correct backend and identifier are active, as documented in the
  validator tooling guide.【F:docs/validator_tooling.md†L15-L64】

## Wallet keystore hardening

`wallet init` now produces an encrypted keystore that records Argon2id KDF
parameters (64 MiB memory, 3 iterations, single thread), a random salt, and the
ChaCha20-Poly1305 nonce alongside the ciphertext. Passphrases may be supplied
interactively, through `--passphrase-file`, `--passphrase-env`, or direct CLI
arguments, and plaintext files are migrated on first load. Operators should:

- store passphrases in dedicated secret stores (e.g., Vault) and reference them
  via environment variables or files rather than embedding them in shell
  history;
- rotate passphrases when migrating keystores between hosts by re-running
  `wallet init --force` with the new credential and distributing the refreshed
  ciphertext;
- ensure backups capture the entire keystore file (metadata + ciphertext) and
  protect the passphrase copies with the same diligence as other hot wallet
  secrets.

## Wallet backup, prover, and hardware hygiene

- Encrypted backup export/validation/import flows zeroize the derived Argon2
  keys, plaintext envelopes, and keystore payloads after use, and include debug
  assertions so CI catches regressions before release.【F:rpp/wallet/src/backup/mod.rs†L226-L342】【F:rpp/wallet/src/backup/import.rs†L37-L143】
- Watch-only seed derivation, prover witness construction, and hardware signing
  payloads are all treated as sensitive buffers; each path now uses `zeroize`
  (or drop hooks) to clear memory after RPC calls or proof generation finish so
  secrets never linger in logs or heap snapshots.【F:rpp/wallet/src/modes/watch_only.rs†L1-L70】【F:rpp/wallet/src/engine/signing/prover.rs†L90-L420】【F:rpp/wallet/src/hw/traits.rs†L1-L118】
- Wallet RPC audit records only persist hashed bearer tokens or certificate
  fingerprints, which keeps new backup/mTLS/hardware administrative events
  traceable without disclosing raw credentials in log archives.【F:rpp/runtime/wallet/rpc/security.rs†L1-L120】【F:rpp/runtime/wallet/rpc/audit.rs†L1-L80】

## Related security guidance

- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) details the system assets,
  trust boundaries, and defensive controls operators rely on in production.
- [`docs/KEY_MANAGEMENT.md`](docs/KEY_MANAGEMENT.md) documents VRF key lifecycle
  management and secrets backend expectations.
- [`docs/API_SECURITY.md`](docs/API_SECURITY.md) captures RPC hardening
  practices, rate limits, and telemetry authentication hooks.
- [`docs/GOVERNANCE.md`](docs/GOVERNANCE.md) summarises change control, release
  approvals, and incident-response policies.
- [`docs/zk_backends.md`](docs/zk_backends.md#incident-runbook-rpp-stark-verification-failures) liefert Stage-Flag-Gegenmaßnahmen, Proof-Replay-Befehle und Backend-Fallbacks für Verifier-Incidents, die Security während eines Hotfixes begleiten muss.【F:docs/zk_backends.md†L74-L207】
