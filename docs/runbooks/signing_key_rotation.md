# Snapshot & admission signing key rotation

This runbook consolidates the lifecycle tasks for the two signing domains that gate
snapshot distribution and admission policy attestations. Snapshot bundle manifests
are signed through the release pipeline so downstream operators can authenticate
state-sync artefacts before ingestion, while tier policies and audit logs are signed
by the validator runtime to preserve dual-control evidence.

> **Scope.** Follow these steps whenever a signing credential is introduced,
> rotated on its regular cadence, or revoked after compromise. Record every
> rotation in the compliance dashboard and the weekly status log so auditors can
> trace execution.

## Snapshot manifest signing (release pipeline)

The GitHub Actions release workflow signs every snapshot artefact—including the
`snapshot-manifest-summary-<target>.json` bundles—via `cosign sign-blob`, which
emits detached signatures and x509 certificates for each file. The same workflow
invokes `scripts/provenance_attest.sh` to generate and sign SLSA provenance
statements for the artefacts.【F:.github/workflows/release.yml†L258-L311】【F:scripts/provenance_attest.sh†L1-L118】 Operators verify
these signatures with `cosign verify-blob` against the GitHub OIDC identity bound
in the security policy.【F:SECURITY.md†L16-L40】

### Generate or rotate a manifest signing key

1. Decide whether to continue using GitHub OIDC keyless signing or a dedicated key
   pair. Keyless signing relies on the workflow’s OIDC identity; rotation consists
   of enforcing the new repository/environment policy and updating the verification
   regex in `SECURITY.md` if the issuer or subject string changes.【F:SECURITY.md†L16-L40】
2. For a dedicated key pair, provision a fresh `cosign` Ed25519 key (example
   command: `cosign generate-key-pair --kms <provider-uri>`). Store the secret
   component in the release secret manager approved for CI usage and restrict
   access to the release engineering role.
3. Update the release workflow environment or repository secrets so
   `cosign sign-blob` loads the new key during the signing step (set
   `COSIGN_KEY`/`COSIGN_PASSWORD` or configure the KMS URI before the job invokes
   the signing loop). Commit the corresponding verification hint (certificate
   subject, Fulcio issuer, or key fingerprint) to `SECURITY.md`.
4. Run the release workflow in a staging branch to confirm the new key produces
   valid signatures and that downstream verification succeeds via
   `cosign verify-blob`.

### Storage, monitoring, and evidence

- Keep the private key or OIDC binding metadata in the hardened secret store used
  for release automation. The rotated key fingerprint and storage location must be
  captured in the compliance register entry for supply-chain controls.【F:docs/GOVERNANCE.md†L54-L72】
- Store generated signatures, certificates, and provenance statements alongside
  the artefacts in the published release so auditors can replay verification.
  The workflow already publishes these files in `dist/` and the GitHub release
  payload.【F:.github/workflows/release.yml†L258-L311】
- After each rotation, attach the verification transcript (command output and
  certificate metadata) to the Phase 3 evidence archive using the
  `collect-phase3-evidence` xtask to maintain traceability.【F:xtask/src/main.rs†L1498-L1852】

### Revocation workflow

1. Disable the compromised key (revoke the Fulcio certificate or remove the
   key material from the secret manager/KMS) immediately.
2. Remove the matching verification instructions from `SECURITY.md` and replace
   them with the new key identity once a fresh credential is live.【F:SECURITY.md†L16-L40】
3. Re-run the release workflow with the new key to re-sign any artefacts that were
   still pending publication.
4. Update the weekly status report and compliance overview with the revocation
   timestamp and follow-up tasks.

## Admission tier-policy signing (validator runtime)

Validators sign the persisted admission policy snapshot and every audit log entry
with the active Ed25519 key configured under `network.admission.signing`. The peer
store keeps a trust store of allowed public keys, verifies that the active key is
trusted, and signs the canonical JSON payload before returning it via RPC.【F:rpp/runtime/config.rs†L978-L1005】【F:rpp/p2p/src/policy_signing.rs†L1-L200】 The
`rpp-node validator admission verify` command validates snapshots and audit entries
against the configured trust store to provide rotation evidence.【F:rpp/node/src/main.rs†L1065-L1176】

### Rotation steps

1. Generate a new Ed25519 signing key in TOML format (the same layout used by the
   runtime) and add the derived public key to
   `network.admission.signing.trust_store` without removing previous entries so
   historical signatures stay verifiable.【F:rpp/runtime/config.rs†L978-L1005】
2. Update `network.admission.signing.key_path` (or the HSM alias) and
   `network.admission.signing.active_key` to point to the new key material, then
   deploy the configuration change through the validator rollout pipeline.【F:rpp/runtime/config.rs†L978-L1005】
3. Restart the validator; the peerstore reloads the key, signs the snapshot, and
   continues to sign audit entries with the new identifier.【F:rpp/p2p/src/policy_signing.rs†L42-L146】【F:rpp/p2p/src/peerstore.rs†L699-L758】
4. Run `rpp-node validator admission verify --audit-limit <N>` and attach the
   CLI output to the change ticket as proof that the new key signs and that the
   trust store still validates legacy entries.【F:rpp/node/src/main.rs†L1065-L1176】【F:docs/runbooks/admission.md†L74-L116】

### Storage and evidence

- Store the secret key according to the deployment’s secrets policy (filesystem
  with `600` permissions, Vault path, or HSM reference). The runtime enforces
  non-empty key paths and validates that the configured active key is present in
  the trust store before starting up.【F:rpp/runtime/config.rs†L978-L1005】
- Admission snapshots and audit logs remain signed automatically; include the
  verification output and updated trust store mapping in the compliance evidence
  bundle after every rotation.【F:docs/runbooks/admission.md†L74-L116】【F:xtask/src/main.rs†L1498-L1852】

### Revocation procedure

1. Mark the compromised key as inactive by switching `active_key` to a trusted
   successor and removing the secret material from disk or the external HSM.
2. Once retention requirements for historical signatures are satisfied, prune the
   revoked key from the trust store to avoid future use while keeping archived
   verification logs intact.【F:docs/runbooks/admission.md†L97-L116】
3. Run `rpp-node validator admission verify` to ensure remaining trust store
   entries still validate the historical audit trail.【F:rpp/node/src/main.rs†L1065-L1176】
4. Update the incident log, weekly status template, and compliance overview with
  the revocation details and follow-up remediation tasks.

---

**Post-rotation checklist**

- [ ] Update the compliance overview table with the rotation date, verifying key
      identifier, and evidence links.
- [ ] Add the rotation summary and next expiry reminder to the weekly status
      template.
- [ ] Archive the verification outputs with the Phase 3 evidence bundle.
- [ ] Notify on-call and governance distribution lists that the new keys are live.
