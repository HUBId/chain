# Wallet security advisory template

Use this template when coordinating a GHSA for wallet-related issues. Copy the
sections below into the draft advisory and fill in the details as evidence is
collected. Follow the disclosure requirements in [SECURITY.md](../../SECURITY.md)
and the support commitments listed in
[`docs/wallet_support_policy.md`](../wallet_support_policy.md).

---

**Title:** `<Concise vulnerability name>`

**CVE/GHSA ID:** `<Pending>`

**Report date:** `<YYYY-MM-DD>`

**Discovered by:** `<Name / handle / company>`

## Summary

Describe the vulnerability in two to three sentences. Mention which wallet
surfaces (CLI, GUI, RPC, Electrs integration, hardware bridges) are affected and
why the issue matters to operators.

## Affected components

| Component | Versions | Notes |
| --- | --- | --- |
| `rpp-wallet` CLI | `<vX.Y.Z range>` | e.g., compiled without `wallet_rpc_mtls` | 
| GUI bundle | `<vX.Y.Z range>` | e.g., notarized builds signed before `<date>` |
| RPC service | `<vX.Y.Z range>` | e.g., missing RBAC guard on `<endpoint>` |

List any configuration prerequisites (feature flags, OS-specific behaviours,
Electrs plugins, etc.).

## Impact

Summarise the worst-case scenario (privilege escalation, funds at risk, DoS,
policy bypass). Include references to logs, crash reports, or regression tests
that demonstrate the failure mode.

## Mitigations and fixes

1. Describe configuration-level workarounds (feature flags, firewall rules,
   watchdogs) that can reduce exposure before patches are available.
2. Document the patched versions, commit hashes, and release artifacts that carry
   the fix. Link to the SBOM/provenance evidence published by the release
   workflow so auditors can validate the binaries.
3. Point to the [release checklist](../release_checklist.md) entries that were
   exercised while validating the fix (manual smoke tests, signature checks,
   documentation updates).

## Detection and verification

- Provide `jq`/`grep` snippets to identify vulnerable installations (e.g., scan
  manifests for missing `wallet_rpc_mtls`).
- Reference CI jobs (`wallet-feature-matrix`, `cargo audit`, `cargo deny`) or
  new regression tests that demonstrate the vulnerability and its fix.

## Timeline

| Date | Event |
| --- | --- |
| `<YYYY-MM-DD>` | Report received via security@ or GHSA draft |
| `<YYYY-MM-DD>` | Fix merged to `main` |
| `<YYYY-MM-DD>` | Releases published (`vX.Y.Z`, `lts/X.Y`) |
| `<YYYY-MM-DD>` | Advisory disclosed |

## Credits and acknowledgements

Thank the reporter, reviewers, and operators who validated the mitigation. Note
if a bounty or public thank-you is applicable.

---

Attach signed release artifacts, SBOMs, and provenance statements when submitting
the GHSA so GitHub Security Lab can verify the fix prior to publication.
