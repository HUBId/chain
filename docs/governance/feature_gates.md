# Feature Gate Governance Protocols

This document describes how feature gates move from development to mainnet.
Governance enforces the staged rollout defined in
`config/defaults/mainnet.toml` and the operational runbook in
[`docs/deployment/staged_rollout.md`](../deployment/staged_rollout.md).

## Roles and Responsibilities

* **Release commander.** Owns the rollout issue, tracks checklists, and confirms
  the target stage is ready to activate.
* **Governance council.** Reviews proposals to promote or demote feature gates
  and records approvals in the public meeting minutes.
* **SRE lead.** Confirms observability coverage and recovery assets before a
  stage promotion.
* **Security steward.** Verifies binary provenance, SBOM attestation, and any
  policy exceptions.

## Promotion Workflow

1. **Proposal submission.** The release commander files a governance proposal
   that references the target stage (`development`, `testnet`, `canary`, or
   `mainnet`) and links to the current bundle hash of
   `config/defaults/mainnet.toml`.
2. **Readiness review.** Council members verify the `*-readiness` and
   `common-preflight-checks` sections of the staged rollout runbook are complete
   and attach evidence (dashboard snapshots, test reports, incident summaries).
3. **Vote and record.** A promotion requires a two-thirds majority of the
   council. Votes and reasoning are appended to the governance log.
4. **Execution window.** The release commander coordinates execution during the
   approved change window and documents the resulting gate states.
5. **Post-activation audit.** Within 24 hours of activation, the commander posts
   metrics proving the gate behaved as expected or files an incident.

## Emergency Actions

* **Emergency disable.** The release commander may temporarily disable a gate if
  consensus safety or liveness is threatened. The council must ratify the action
  within 24 hours and capture the mitigation steps.
* **Rollback authority.** The SRE lead triggers the recovery playbook referenced
  by the stage if telemetry or community reports indicate regressions.
* **Freeze.** During mainnet activation, new governance proposals are frozen
  until the readiness audit completes.

## Release Verification

Before closing a promotion proposal:

1. Confirm the release issue references the executed `release_checks` for the
   stage and that they were signed off by the relevant role owners.
2. Ensure the deployed configuration matches the stage profile when inspected
   via the telemetry API (`feature_gates` map advertised by the fleet).
3. Capture a checksum of the deployed config bundle and archive it with the
   governance records.
4. Validate that recovery artifacts (snapshots, container images, previous
   config bundles) remain accessible in case a gate needs to be reversed.

## Record Keeping

* Store all proposals, votes, and incident reports in the governance repository.
* Update `docs/rollout_plan.md` whenever the staged rollout sequence or gate
  dependencies change.
* Publish quarterly retrospectives that track how long each gate spent in each
  stage and the incidents encountered.

These protocols ensure feature gate changes remain transparent, auditable, and
reversible.
