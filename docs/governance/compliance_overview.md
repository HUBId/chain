# Compliance Overview

## Recent Enhancements
- **Snapshot retention:** Implemented automated snapshot retention policy maintaining 13 months of validator and prover backups with quarterly immutability checks. Escalations are routed through the storage SRE rotation and recorded in the security register.
- **Audit trails:** Expanded structured audit logging for key management, configuration updates, and deployment workflows. Logs are forwarded to the central SIEM with 400-day retention and mapped to SOC 2 CC7.2 evidence requirements.

## Evidence Traceability
- Updated [Threat Model](../THREAT_MODEL.md) highlighting snapshot and audit log attack surfaces.
- [Security Risk Register](../security/register.md) entries for retention deviations and audit trail coverage.
- Phase 3 [Acceptance Checklist](../runbooks/phase3_acceptance.md) referencing new controls and sign-off artifacts.

## Outstanding Items
| Item | Owner | Target Date | Notes |
| --- | --- | --- | --- |
| Dual approval rollout for privileged configuration changes | Security Engineering (A. Ortega) | 2024-07-15 | Aligns with SOC 2 CC6.3. Awaiting integration tests on staged environments. |
| WORM export pipeline for quarterly audit snapshots | Compliance (M. Chen) | 2024-08-01 | Required for SOC 2 CC3.3 and CC8.1 evidence. Vendors shortlisted; contract review pending. |

## Regulatory Follow-ups
- Map finalized snapshot retention runbooks to SOC 2 CC8.1 and CC7.2 once WORM export is operational.
- Update evidence package in GRC tool after dual approval rollout completes and capture sign-offs from Security Engineering and Compliance leadership.

