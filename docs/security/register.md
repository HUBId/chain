# Security Risk Register

The table below summarises the currently open snapshot lifecycle risks and the
teams accountable for completing remediation. Each risk links to the
implementation task that tracks delivery work.

| Risk | Impact | Mitigation Status | Remediation Owner | Tracking |
| --- | --- | --- | --- | --- |
| Snapshot replay defence coverage | Replayed manifests could poison state-sync and trigger consensus divergence. | Controls drafted in the threat model addendum; instrumentation rollout pending. | State Sync Guild | [ENG-921](../status/weekly.md#snapshot-replay-hardening) |
| Resume validation gaps | Tampered partial downloads may bypass integrity checks and lead to corrupted node states. | Resume attestation hooks merged; retry + hashing safeguards queued for rollout. | Recovery Working Group | [ENG-922](../status/weekly.md#resume-validation-guardrails) |
| Tier policy persistence drift | Unpersisted policy changes weaken witness tier isolation and allow bypass of rate controls. | Append-only log design approved; dual control automation scheduled. | Network Operations | [ENG-923](../status/weekly.md#tier-policy-persistence) |
| Audit trail reconciliation debt | Missing audit events reduce forensic confidence during incident response. | WORM export complete; reconciliation job awaiting deployment. | Security Engineering | [ENG-924](../status/weekly.md#audit-trail-reconciliation) |

## Next Review
The security review board will revisit these items during the Phase 3 planning
checkpoint or earlier if blocking incidents are detected.
