# Security Risk Register

**Last reviewed:** 27 May 2026 by the security review board.

The table below summarises the currently open snapshot lifecycle risks and the
teams accountable for completing remediation. Each risk links to the
implementation task that tracks delivery work.

| Risk | Impact | Mitigation Status | Remediation Owner | Tracking |
| --- | --- | --- | --- | --- |
| Snapshot replay defence coverage | Replayed manifests could poison state-sync and trigger consensus divergence. | Manifest-Signaturen werden via Nightly `snapshot-health` überprüft (`cargo xtask snapshot-health`) und schlagen als `SnapshotManifestSignatureInvalid`-Alert auf. Phase‑3-Evidence sammelt das JSON-Reporting automatisch. | State Sync Guild | [ENG-921](../status/weekly.md#snapshot-replay-hardening) |
| Snapshot manifest signature control | Fehlende Signaturen erlauben manipulierte Bundles im Release- oder On-Call-Fluss. | Release-Pipeline veröffentlicht `snapshot-manifest-summary-<target>.json`, Observability überwacht fehlende/abweichende Segmente und Runbooks fordern sofortige `snapshot-health`-Audits. Evidence-Bundle archiviert die Signatur-/Summary-Dateien. | Release Engineering | [ENG-1124](../status/weekly.md#phase3-tracking-kalenderwoche-20-2026) |
| External snapshot verification gap | Operators lack an offline tool to verify manifests before distribution, leaving replay detection dependent on online guards. | CLI spec signed off; prototype under development in `tools/firewood`. | Tooling Team | [ENG-1053](../status/weekly.md#external-snapshot-verification-eng-1053) |
| Resume validation gaps | Tampered partial downloads may bypass integrity checks and lead to corrupted node states. | Attestation hooks merged; chunk hash retry guardrails in QA ahead of staged rollout. | Recovery Working Group | [ENG-922](../status/weekly.md#resume-validation-guardrails) |
| Tier policy persistence drift | Unpersisted policy changes weaken witness tier isolation and allow bypass of rate controls. | Append-only log landed; policy snapshots und Audit-Entries sind signiert und lassen sich mit `rpp-node validator admission verify` prüfen. Evidence-Bundle sammelt Audit-Logs und Signaturen, Dual-Control-Automation bleibt offen. | Network Operations | [ENG-923](../status/weekly.md#tier-policy-persistence) |
| Tier policy signature attestation | Ohne Nachweis der Signaturprüfung fehlen Auditor:innen Belege für Dual-Control-Konformität. | `rpp-node validator admission verify` prüft Snapshot- & Audit-Signaturen, CI/Docs (Snapshot & Timetoke Automation) verweisen auf die verpflichtenden Checks. Compliance verlinkt Signaturnachweise in Phase‑3-Artefakten. | Identity & Access | [ENG-1051](../status/weekly.md#dual-control-automation-eng-1051) |
| Dual-control enforcement for admissions | Single-operator approvals enable policy tampering without peer review. | Witness approval service integration in progress; policy rollback alerts drafted. | Identity & Access | [ENG-1051](../status/weekly.md#dual-control-automation-eng-1051) |
| Audit trail reconciliation debt | Missing audit events reduce forensic confidence during incident response. | Immutable storage replication blocked on storage API upgrade; reconciliation job staged for post-upgrade deployment. | Security Engineering | [ENG-924](../status/weekly.md#audit-trail-reconciliation) |
| WORM export coverage | Local append-only logs can still be modified on compromised hosts, eroding evidentiary integrity. | Object storage pipeline design approved; retention policy awaiting compliance sign-off. | Security Engineering | [ENG-1052](../status/weekly.md#worm-export-hardening-eng-1052) |

## Next Review
The security review board will revisit these items during the Phase 3 planning
checkpoint or earlier if blocking incidents are detected.
