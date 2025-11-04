# Vendor refresh warning ticket template

Use this template when raising a follow-up for warnings captured during a Plonky3 mirror refresh. Copy the sections below into the internal operations ticket and fill in the details.

## Summary
- **Warning:** <copy the warning message or short paraphrase>
- **Affected crate/component:** <crate name and version>
- **Log reference:** <path to log file and line number>

## Impact assessment
- **Observed impact:** <build failure, checksum mismatch, resolver churn, etc.>
- **Potential downstream risk:** <release blockers, policy review, additional testing>

## Proposed next steps
- [ ] Patch or pin dependency (owner: <name>)
- [ ] Re-run vendor refresh after fix
- [ ] Update documentation / release notes
- **Additional notes:** <links to PRs, discussions, or other artefacts>

## Attachments
- Paste relevant log excerpts.
- Link to the entry in `docs/vendor_log.md` tracking this warning.
