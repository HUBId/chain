# Release Checklist

- [ ] Align all `Cargo.toml` package versions with the release tag (v1.0.0-beta).
- [ ] Confirm `PROOF_VERSION` remains correct or bump it alongside snapshot updates if the ABI changed.
- [ ] Regenerate and review Golden Vectors and snapshots; ensure the snapshot guard passes locally.
- [ ] Update `CHANGELOG.md` and `docs/RELEASE_NOTES.md` with highlights, compatibility, and upgrade notes.
- [ ] Verify MSRV (1.79) and stable-only toolchains in CI matrices.
- [ ] Run `scripts/ci/sim_smoke.sh` (libp2p simulation smoke) and attach the `ci-artifacts/sim-smoke` bundle to the release ticket.
- [ ] Tag the repository with `rpp-stark-v1.0.0-beta` and push the tag.
- [ ] Draft the GitHub release referencing `docs/RELEASE_NOTES.md` and link to deterministic fixtures.
