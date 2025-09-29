# Dependency update policy

This policy applies to all Rust crates in the repository and complements the
toolchain pinning we already enforce via `rust-toolchain.toml`.

## Step-by-step update checklist

1. **Prepare an update window.**
   - Coordinate with the maintainers of the affected crates and schedule a
     review window where no other dependency bumps are merged.
   - Capture the motivation for the change (security advisory, performance fix,
     etc.) in the pull request description.
2. **Stage the changes behind review gates.**
   - Open a dedicated pull request per dependency family (e.g. STWO, hashing,
     field arithmetic) so that reviewers can focus on one risk domain at a time.
   - Run the full CI suite and attach logs for any manual verification that was
     required (integration networks, prover benchmarks, …).
3. **Define a rollback plan before merging.**
   - Document the minimum supported version after the bump and confirm that the
     previous lockfile still builds from a clean checkout.
   - Note who owns the release of the downstream crates in case the update needs
     to be reverted quickly.
4. **Review and commit the lockfile.**
   - Inspect `Cargo.lock` for new transitive dependencies or extra feature flags
     introduced by the update.
   - Reject the change if the lockfile contains unreviewed build scripts or
     network access in new dependencies.
   - Commit the regenerated lockfile together with the manifest changes so the
     repository remains reproducible.
5. **Communicate the rollout.**
   - Announce the update, the expected impact and the rollback contact in the
     weekly engineering sync and in the `#release` Slack channel.
   - Track the deployment on the rollout board and confirm completion once the
     change runs in production and on the nightly simulator.

Following this process keeps dependency bumps reviewable, reversible and fully
traceable.
