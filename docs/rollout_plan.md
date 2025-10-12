# Malachite BFT Rollout Plan

This guide sequences the activities required to roll out the Malachite BFT
blueprint from development to mainnet. It assumes the supporting reputation,
timetoke, consensus, proof, and networking features described in the blueprint
are ready for staging.

## 1. Preparation & Readiness Gates

1. **Freeze interfaces and configuration defaults.** Publish a tagged release
   candidate once the Rust interface contracts, configuration schema, and
   telemetry payloads match the blueprint. Future changes should be
   backward-compatible or staged behind feature gates.
2. **Complete storage migrations in isolation.** Run migrations on a copy of
   production state and capture before/after checksums for critical column
   families (ledger state, timetoke snapshots, consensus metadata). Automate the
   checksum comparison in CI so the exact migration binary is reproducible.
3. **Finalize documentation and runbooks.** Ensure the architecture blueprint,
   cross-cutting concerns, validator lifecycle, and deployment playbooks are all
   published internally. Rollout cannot begin while key documents are in draft
   form.
4. **Run exhaustive test suites.** Finish unit, property-based, integration,
   fuzzing, and simulation test suites. Block release if any blueprint coverage
   regression is detected.

## 2. Channel Promotion Strategy

1. **Development channel.** Deploy nightly builds to an internal cluster with
   synthetic traffic. Validate consensus liveness, proof pipeline throughput,
   telemetry integrity, and RPC compatibility.
2. **Testnet channel.** Promote builds that clear development testing. Rotate in
   community validators, enable snapshot sync, and exercise witness flows for
   several epochs. Collect feedback on reward distribution and leader rotation.
3. **Canary channel.** Select a small subset of mainnet validators to run the
   upcoming release in parallel with existing production binaries. Require
   regular reporting on consensus metrics, proof latencies, and resource
   consumption.
4. **Mainnet channel.** Execute a scheduled maintenance window once canary shows
   no regressions. Announce the timeline, publish release notes, and cut the
   final tag.

## 3. Feature Gate Progression

1. **Consensus-only activation.** Enable validator/witness selection and
   telemetry gates first while keeping reward payouts, slashing, and recursive
   proof enforcement disabled. Monitor for hotfixes.
2. **Reward engine activation.** Once consensus stabilizes, enable leader bonus
   distribution and validator rewards in a single epoch transition. Confirm
   payouts on-chain and in telemetry.
3. **Proof enforcement.** Turn on recursive proof enforcement and pruning
   requirement once the proof cache demonstrates sustained headroom. Update
   wallet clients and witnesses to reject blocks missing proofs.
4. **Anti-abuse tooling.** Finally, enable automated slashing for double-signs,
   fake proofs, censorship, and inactivity. Ensure appeal processes and audit
   logging are in place before activation.

## 4. Operational Checklist per Channel

1. **Genesis & configuration parity.** Verify every validator uses identical
   genesis files, reputation tier thresholds, timetoke parameters, and feature
   gates. Publish the canonical configuration bundle before rollout.
2. **Monitoring dashboards.** Stand up dashboards and alerts for release
   channel, feature gates, telemetry loops, consensus health, proof queue depth,
   and witness participation before promoting the build.
3. **Incident response rota.** Staff 24/7 on-call coverage during canary and the
   first 48 hours of mainnet rollout. Provide clear escalation paths for
   consensus faults or proof verification failures.
4. **Data retention & backups.** Take coordinated backups of ledger state,
   timetoke snapshots, and proof caches prior to each promotion. Confirm restore
   procedures against staging nodes.
5. **Publish the storage recovery runbook.** Link operators to the Firewood
   recovery steps for WAL replay, snapshot restoration, and pruning proof
   validation so maintenance windows have a vetted rollback plan.【F:docs/storage_recovery.md†L1-L53】

## 5. Communication Plan

1. **Validator briefings.** Share the rollout schedule, configuration deltas,
   and operational expectations with validators at least two weeks in advance.
   Host Q&A sessions and dry-run walkthroughs.
2. **Ecosystem updates.** Publish release notes for wallets, witnesses, and
   explorers describing API changes, telemetry fields, and new proof
   requirements. Provide migration guides for SDK consumers.
3. **Real-time status.** During rollout windows, post hourly status updates that
   include height progression, validator participation, proof latency, and any
   incidents. Maintain a public status page.

## 6. Post-Rollout Validation & Stabilization

1. **Audit reward distribution.** After the first 10 epochs, audit on-chain
   rewards to confirm leader bonuses and validator payouts match the expected
   configuration. Address discrepancies immediately.
2. **Review telemetry & logs.** Analyze telemetry for missed proofs, delayed
   votes, or gossip back-pressure. Triage regressions and schedule follow-up
   patches.
3. **Capture lessons learned.** Conduct a rollout retrospective within two
   weeks. Document automation gaps, tooling improvements, and blueprint updates
   required for the next iteration.
4. **Establish maintenance cadence.** Define the schedule for subsequent
   releases, including how feature gates graduate to defaults and how emergency
   patches are handled.

Following this plan ensures the Malachite BFT blueprint reaches production with
controlled risk, clear communication, and robust observability.
