# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### ⚙️ Miscellaneous Tasks

- Rebuild the Plonky3 verification path on top of `p3_uni_stark::verify`,
  reconstructing Stark configs from the verifying key, replaying challenger
  transcripts, and mapping upstream errors into backend variants with
  structured logging for RPP modules.【F:prover/plonky3_backend/src/lib.rs†L2055-L2224】【F:prover/plonky3_backend/src/lib.rs†L2489-L2523】
- Update documentation and automation to reference the new `ava-labs/chain` repository path across tooling and guides.
- Wire the Simnet regression orchestrator and CI/nightly job to chain VRF/quorum stress, snapshot rebuild, and gossip backpressure scenarios while exporting HTML/JSON artifacts for audit trails.【F:tools/simnet/src/bin/regression.rs†L1-L220】【F:.github/workflows/ci.yml†L1-L120】【F:.github/workflows/nightly.yml†L1-L130】
- Align all nightly Rust toolchain references on `nightly-2025-07-14`, update CI to guard the pin, and document the one-time cache cleanup required after installing the new compiler.
- Confirm contributors have the cleanup steps for stale nightly artifacts (`cargo clean -p prover_stwo_backend`, `rm -rf prover/target`, uninstall toolchains older than `nightly-2025-07-14`) and record the stable/nightly build separation verified on Rust 1.79 and the pinned nightly toolchain.

### 📚 Documentation

- Flag the expanded branch-protection gates in the contributor guide, testing
  strategy, and governance review checklist so everyone sees the new
  `snapshot-cli`, `observability-snapshot`, `simnet-admission`, and
  `runtime-smoke` requirements before merging.【F:CONTRIBUTING.md†L29-L52】【F:docs/test_validation_strategy.md†L104-L145】【F:docs/governance/review_process.md†L1-L53】【F:docs/GOVERNANCE.md†L19-L44】
- Detail the VRF/quorum proof constraints and failure modes in the consensus ADR and architecture foundations so reviewers can trace the new public inputs across circuits, runtime verifiers, and regression tests.【F:docs/adr/0001_consensus_proofs.md†L15-L44】【F:docs/architecture_foundations.md†L45-L86】

- Capture the Plonky3 production graduation, including updated telemetry
  metrics, artefact paths, and supply-chain gates in the README, runbook, and
  ADR so operators can point auditors at the final proof flow and dashboard
  evidence.【F:README.md†L1-L21】【F:docs/runbooks/plonky3.md†L1-L120】【F:docs/architecture/adr/0001-zk-backend-status.md†L1-L80】
- Capture the Plonky3 STARK verification flow, transcript specification, and
  RPP module integration guidelines for operators and client developers.【F:docs/zk_verification.md†L1-L56】
- Document the Phase 2 regression harness, VRF/quorum alert playbook, acceptance checklist, and proof metadata release notes so operators and auditors can trace readiness artifacts.【F:docs/testing/simulations.md†L1-L120】【F:docs/observability/alerts/consensus_vrf.yaml†L1-L120】【F:docs/runbooks/phase2_acceptance.md†L1-L200】【F:docs/release_notes.md†L1-L80】【F:docs/runbooks/observability.md†L1-L160】
- Mark the Phase 1 blueprint milestone as completed in the roadmap, weekly status report, and coverage index so stakeholders can follow the handover into Phase 2.【F:docs/roadmap_implementation_plan.md†L3-L26】【F:docs/status/weekly.md†L1-L20】【F:docs/blueprint_coverage.md†L1-L115】
- Point operators to the VRF telemetry endpoints exposed by `/status/node` and
  the `target_validator_count` / `rollout.telemetry.*` configuration knobs so
  the new metrics surface alongside existing dashboards.【F:docs/poseidon_vrf.md†L55-L104】【F:config/node.toml†L8-L76】
- Capture the wallet UI/RPC completion by linking maintainers to the Electrs-backed tab models and `/wallet/ui/*` handlers so dashboard status sheets reference the finished modules.【F:rpp/wallet/ui/wallet.rs†L736-L924】【F:rpp/rpc/api.rs†L1405-L1440】【F:rpp/rpc/tests/wallet_ui_contract.rs†L1-L120】
- Refresh the Electrs wallet/node blueprint to mirror the post-refactor crate layout and verify every inline citation targets the new module tree.【F:docs/electrs_fork_wallet_node_blueprint.md†L1-L210】
- Clarify that the STWO backend now lives under `prover/prover_stwo_backend/` and retarget inline citations in the prover docs to the new module path.【F:docs/architecture/prover-backends.md†L8-L55】【F:docs/blueprint_coverage.md†L5-L22】【F:docs/vendor_log.md†L24-L75】【F:docs/DEPS_COMPAT_REPORT.md†L7-L11】
- Extend the observability runbook with `ProofError::IO` diagnostics for state-sync chunk RPCs, including Prometheus/Log markers and regression coverage pointers.【F:docs/runbooks/observability.md†L7-L26】【F:docs/runbooks/observability.md†L88-L92】
- Highlight the state-sync root-corruption safeguard for operators, linking the Firewood storage notes, observability runbook, and regression coverage so on-call staff can audit `ProofError::IO` escalations.【F:docs/storage/firewood.md†L49-L68】【F:docs/runbooks/observability.md†L1-L38】【F:tests/state_sync/root_corruption.rs†L1-L53】
- Add production callouts that block `backend-plonky3`, reiterate the STWO feature
  requirements, and link the release pipeline checklist so operators understand
  the new compile-, packaging-, and runtime guards.【F:docs/rpp_node_operator_guide.md†L7-L23】【F:docs/poseidon_vrf.md†L9-L25】【F:RELEASE.md†L88-L123】
- Summarize the compile-time, runtime, and release guardrails that keep the
  experimental `backend-plonky3` feature out of production builds, and document
  the failure modes operators should expect. The notes call out the
  `compile_error!` emitted by [`feature_guard.rs`](rpp/node/src/feature_guard.rs)
  when `backend-plonky3` is paired with `prod`/`validator`, the runtime launch
  failure raised by `ensure_prover_backend` when validator or hybrid roles miss
  the STWO prover, and the release tooling errors from
  `scripts/build_release.sh`/`scripts/verify_release_features.sh` that surface as
  `error: backend-plonky3 is experimental and cannot be enabled for release
  builds` or `error: forbidden prover features enabled for rpp-node`.
  【F:rpp/node/src/feature_guard.rs†L1-L7】【F:rpp/node/src/lib.rs†L520-L532】【F:scripts/build_release.sh†L115-L126】【F:scripts/verify_release_features.sh†L1-L108】

## [0.0.12] - 2025-08-26

### 🚀 Features

- *(async-removal)* Phase 3 - make `Db` trait sync ([#1213](https://github.com/ava-labs/chain/pull/1213))
- *(checker)* Fix error with free area that is not head of a free list ([#1231](https://github.com/ava-labs/chain/pull/1231))
- *(async-removal)* Phase 4 - Make `DbView` synchronous ([#1219](https://github.com/ava-labs/chain/pull/1219))
- *(ffi-refactor)* Refactor cached view (1/8) ([#1222](https://github.com/ava-labs/chain/pull/1222))
- *(ffi-refactor)* Add OwnedSlice and OwnedBytes (2/8) ([#1223](https://github.com/ava-labs/chain/pull/1223))
- *(ffi-refactor)* Introduce VoidResult and panic handlers (3/8) ([#1224](https://github.com/ava-labs/chain/pull/1224))
- *(ffi-refactor)* Refactor Db opening to use new Result structure (4/8) ([#1225](https://github.com/ava-labs/chain/pull/1225))
- *(ffi-refactor)* Refactor how hash values are returned (5/8) ([#1226](https://github.com/ava-labs/chain/pull/1226))
- *(ffi-refactor)* Refactor revision to use database handle (6/8) ([#1227](https://github.com/ava-labs/chain/pull/1227))
- *(ffi-refactor)* Add `ValueResult` type (7/8) ([#1228](https://github.com/ava-labs/chain/pull/1228))

### ⚙️ Miscellaneous Tasks

- Only allocate the area needed ([#1217](https://github.com/ava-labs/chain/pull/1217))
- Synchronize .golangci.yaml ([#1234](https://github.com/ava-labs/chain/pull/1234))
- *(metrics-check)* Re-use previous comment instead of spamming new ones ([#1232](https://github.com/ava-labs/chain/pull/1232))
- Nuke grpc-testtool ([#1220](https://github.com/ava-labs/chain/pull/1220))

### 🧪 Tests

- Add regression coverage for pipeline error propagation across node restarts and UI alerts.

## [0.0.11] - 2025-08-20

### 🚀 Features

- *(checker)* Checker returns all errors found in the report ([#1176](https://github.com/ava-labs/chain/pull/1176))
- Remove Default impl on HashType ([#1169](https://github.com/ava-labs/chain/pull/1169))
- Update revision manager error ([#1170](https://github.com/ava-labs/chain/pull/1170))
- *(checker)* Return the leaked areas in the checker report ([#1179](https://github.com/ava-labs/chain/pull/1179))
- *(checker)* Update unaligned page count ([#1181](https://github.com/ava-labs/chain/pull/1181))
- *(checker)* Add error when node data is bigger than area size ([#1183](https://github.com/ava-labs/chain/pull/1183))
- Remove `Batch` type alias ([#1171](https://github.com/ava-labs/chain/pull/1171))
- *(checker)* Annotate IO error with parent pointer in checker errors ([#1188](https://github.com/ava-labs/chain/pull/1188))
- *(checker)* Do not return physical size to accomodate raw disks ([#1200](https://github.com/ava-labs/chain/pull/1200))
- *(ffi)* Add BorrowedBytes type ([#1174](https://github.com/ava-labs/chain/pull/1174))
- *(checker)* More clear print formats for checker report ([#1201](https://github.com/ava-labs/chain/pull/1201))
- *(async-removal)* Phase 1 - lint on `clippy::unused_async` ([#1211](https://github.com/ava-labs/chain/pull/1211))
- *(checker)* Collect statistics for branches and leaves separately ([#1206](https://github.com/ava-labs/chain/pull/1206))
- *(async-removal)* Phase 2 - make `Proposal` trait sync ([#1212](https://github.com/ava-labs/chain/pull/1212))
- *(checker)* Add checker fix template ([#1199](https://github.com/ava-labs/chain/pull/1199))

### 🐛 Bug Fixes

- *(checker)* Skip freelist after first encountering an invalid free area ([#1178](https://github.com/ava-labs/chain/pull/1178))
- Fix race around reading nodes during commit ([#1180](https://github.com/ava-labs/chain/pull/1180))
- *(fwdctl)* [**breaking**] Db path consistency + no auto-create ([#1189](https://github.com/ava-labs/chain/pull/1189))

### ⚡ Performance

- Remove unnecessary Box on `OffsetReader` ([#1185](https://github.com/ava-labs/chain/pull/1185))

### 🧪 Testing

- Add read-during-commit test ([#1186](https://github.com/ava-labs/chain/pull/1186))
- Fix merkle compatibility test ([#1173](https://github.com/ava-labs/chain/pull/1173))
- Ban `rand::rng()` and provide an env seeded alternative ([#1192](https://github.com/ava-labs/chain/pull/1192))
- Reenable eth merkle compatibility test ([#1214](https://github.com/ava-labs/chain/pull/1214))

### ⚙️ Miscellaneous Tasks

- Metric change detection comments only on 1st-party PRs ([#1167](https://github.com/ava-labs/chain/pull/1167))
- Run CI on macOS ([#1168](https://github.com/ava-labs/chain/pull/1168))
- Update .golangci.yaml ([#1166](https://github.com/ava-labs/chain/pull/1166))
- Allow FreeListIterator to skip to next free list ([#1177](https://github.com/ava-labs/chain/pull/1177))
- Address lints triggered with rust 1.89 ([#1182](https://github.com/ava-labs/chain/pull/1182))
- Deny `undocumented-unsafe-blocks` ([#1172](https://github.com/ava-labs/chain/pull/1172))
- Fwdctl cleanups ([#1190](https://github.com/ava-labs/chain/pull/1190))
- AreaIndex newtype ([#1193](https://github.com/ava-labs/chain/pull/1193))
- Remove setup-protoc ([#1203](https://github.com/ava-labs/chain/pull/1203))
- Automatically label PRs from external contributors ([#1195](https://github.com/ava-labs/chain/pull/1195))
- Don't fail fast on certain jobs ([#1198](https://github.com/ava-labs/chain/pull/1198))
- Add PathGuard type when computing hashes ([#1202](https://github.com/ava-labs/chain/pull/1202))
- *(checker)* Add function to compute area counts and bytes ([#1218](https://github.com/ava-labs/chain/pull/1218))

## [0.0.10] - 2025-08-01

### 🚀 Features

- *(async-iterator)* Implement ([#1096](https://github.com/ava-labs/chain/pull/1096))
- Export logs ([#1070](https://github.com/ava-labs/chain/pull/1070))
- Render the commit sha in fwdctl ([#1109](https://github.com/ava-labs/chain/pull/1109))
- Update proof types to be generic over mutable or immutable collections ([#1121](https://github.com/ava-labs/chain/pull/1121))
- Refactor value types to use the type alias ([#1122](https://github.com/ava-labs/chain/pull/1122))
- *(dumper)* Child links in hex (easy) ([#1124](https://github.com/ava-labs/chain/pull/1124))
- *(deferred-allocate)* Part 3: Defer allocate ([#1061](https://github.com/ava-labs/chain/pull/1061))
- *(checker)* Disable buggy ethhash checker ([#1127](https://github.com/ava-labs/chain/pull/1127))
- Add `Children<T>` type alias ([#1123](https://github.com/ava-labs/chain/pull/1123))
- Make NodeStore more generic ([#1134](https://github.com/ava-labs/chain/pull/1134))
- *(checker)* Add progress bar ([#1105](https://github.com/ava-labs/chain/pull/1105))
- *(checker)* Checker errors include reference to parent ([#1085](https://github.com/ava-labs/chain/pull/1085))
- Update RangeProof structure ([#1136](https://github.com/ava-labs/chain/pull/1136))
- Update range_proof signature ([#1151](https://github.com/ava-labs/chain/pull/1151))
- *(checker)* Add InvalidKey error
- *(deferred-persist)* Part 1: unpersisted gauge ([#1116](https://github.com/ava-labs/chain/pull/1116))
- *(checker)* Collect basic statistics while checking the db image ([#1149](https://github.com/ava-labs/chain/pull/1149))
- *(fwdctl)* Add support for dump formats ([#1161](https://github.com/ava-labs/chain/pull/1161))
- *(ffi)* Remove the Arc wrapper around Proposal ([#1160](https://github.com/ava-labs/chain/pull/1160))

### 🐛 Bug Fixes

- *(fwdctl)* Fix fwdctl with ethhash ([#1091](https://github.com/ava-labs/chain/pull/1091))
- *(checker)* Fix checker with ethhash ([#1130](https://github.com/ava-labs/chain/pull/1130))
- Fix broken deserialization of old FreeArea format ([#1147](https://github.com/ava-labs/chain/pull/1147))
- Create metrics registration macros ([#980](https://github.com/ava-labs/chain/pull/980))

### 💼 Other

- Cargo.toml upgrades and fixes ([#1099](https://github.com/ava-labs/chain/pull/1099))
- *(deps)* Update criterion requirement from 0.6.0 to 0.7.0 ([#1140](https://github.com/ava-labs/chain/pull/1140))

### 📚 Documentation

- Document the Phase 2 regression harness, VRF/quorum alert playbook, acceptance checklist, and proof metadata release notes so operators and auditors can trace readiness artifacts.【F:docs/testing/simulations.md†L1-L120】【F:docs/observability/alerts/consensus_vrf.yaml†L1-L120】【F:docs/runbooks/phase2_acceptance.md†L1-L200】【F:docs/release_notes.md†L1-L80】【F:docs/runbooks/observability.md†L1-L160】
- Update ffi/README.md to include configs, metrics, and logs ([#1111](https://github.com/ava-labs/chain/pull/1111))

### 🎨 Styling

- Remove unnecessary string in error ([#1104](https://github.com/ava-labs/chain/pull/1104))

### 🧪 Testing

- Add fuzz testing for checker, with fixes ([#1118](https://github.com/ava-labs/chain/pull/1118))
- Port TestDeepPropose from go->rust ([#1115](https://github.com/ava-labs/chain/pull/1115))

### ⚙️ Miscellaneous Tasks

- Add propose-on-propose test ([#1097](https://github.com/ava-labs/chain/pull/1097))
- Implement newtype for LInearAddress ([#1086](https://github.com/ava-labs/chain/pull/1086))
- Refactor verifying value digests ([#1119](https://github.com/ava-labs/chain/pull/1119))
- Checker test cleanups ([#1131](https://github.com/ava-labs/chain/pull/1131))
- Minor cleanups and nits ([#1133](https://github.com/ava-labs/chain/pull/1133))
- Add a golang install script ([#1141](https://github.com/ava-labs/chain/pull/1141))
- Move all merkle tests into a subdirectory ([#1150](https://github.com/ava-labs/chain/pull/1150))
- Require license header for ffi code ([#1159](https://github.com/ava-labs/chain/pull/1159))
- Bump version to v0.0.10 ([#1165](https://github.com/ava-labs/chain/pull/1165))

## [0.0.9] - 2025-07-17

### 🚀 Features

- *(ffi)* Add gauges to metrics reporter ([#1035](https://github.com/ava-labs/chain/pull/1035))
- *(delayed-persist)* Part 1: Roots may be in mem ([#1041](https://github.com/ava-labs/chain/pull/1041))
- *(delayed-persist)* 2.1: Unpersisted deletions ([#1045](https://github.com/ava-labs/chain/pull/1045))
- *(delayed-persist)* Part 2.2: Branch Children ([#1047](https://github.com/ava-labs/chain/pull/1047))
- [**breaking**] Export firewood metrics ([#1044](https://github.com/ava-labs/chain/pull/1044))
- *(checker)* Add error to report finding leaked areas ([#1052](https://github.com/ava-labs/chain/pull/1052))
- *(delayed-persist)* Dump unpersisted nodestore ([#1055](https://github.com/ava-labs/chain/pull/1055))
- *(checker)* Split leaked ranges into valid areas ([#1059](https://github.com/ava-labs/chain/pull/1059))
- *(checker)* Check for misaligned stored areas ([#1046](https://github.com/ava-labs/chain/pull/1046))
- [**breaking**] Auto open or create with truncate ([#1064](https://github.com/ava-labs/chain/pull/1064))
- *(deferred-allocate)* UnpersistedIterator ([#1060](https://github.com/ava-labs/chain/pull/1060))
- *(checker)* Add hash checks ([#1063](https://github.com/ava-labs/chain/pull/1063))

### 🐛 Bug Fixes

- Avoid reference to LinearAddress ([#1042](https://github.com/ava-labs/chain/pull/1042))
- Remove dependency on serde ([#1066](https://github.com/ava-labs/chain/pull/1066))
- Encoding partial paths for leaf nodes ([#1067](https://github.com/ava-labs/chain/pull/1067))
- Root_hash_reversed_deletions duplicate keys ([#1076](https://github.com/ava-labs/chain/pull/1076))
- *(checker)* Avoid checking physical file size for compatibility ([#1079](https://github.com/ava-labs/chain/pull/1079))

### 🎨 Styling

- Remove unnecessary error descriptor ([#1049](https://github.com/ava-labs/chain/pull/1049))

### ⚙️ Miscellaneous Tasks

- *(build)* Remove unused dependencies ([#1037](https://github.com/ava-labs/chain/pull/1037))
- Update firewood in grpc-testtool ([#1040](https://github.com/ava-labs/chain/pull/1040))
- Aaron is requested only for .github ([#1043](https://github.com/ava-labs/chain/pull/1043))
- Remove `#[allow]`s no longer needed ([#1022](https://github.com/ava-labs/chain/pull/1022))
- Split nodestore into functional areas ([#1048](https://github.com/ava-labs/chain/pull/1048))
- Update `golangci-lint` ([#1053](https://github.com/ava-labs/chain/pull/1053))
- Update CODEOWNERS ([#1080](https://github.com/ava-labs/chain/pull/1080))
- Run CI with --no-default-features ([#1081](https://github.com/ava-labs/chain/pull/1081))
- Release 0.0.9 ([#1084](https://github.com/ava-labs/chain/pull/1084))

## [0.0.8] - 2025-07-07

### 🚀 Features

- *(checker)* Firewood checker framework ([#936](https://github.com/ava-labs/chain/pull/936))
- Enable a configurable free list cache in the FFI ([#1017](https://github.com/ava-labs/chain/pull/1017))
- *(nodestore)* Add functionalities to iterate the free list ([#1015](https://github.com/ava-labs/chain/pull/1015))
- *(checker)* Traverse free lists ([#1026](https://github.com/ava-labs/chain/pull/1026))

### 🐛 Bug Fixes

- Unnecessary quotes in publish action ([#996](https://github.com/ava-labs/chain/pull/996))
- Report IO errors ([#1005](https://github.com/ava-labs/chain/pull/1005))
- Publish firewood-macros ([#1019](https://github.com/ava-labs/chain/pull/1019))
- Logger macros causing linting warnings ([#1021](https://github.com/ava-labs/chain/pull/1021))

### 💼 Other

- *(deps)* Update lru requirement from 0.14.0 to 0.15.0 ([#1001](https://github.com/ava-labs/chain/pull/1001))
- *(deps)* Update lru requirement from 0.15.0 to 0.16.0 ([#1023](https://github.com/ava-labs/chain/pull/1023))
- *(deps)* Upgrade sha2, tokio, clap, fastrace, serde... ([#1025](https://github.com/ava-labs/chain/pull/1025))

### 🚜 Refactor

- *(deps)* Move duplicates to workspace ([#1002](https://github.com/ava-labs/chain/pull/1002))
- *(ffi)* [**breaking**] Split starting metrics exporter from db startup ([#1016](https://github.com/ava-labs/chain/pull/1016))

### 📚 Documentation

- Document the Phase 2 regression harness, VRF/quorum alert playbook, acceptance checklist, and proof metadata release notes so operators and auditors can trace readiness artifacts.【F:docs/testing/simulations.md†L1-L120】【F:docs/observability/alerts/consensus_vrf.yaml†L1-L120】【F:docs/runbooks/phase2_acceptance.md†L1-L200】【F:docs/release_notes.md†L1-L80】【F:docs/runbooks/observability.md†L1-L160】
- README cleanup ([#1024](https://github.com/ava-labs/chain/pull/1024))

### ⚡ Performance

- Cache the latest view ([#1004](https://github.com/ava-labs/chain/pull/1004))
- Allow cloned proposals ([#1010](https://github.com/ava-labs/chain/pull/1010))
- Break up the RevisionManager lock ([#1027](https://github.com/ava-labs/chain/pull/1027))

### ⚙️ Miscellaneous Tasks

- Suppress clippy::cast_possible_truncation across the workspace ([#1012](https://github.com/ava-labs/chain/pull/1012))
- Clippy pushdown ([#1011](https://github.com/ava-labs/chain/pull/1011))
- Allow some extra pedantic warnings ([#1014](https://github.com/ava-labs/chain/pull/1014))
- Check for metrics changes ([#1013](https://github.com/ava-labs/chain/pull/1013))
- Share workspace metadata and packages ([#1020](https://github.com/ava-labs/chain/pull/1020))
- Add concurrency group to attach static libs workflow ([#1038](https://github.com/ava-labs/chain/pull/1038))
- Bump version to v0.0.8 ([#1018](https://github.com/ava-labs/chain/pull/1018))

## [0.0.7] - 2025-06-26

### 🚀 Features

- Add methods to fetch views from any hash ([#993](https://github.com/ava-labs/chain/pull/993))

### 🐛 Bug Fixes

- *(ci)* Include submodule name in ffi tag ([#991](https://github.com/ava-labs/chain/pull/991))

### ⚡ Performance

- *(metrics)* Add some metrics around propose and commit times ([#989](https://github.com/ava-labs/chain/pull/989))

### 🎨 Styling

- Use cbindgen to convert to pointers ([#969](https://github.com/ava-labs/chain/pull/969))

### 🧪 Testing

- Check support for empty proposals ([#988](https://github.com/ava-labs/chain/pull/988))

### ⚙️ Miscellaneous Tasks

- Simplify + cleanup generate_cgo script ([#979](https://github.com/ava-labs/chain/pull/979))
- Update Cargo.toml add repository field ([#987](https://github.com/ava-labs/chain/pull/987))
- *(fuzz)* Add step to upload fuzz testdata on failure ([#990](https://github.com/ava-labs/chain/pull/990))
- Add special case for non semver tags to attach static libs ([#992](https://github.com/ava-labs/chain/pull/992))
- Remove requirement for conventional commits ([#994](https://github.com/ava-labs/chain/pull/994))
- Release v0.0.7 ([#997](https://github.com/ava-labs/chain/pull/997))

## [0.0.6] - 2025-06-21

### 🚀 Features

- Improve error handling and add sync iterator ([#941](https://github.com/ava-labs/chain/pull/941))
- *(metrics)* Add read_node counters ([#947](https://github.com/ava-labs/chain/pull/947))
- Return database creation errors through FFI ([#945](https://github.com/ava-labs/chain/pull/945))
- *(ffi)* Add go generate switch between enabled cgo blocks ([#978](https://github.com/ava-labs/chain/pull/978))

### 🐛 Bug Fixes

- Use saturating subtraction for metrics counter ([#937](https://github.com/ava-labs/chain/pull/937))
- *(attach-static-libs)* Push commit/branch to remote on tag events ([#944](https://github.com/ava-labs/chain/pull/944))
- Add add_arithmetic_side_effects clippy ([#949](https://github.com/ava-labs/chain/pull/949))
- Improve ethhash warning message ([#961](https://github.com/ava-labs/chain/pull/961))
- *(storage)* Parse and validate database versions ([#964](https://github.com/ava-labs/chain/pull/964))

### 💼 Other

- *(deps)* Update fastrace-opentelemetry requirement from 0.11.0 to 0.12.0 ([#943](https://github.com/ava-labs/chain/pull/943))
- Move lints to the workspace ([#957](https://github.com/ava-labs/chain/pull/957))

### ⚡ Performance

- Remove some unecessary allocs during serialization ([#965](https://github.com/ava-labs/chain/pull/965))

### 🎨 Styling

- *(attach-static-libs)* Use go mod edit instead of sed to update mod path ([#946](https://github.com/ava-labs/chain/pull/946))

### 🧪 Testing

- *(ethhash)* Convert ethhash test to fuzz test for ethhash compatibility ([#956](https://github.com/ava-labs/chain/pull/956))

### ⚙️ Miscellaneous Tasks

- Upgrade actions/checkout ([#939](https://github.com/ava-labs/chain/pull/939))
- Add push to main to attach static libs triggers ([#952](https://github.com/ava-labs/chain/pull/952))
- Check the PR title for conventional commits ([#953](https://github.com/ava-labs/chain/pull/953))
- Add Brandon to CODEOWNERS ([#954](https://github.com/ava-labs/chain/pull/954))
- Set up for publishing to crates.io ([#962](https://github.com/ava-labs/chain/pull/962))
- Remove remnants of no-std ([#968](https://github.com/ava-labs/chain/pull/968))
- *(ffi)* Rename ffi package to match dir ([#971](https://github.com/ava-labs/chain/pull/971))
- *(attach-static-libs)* Add pre build command to set MACOSX_DEPLOYMENT_TARGET for static libs build ([#973](https://github.com/ava-labs/chain/pull/973))
- Use new firewood-go-* FFI repo naming ([#975](https://github.com/ava-labs/chain/pull/975))
- Upgrade metrics packages ([#982](https://github.com/ava-labs/chain/pull/982))
- Release v0.0.6 ([#985](https://github.com/ava-labs/chain/pull/985))

## [0.0.5] - 2025-06-05

### 🚀 Features

- *(ffi)* Ffi error messages ([#860](https://github.com/ava-labs/chain/pull/860))
- *(ffi)* Proposal creation isolated from committing ([#867](https://github.com/ava-labs/chain/pull/867))
- *(ffi)* Get values from proposals ([#877](https://github.com/ava-labs/chain/pull/877))
- *(ffi)* Full proposal support ([#878](https://github.com/ava-labs/chain/pull/878))
- *(ffi)* Support `Get` for historical revisions ([#881](https://github.com/ava-labs/chain/pull/881))
- *(ffi)* Add proposal root retrieval ([#910](https://github.com/ava-labs/chain/pull/910))

### 🐛 Bug Fixes

- *(ffi)* Prevent memory leak and tips for finding leaks ([#862](https://github.com/ava-labs/chain/pull/862))
- *(src)* Drop unused revisions ([#866](https://github.com/ava-labs/chain/pull/866))
- *(ffi)* Clarify roles of `Value` extractors ([#875](https://github.com/ava-labs/chain/pull/875))
- *(ffi)* Check revision is available ([#890](https://github.com/ava-labs/chain/pull/890))
- *(ffi)* Prevent undefined behavior on empty slices ([#894](https://github.com/ava-labs/chain/pull/894))
- Fix empty hash values ([#925](https://github.com/ava-labs/chain/pull/925))

### 💼 Other

- *(deps)* Update pprof requirement from 0.12.1 to 0.13.0 ([#283](https://github.com/ava-labs/chain/pull/283))
- *(deps)* Update lru requirement from 0.11.0 to 0.12.0 ([#306](https://github.com/ava-labs/chain/pull/306))
- *(deps)* Update typed-builder requirement from 0.16.0 to 0.17.0 ([#320](https://github.com/ava-labs/chain/pull/320))
- *(deps)* Update typed-builder requirement from 0.17.0 to 0.18.0 ([#324](https://github.com/ava-labs/chain/pull/324))
- Remove dead code ([#333](https://github.com/ava-labs/chain/pull/333))
- Kv_dump should be done with the iterator ([#347](https://github.com/ava-labs/chain/pull/347))
- Add remaining lint checks ([#397](https://github.com/ava-labs/chain/pull/397))
- Finish error handler mapper ([#421](https://github.com/ava-labs/chain/pull/421))
- Switch from EmptyDB to Db ([#422](https://github.com/ava-labs/chain/pull/422))
- *(deps)* Update aquamarine requirement from 0.3.1 to 0.4.0 ([#434](https://github.com/ava-labs/chain/pull/434))
- *(deps)* Update serial_test requirement from 2.0.0 to 3.0.0 ([#477](https://github.com/ava-labs/chain/pull/477))
- *(deps)* Update aquamarine requirement from 0.4.0 to 0.5.0 ([#496](https://github.com/ava-labs/chain/pull/496))
- *(deps)* Update env_logger requirement from 0.10.1 to 0.11.0 ([#502](https://github.com/ava-labs/chain/pull/502))
- *(deps)* Update tonic-build requirement from 0.10.2 to 0.11.0 ([#522](https://github.com/ava-labs/chain/pull/522))
- *(deps)* Update tonic requirement from 0.10.2 to 0.11.0 ([#523](https://github.com/ava-labs/chain/pull/523))
- *(deps)* Update nix requirement from 0.27.1 to 0.28.0 ([#563](https://github.com/ava-labs/chain/pull/563))
- Move clippy pragma closer to usage ([#578](https://github.com/ava-labs/chain/pull/578))
- *(deps)* Update typed-builder requirement from 0.18.1 to 0.19.1 ([#684](https://github.com/ava-labs/chain/pull/684))
- *(deps)* Update lru requirement from 0.8.0 to 0.12.4 ([#708](https://github.com/ava-labs/chain/pull/708))
- *(deps)* Update typed-builder requirement from 0.19.1 to 0.20.0 ([#711](https://github.com/ava-labs/chain/pull/711))
- *(deps)* Bump actions/download-artifact from 3 to 4.1.7 in /.github/workflows ([#715](https://github.com/ava-labs/chain/pull/715))
- Insert truncated trie
- Allow for trace and no logging
- Add read_for_update
- Revision history should never grow
- Use a more random hash
- Use smallvec to optimize for 16 byte values
- *(deps)* Update aquamarine requirement from 0.5.0 to 0.6.0 ([#727](https://github.com/ava-labs/chain/pull/727))
- *(deps)* Update thiserror requirement from 1.0.57 to 2.0.3 ([#751](https://github.com/ava-labs/chain/pull/751))
- *(deps)* Update pprof requirement from 0.13.0 to 0.14.0 ([#750](https://github.com/ava-labs/chain/pull/750))
- *(deps)* Update metrics-util requirement from 0.18.0 to 0.19.0 ([#765](https://github.com/ava-labs/chain/pull/765))
- *(deps)* Update cbindgen requirement from 0.27.0 to 0.28.0 ([#767](https://github.com/ava-labs/chain/pull/767))
- *(deps)* Update bitfield requirement from 0.17.0 to 0.18.1 ([#772](https://github.com/ava-labs/chain/pull/772))
- *(deps)* Update lru requirement from 0.12.4 to 0.13.0 ([#771](https://github.com/ava-labs/chain/pull/771))
- *(deps)* Update bitfield requirement from 0.18.1 to 0.19.0 ([#801](https://github.com/ava-labs/chain/pull/801))
- *(deps)* Update typed-builder requirement from 0.20.0 to 0.21.0 ([#815](https://github.com/ava-labs/chain/pull/815))
- *(deps)* Update tonic requirement from 0.12.1 to 0.13.0 ([#826](https://github.com/ava-labs/chain/pull/826))
- *(deps)* Update opentelemetry requirement from 0.28.0 to 0.29.0 ([#816](https://github.com/ava-labs/chain/pull/816))
- *(deps)* Update lru requirement from 0.13.0 to 0.14.0 ([#840](https://github.com/ava-labs/chain/pull/840))
- *(deps)* Update metrics-exporter-prometheus requirement from 0.16.1 to 0.17.0 ([#853](https://github.com/ava-labs/chain/pull/853))
- *(deps)* Update rand requirement from 0.8.5 to 0.9.1 ([#850](https://github.com/ava-labs/chain/pull/850))
- *(deps)* Update pprof requirement from 0.14.0 to 0.15.0 ([#906](https://github.com/ava-labs/chain/pull/906))
- *(deps)* Update cbindgen requirement from 0.28.0 to 0.29.0 ([#899](https://github.com/ava-labs/chain/pull/899))
- *(deps)* Update criterion requirement from 0.5.1 to 0.6.0 ([#898](https://github.com/ava-labs/chain/pull/898))
- *(deps)* Bump golang.org/x/crypto from 0.17.0 to 0.35.0 in /ffi/tests ([#907](https://github.com/ava-labs/chain/pull/907))
- *(deps)* Bump google.golang.org/protobuf from 1.27.1 to 1.33.0  /ffi/tests ([#923](https://github.com/ava-labs/chain/pull/923))
- *(deps)* Bump google.golang.org/protobuf from 1.30.0 to 1.33.0 ([#924](https://github.com/ava-labs/chain/pull/924))

### 🚜 Refactor

- *(ffi)* Cleanup unused and duplicate code ([#926](https://github.com/ava-labs/chain/pull/926))

### 📚 Documentation

- Document the Phase 2 regression harness, VRF/quorum alert playbook, acceptance checklist, and proof metadata release notes so operators and auditors can trace readiness artifacts.【F:docs/testing/simulations.md†L1-L120】【F:docs/observability/alerts/consensus_vrf.yaml†L1-L120】【F:docs/runbooks/phase2_acceptance.md†L1-L200】【F:docs/release_notes.md†L1-L80】【F:docs/runbooks/observability.md†L1-L160】
- *(ffi)* Remove private declarations from public docs ([#874](https://github.com/ava-labs/chain/pull/874))

### 🧪 Testing

- *(ffi/tests)* Basic eth compatibility ([#825](https://github.com/ava-labs/chain/pull/825))
- *(ethhash)* Use libevm ([#900](https://github.com/ava-labs/chain/pull/900))

### ⚙️ Miscellaneous Tasks

- Use `decode` in single key proof verification ([#295](https://github.com/ava-labs/chain/pull/295))
- Use `decode` in range proof verification ([#303](https://github.com/ava-labs/chain/pull/303))
- Naming the elements of `ExtNode` ([#305](https://github.com/ava-labs/chain/pull/305))
- Remove the getter pattern over `ExtNode` ([#310](https://github.com/ava-labs/chain/pull/310))
- Proof cleanup ([#316](https://github.com/ava-labs/chain/pull/316))
- *(ffi/tests)* Update go-ethereum v1.15.7 ([#838](https://github.com/ava-labs/chain/pull/838))
- *(ffi)* Fix typo fwd_close_db comment ([#843](https://github.com/ava-labs/chain/pull/843))
- *(ffi)* Add linter ([#893](https://github.com/ava-labs/chain/pull/893))
- Require conventional commit format ([#933](https://github.com/ava-labs/chain/pull/933))
- Bump to v0.5.0 ([#934](https://github.com/ava-labs/chain/pull/934))

## [0.0.4] - 2023-09-27

### 🚀 Features

- Identify a revision with root hash ([#126](https://github.com/ava-labs/chain/pull/126))
- Supports chains of `StoreRevMut` ([#175](https://github.com/ava-labs/chain/pull/175))
- Add proposal ([#181](https://github.com/ava-labs/chain/pull/181))

### 🐛 Bug Fixes

- Update release to cargo-workspace-version ([#75](https://github.com/ava-labs/chain/pull/75))

### 💼 Other

- *(deps)* Update criterion requirement from 0.4.0 to 0.5.1 ([#96](https://github.com/ava-labs/chain/pull/96))
- *(deps)* Update enum-as-inner requirement from 0.5.1 to 0.6.0 ([#107](https://github.com/ava-labs/chain/pull/107))
- :position FTW? ([#140](https://github.com/ava-labs/chain/pull/140))
- *(deps)* Update indexmap requirement from 1.9.1 to 2.0.0 ([#147](https://github.com/ava-labs/chain/pull/147))
- *(deps)* Update pprof requirement from 0.11.1 to 0.12.0 ([#152](https://github.com/ava-labs/chain/pull/152))
- *(deps)* Update typed-builder requirement from 0.14.0 to 0.15.0 ([#153](https://github.com/ava-labs/chain/pull/153))
- *(deps)* Update lru requirement from 0.10.0 to 0.11.0 ([#155](https://github.com/ava-labs/chain/pull/155))
- Update hash fn to root_hash ([#170](https://github.com/ava-labs/chain/pull/170))
- Remove generics on Db ([#196](https://github.com/ava-labs/chain/pull/196))
- Remove generics for Proposal ([#197](https://github.com/ava-labs/chain/pull/197))
- Use quotes around all ([#200](https://github.com/ava-labs/chain/pull/200))
- :get<K>: use Nibbles ([#210](https://github.com/ava-labs/chain/pull/210))
- Variable renames ([#211](https://github.com/ava-labs/chain/pull/211))
- Use thiserror ([#221](https://github.com/ava-labs/chain/pull/221))
- *(deps)* Update typed-builder requirement from 0.15.0 to 0.16.0 ([#222](https://github.com/ava-labs/chain/pull/222))
- *(deps)* Update tonic-build requirement from 0.9.2 to 0.10.0 ([#247](https://github.com/ava-labs/chain/pull/247))
- *(deps)* Update prost requirement from 0.11.9 to 0.12.0 ([#246](https://github.com/ava-labs/chain/pull/246))

### ⚙️ Miscellaneous Tasks

- Refactor `rev.rs` ([#74](https://github.com/ava-labs/chain/pull/74))
- Disable `test_buffer_with_redo` ([#128](https://github.com/ava-labs/chain/pull/128))
- Verify concurrent committing write batches ([#172](https://github.com/ava-labs/chain/pull/172))
- Remove redundant code ([#174](https://github.com/ava-labs/chain/pull/174))
- Remove unused clone for `StoreRevMutDelta` ([#178](https://github.com/ava-labs/chain/pull/178))
- Abstract out mutable store creation ([#176](https://github.com/ava-labs/chain/pull/176))
- Proposal test cleanup ([#184](https://github.com/ava-labs/chain/pull/184))
- Add comments for `Proposal` ([#186](https://github.com/ava-labs/chain/pull/186))
- Deprecate `WriteBatch` and use `Proposal` instead ([#188](https://github.com/ava-labs/chain/pull/188))
- Inline doc clean up ([#240](https://github.com/ava-labs/chain/pull/240))
- Remove unused blob in db ([#245](https://github.com/ava-labs/chain/pull/245))
- Add license header to firewood files ([#262](https://github.com/ava-labs/chain/pull/262))
- Revert back `test_proof` changes accidentally changed ([#279](https://github.com/ava-labs/chain/pull/279))

## [0.0.3] - 2023-04-28

### 💼 Other

- Move benching to criterion ([#61](https://github.com/ava-labs/chain/pull/61))
- Refactor file operations to use a Path ([#26](https://github.com/ava-labs/chain/pull/26))
- Fix panic get_item on a dirty write ([#66](https://github.com/ava-labs/chain/pull/66))
- Improve error handling ([#70](https://github.com/ava-labs/chain/pull/70))

### 🧪 Testing

- Speed up slow unit tests ([#58](https://github.com/ava-labs/chain/pull/58))

### ⚙️ Miscellaneous Tasks

- Add backtrace to e2e tests ([#59](https://github.com/ava-labs/chain/pull/59))

## [0.0.2] - 2023-04-21

### 💼 Other

- Fix test flake ([#44](https://github.com/ava-labs/chain/pull/44))

### 📚 Documentation

- Document the Phase 2 regression harness, VRF/quorum alert playbook, acceptance checklist, and proof metadata release notes so operators and auditors can trace readiness artifacts.【F:docs/testing/simulations.md†L1-L120】【F:docs/observability/alerts/consensus_vrf.yaml†L1-L120】【F:docs/runbooks/phase2_acceptance.md†L1-L200】【F:docs/release_notes.md†L1-L80】【F:docs/runbooks/observability.md†L1-L160】
- Add release notes ([#27](https://github.com/ava-labs/chain/pull/27))
- Update CODEOWNERS ([#28](https://github.com/ava-labs/chain/pull/28))
- Add badges to README ([#33](https://github.com/ava-labs/chain/pull/33))

## [0.0.1] - 2023-04-14

### 🐛 Bug Fixes

- Clippy linting
- Specificy --lib in rustdoc linters
- Unset the pre calculated RLP values of interval nodes
- Run cargo clippy --fix
- Handle empty key value proof arguments as an error
- Tweak repo organization ([#130](https://github.com/ava-labs/chain/pull/130))
- Run clippy --fix across all workspaces ([#149](https://github.com/ava-labs/chain/pull/149))
- Update StoreError to use thiserror ([#156](https://github.com/ava-labs/chain/pull/156))
- Update db::new() to accept a Path ([#187](https://github.com/ava-labs/chain/pull/187))
- Use bytemuck instead of unsafe in growth-ring ([#185](https://github.com/ava-labs/chain/pull/185))
- Update firewood sub-projects ([#16](https://github.com/ava-labs/chain/pull/16))

### 💼 Other

- Fix additional clippy warnings
- Additional clippy fixes
- Fix additional clippy warnings
- Fix outstanding lint issues
- *(deps)* Update nix requirement from 0.25.0 to 0.26.1
- Update version to 0.0.1
- Add usage examples
- Add fwdctl create command
- Add fwdctl README and test
- Fix flag arguments; add fwdctl documentation
- Add logger
- Use log-level flag for setting logging level
- *(deps)* Update lru requirement from 0.8.0 to 0.9.0
- Add generic key value insertion command
- Add get command
- Add delete command
- Move cli tests under tests/
- Only use kv_ functions in fwdctl
- Fix implementation and add tests
- Add exit codes and stderr error logging
- Add tests
- Add serial library for testing purposes
- Add root command
- Add dump command
- Fixup root tests to be serial
- *(deps)* Update typed-builder requirement from 0.11.0 to 0.12.0
- Add VSCode
- Update merkle_utils to return Results
- Fixup command UX to be positional
- Update firewood to match needed functionality
- Update DB and Merkle errors to implement the Error trait
- Update proof errors
- Add StdError trait to ProofError
- *(deps)* Update nix requirement from 0.25.0 to 0.26.2
- *(deps)* Update lru requirement from 0.8.0 to 0.10.0
- *(deps)* Update typed-builder requirement from 0.12.0 to 0.13.0
- *(deps)* Update typed-builder requirement from 0.13.0 to 0.14.0 ([#144](https://github.com/ava-labs/chain/pull/144))
- Update create_file to return a Result ([#150](https://github.com/ava-labs/chain/pull/150))
- *(deps)* Update predicates requirement from 2.1.1 to 3.0.1 ([#154](https://github.com/ava-labs/chain/pull/154))
- Add new library crate ([#158](https://github.com/ava-labs/chain/pull/158))
- *(deps)* Update serial_test requirement from 1.0.0 to 2.0.0 ([#173](https://github.com/ava-labs/chain/pull/173))
- Refactor kv_remove to be more ergonomic ([#168](https://github.com/ava-labs/chain/pull/168))
- Add e2e test ([#167](https://github.com/ava-labs/chain/pull/167))
- Use eth and proof feature gates across all API surfaces. ([#181](https://github.com/ava-labs/chain/pull/181))
- Add license header to firewood source code ([#189](https://github.com/ava-labs/chain/pull/189))

### 📚 Documentation

- Document the Phase 2 regression harness, VRF/quorum alert playbook, acceptance checklist, and proof metadata release notes so operators and auditors can trace readiness artifacts.【F:docs/testing/simulations.md†L1-L120】【F:docs/observability/alerts/consensus_vrf.yaml†L1-L120】【F:docs/runbooks/phase2_acceptance.md†L1-L200】【F:docs/release_notes.md†L1-L80】【F:docs/runbooks/observability.md†L1-L160】
- Add link to fwdctl README in main README
- Update fwdctl README with storage information
- Update fwdctl README with more examples
- Document get_revisions function with additional information. ([#177](https://github.com/ava-labs/chain/pull/177))
- Add alpha warning to firewood README ([#191](https://github.com/ava-labs/chain/pull/191))

### 🧪 Testing

- Add more range proof tests
- Update tests to use Results
- Re-enable integration tests after introduce cargo workspaces

### ⚙️ Miscellaneous Tasks

- Add release and publish GH Actions
- Update batch sizes in ci e2e job
- Add docs linter to strengthen firewood documentation
- Clippy should fail in case of warnings ([#151](https://github.com/ava-labs/chain/pull/151))
- Fail in case of error publishing firewood crate ([#21](https://github.com/ava-labs/chain/pull/21))

<!-- generated by git-cliff -->
