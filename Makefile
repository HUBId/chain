# Helper targets for running workspace builds with explicit toolchains.

STABLE_TOOLCHAIN ?= +1.79.0
NIGHTLY_TOOLCHAIN ?= +nightly-2025-07-14
PROVER_MANIFEST ?= prover/Cargo.toml
PROVER_CRATES ?= prover_stwo_backend

EXCLUDE_PROVER_FLAGS := $(foreach crate,$(PROVER_CRATES),--exclude $(crate))

.PHONY: build\:stable test\:stable build\:nightly test\:nightly vendor-plonky3

## Build all stable workspace crates (excluding prover backends) with the pinned toolchain.
build\:stable:
	cargo $(STABLE_TOOLCHAIN) build --workspace $(EXCLUDE_PROVER_FLAGS)

## Run the stable workspace test suite (excluding prover backends) with the pinned toolchain.
test\:stable:
	cargo $(STABLE_TOOLCHAIN) test --workspace $(EXCLUDE_PROVER_FLAGS)

## Build the prover workspace using the nightly toolchain.
build\:nightly:
	cargo $(NIGHTLY_TOOLCHAIN) build --manifest-path $(PROVER_MANIFEST) --workspace

## Run prover tests using the nightly toolchain.
test\:nightly:
        cargo $(NIGHTLY_TOOLCHAIN) test --manifest-path $(PROVER_MANIFEST) --workspace

## Refresh the Plonky3 vendor mirror under third_party/plonky3/.
vendor-plonky3:
        python3 scripts/vendor_plonky3/refresh.py

.PHONY: pruning-validation test\:unit test\:integration test\:simnet test\:all

## Run pruning receipt conformance checks to guard snapshot publication.
pruning-validation:
        cargo xtask pruning-validation

## Execute lightweight unit suites that focus on deterministic circuit and storage behaviour.
test\:unit:
        cargo xtask test-unit

## Execute integration workflows for pipeline, snapshot, and operator RPC lifecycles.
test\:integration:
        cargo xtask test-integration

## Run the CI simnet scenario that exercises orchestrator wiring.
test\:simnet:
        cargo xtask test-simnet

## Run the full multi-layer validation stack (unit + integration + simnet).
test\:all:
        cargo xtask test-all
