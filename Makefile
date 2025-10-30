# Helper targets for running workspace builds with explicit toolchains.

STABLE_TOOLCHAIN ?= +1.79.0
NIGHTLY_TOOLCHAIN ?= +nightly-2025-07-14
PROVER_MANIFEST ?= prover/Cargo.toml
PROVER_CRATES ?= prover_stwo_backend

EXCLUDE_PROVER_FLAGS := $(foreach crate,$(PROVER_CRATES),--exclude $(crate))

.PHONY: build\:stable test\:stable build\:nightly test\:nightly

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

.PHONY: pruning-validation

## Run pruning receipt conformance checks to guard snapshot publication.
pruning-validation:
        cargo xtask pruning-validation
