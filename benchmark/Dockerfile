# syntax=docker/dockerfile:1

FROM rustlang/rust:nightly AS builder
WORKDIR /workspace

# Install build dependencies required by the workspace
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang \
        cmake \
        libssl-dev \
        make \
        pkg-config \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Cache dependency resolution layers
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY build.rs ./
COPY benchmark/Cargo.toml benchmark/
COPY ffi/Cargo.toml ffi/
COPY firewood/Cargo.toml firewood/
COPY firewood-macros/Cargo.toml firewood-macros/
COPY fwdctl/Cargo.toml fwdctl/
COPY storage/Cargo.toml storage/
COPY storage-firewood/Cargo.toml storage-firewood/
COPY triehash/Cargo.toml triehash/
COPY prover/Cargo.toml prover/
COPY prover/plonky3_backend/Cargo.toml prover/plonky3_backend/
COPY rpp/Cargo.toml rpp/
COPY rpp/chain/Cargo.toml rpp/chain/
COPY rpp/consensus/Cargo.toml rpp/consensus/
COPY rpp/crypto/Cargo.toml rpp/crypto/
COPY rpp/crypto-vrf/Cargo.toml rpp/crypto-vrf/
COPY rpp/identity-tree/Cargo.toml rpp/identity-tree/
COPY rpp/p2p/Cargo.toml rpp/p2p/
COPY rpp/pruning/Cargo.toml rpp/pruning/
COPY rpp/node/Cargo.toml rpp/node/
COPY rpp/runtime/Cargo.toml rpp/runtime/
COPY rpp/storage/Cargo.toml rpp/storage/
COPY rpp/wallet/Cargo.toml rpp/wallet/
COPY tools/simnet/Cargo.toml tools/simnet/
COPY tools/snapshot-verify/Cargo.toml tools/snapshot-verify/
COPY tools/worm-export-stub/Cargo.toml tools/worm-export-stub/
COPY vendor ./vendor
COPY xtask/Cargo.toml xtask/

RUN cargo metadata --locked --format-version 1 > /dev/null

# Build the benchmark binary
COPY . .
RUN cargo build --locked --release -p firewood-benchmark

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home /firewood --shell /usr/sbin/nologin firewood

WORKDIR /firewood

COPY --from=builder /workspace/target/release/benchmark /usr/local/bin/benchmark
COPY benchmark/docker-entrypoint.sh /usr/local/bin/benchmark-entrypoint

RUN chmod +x /usr/local/bin/benchmark-entrypoint \
    && install -d -o firewood -g firewood /firewood/data

ENV FIREWOOD_BENCH_DB_PATH="/firewood/data/benchmark_db" \
    FIREWOOD_BENCH_TELEMETRY="" \
    FIREWOOD_BENCH_DURATION_MINUTES=""

USER firewood

ENTRYPOINT ["/usr/local/bin/benchmark-entrypoint"]
CMD ["--help"]
