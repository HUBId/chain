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

# Build the rpp-node binary
COPY . .
RUN cargo build --locked --release -p rpp-node

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --home /app --shell /usr/sbin/nologin app

WORKDIR /app

COPY --from=builder /workspace/target/release/rpp-node /usr/local/bin/rpp-node

# Entry point wrapper to inject environment-based RPC overrides
RUN set -eux; \
    cat <<'ENTRYPOINT' > /usr/local/bin/docker-entrypoint.sh; \
    chmod +x /usr/local/bin/docker-entrypoint.sh
#!/bin/sh
set -e

# Default to the node runtime when no explicit subcommand is provided.
if [ $# -eq 0 ] || [ "${1#-}" != "$1" ]; then
    set -- node "$@"
fi

case "$1" in
    node|wallet|hybrid)
        mode="$1"
        shift
        ;;
    *)
        exec /usr/local/bin/rpp-node "$@"
        ;;
esac

RPC_ADDR="${RPP_NODE_RPC_ADDR:-0.0.0.0}"
RPC_PORT="${RPP_NODE_RPC_PORT:-7070}"

has_rpc_listen=0
for arg in "$@"; do
    case "$arg" in
        --rpc-listen|--rpc-listen=*)
            has_rpc_listen=1
            break
            ;;
    esac
done

if [ $has_rpc_listen -eq 0 ]; then
    set -- "$@" --rpc-listen "${RPC_ADDR}:${RPC_PORT}"
fi

exec /usr/local/bin/rpp-node "$mode" "$@"
ENTRYPOINT

ENV RPP_NODE_RPC_ADDR=0.0.0.0 \
    RPP_NODE_RPC_PORT=7070

USER app

EXPOSE 7070

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD /bin/sh -c 'PORT="${RPP_NODE_RPC_PORT:-7070}"; curl -fsS "http://127.0.0.1:${PORT}/health/live" >/dev/null && curl -fsS "http://127.0.0.1:${PORT}/health/ready" >/dev/null'

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD []
