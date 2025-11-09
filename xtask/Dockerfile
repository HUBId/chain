# syntax=docker/dockerfile:1.6

FROM rust:nightly-slim AS chef
WORKDIR /workspace
RUN apt-get update \
    && apt-get install --no-install-recommends -y pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM rust:nightly-slim AS builder
WORKDIR /workspace
RUN apt-get update \
    && apt-get install --no-install-recommends -y pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN cargo install cargo-chef --locked
COPY --from=chef /workspace/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --locked --release --package xtask

FROM debian:bookworm-slim AS runtime
RUN useradd --create-home --uid 1000 xtask
WORKDIR /workspace
COPY --from=builder /workspace/target/release/xtask /usr/local/bin/xtask
USER xtask
ENTRYPOINT ["/usr/local/bin/xtask"]
CMD ["--help"]
