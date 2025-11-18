# syntax=docker/dockerfile:1.7
ARG RUST_IMAGE=rust:1.79-bullseye
FROM ${RUST_IMAGE} AS builder
SHELL ["/bin/bash", "-c"]

ARG WALLET_TARGET="x86_64-unknown-linux-gnu"
ARG WALLET_PROFILE=release
ARG WALLET_FEATURE_FLAGS="--no-default-features --features runtime,prover-stwo"
ARG WALLET_GUI_FEATURE_FLAGS="--no-default-features --features wallet_gui,prover-stwo"
ARG EXTRA_CARGO_FLAGS=""

ENV CARGO_TARGET_DIR=/workspace/target

RUN apt-get update \ 
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        pkg-config \
        libgtk-3-dev \
        libx11-dev \
        libxcursor-dev \
        libxrandr-dev \
        libxkbcommon-dev \
        libwayland-dev \
        libxcb-render0-dev \
        libxcb-shape0-dev \
        libxcb-xfixes0-dev \
        libxcb1-dev \
        libegl1-mesa-dev \
        libxi-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY . .

RUN rustup target add ${WALLET_TARGET}

RUN set -euo pipefail; \
    BUILD_TOOL="cargo"; \
    if [[ "${WALLET_TARGET}" != "x86_64-unknown-linux-gnu" ]]; then \
        cargo install --locked cross; \
        BUILD_TOOL="cross"; \
    fi; \
    ${BUILD_TOOL} build --locked --package rpp-wallet --bin rpp-wallet --profile "${WALLET_PROFILE}" --target "${WALLET_TARGET}" ${WALLET_FEATURE_FLAGS} ${EXTRA_CARGO_FLAGS}; \
    ${BUILD_TOOL} build --locked --package rpp-wallet-lib --bin rpp-wallet-gui --profile "${WALLET_PROFILE}" --target "${WALLET_TARGET}" ${WALLET_GUI_FEATURE_FLAGS} ${EXTRA_CARGO_FLAGS}

FROM debian:bookworm-slim AS runtime
ARG WALLET_TARGET="x86_64-unknown-linux-gnu"
ARG WALLET_PROFILE=release

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

ENV RPP_WALLET_DATA_DIR=/var/lib/rpp-wallet \
    RPP_WALLET_CONFIG=/etc/rpp-wallet/wallet.toml

WORKDIR /opt/rpp-wallet
RUN useradd --system --home /var/lib/rpp-wallet --shell /usr/sbin/nologin app
RUN install -d -o app -g app /opt/rpp-wallet/bin /var/lib/rpp-wallet /etc/rpp-wallet

COPY --from=builder /workspace/target/${WALLET_TARGET}/${WALLET_PROFILE}/rpp-wallet /opt/rpp-wallet/bin/rpp-wallet
COPY --from=builder /workspace/target/${WALLET_TARGET}/${WALLET_PROFILE}/rpp-wallet-gui /opt/rpp-wallet/bin/rpp-wallet-gui
COPY config/wallet.toml /etc/rpp-wallet/wallet.toml

RUN chown -R app:app /opt/rpp-wallet /var/lib/rpp-wallet /etc/rpp-wallet && \
    chmod 0755 /opt/rpp-wallet/bin/rpp-wallet /opt/rpp-wallet/bin/rpp-wallet-gui

USER app
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/opt/rpp-wallet/bin/rpp-wallet", "--config", "/etc/rpp-wallet/wallet.toml"]
