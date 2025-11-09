# syntax=docker/dockerfile:1

FROM rust:1.79 AS builder
WORKDIR /workspace

# Build application
COPY . .
RUN cargo build --release --package firewood-fwdctl

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

ENV FWDCTL_HEALTH_PORT=8080

# Create non-root user
RUN useradd --system --create-home --uid 10001 fwdctl

COPY --from=builder /workspace/target/release/fwdctl /usr/local/bin/fwdctl

USER fwdctl
WORKDIR /home/fwdctl

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD-SHELL curl --fail http://127.0.0.1:${FWDCTL_HEALTH_PORT:-8080}/health/ready || exit 1

ENTRYPOINT ["fwdctl"]
CMD ["--help"]
