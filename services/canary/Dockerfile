# Builds the synthetic-transfer canary with the repository root as context: docker build -f services/canary/Dockerfile .
# Ships no keys: the wallet and the API key arrive at runtime from the task definition.

# Same digests as protocol-ops/forester/Dockerfile and services/photon/Dockerfile, so the base layers are shared.
FROM rust:1.98.1-slim-bookworm@sha256:ebd900bae66fd508b466cef82d64a83a5fb34682e4c8b2797a42908bddc95a57 AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    pkg-config \
    libssl-dev \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --locked --release --package spr-canary

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/spr-canary /usr/local/bin/spr-canary

RUN groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin nonroot
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/spr-canary"]
CMD []
