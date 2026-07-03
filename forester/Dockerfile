# Build the SPP forester binary.
#
# The forester crate depends on workspace crates (zolana-tree,
# zolana-batched-merkle-tree, zolana-interface, ...), so the build context must
# be the whole zolana workspace root, not just forester/. In docker-bake.hcl the
# `forester` target sets `context = ./zolana-main`; a bare `docker build
# forester/` will NOT work.
#
# rust:1.95 matches the photon builder (docker-compose.yml x-photon-image): the
# workspace pulls solana crates that need a recent toolchain, and 1.92 (the old
# pin here) is stale.
FROM rust:1.95-slim-bookworm AS builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    lld \
    pkg-config \
    libssl-dev \
    git \
    ca-certificates \
    protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

# Whole workspace as context (kept small by zolana-main/.dockerignore, which
# excludes target/, .git/, proving-keys/, ...).
COPY . .
RUN cargo build --release --package forester

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/forester /usr/local/bin/forester
WORKDIR /app

ENTRYPOINT ["/usr/local/bin/forester"]
CMD []
