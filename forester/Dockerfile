# Build the SPP forester binary.
#
# The forester crate depends on workspace crates (zolana-tree,
# zolana-batched-merkle-tree, zolana-interface, ...), so the build context must
# be the repository root, not just forester/:
#
#   docker build -f forester/Dockerfile .
#
# A bare `docker build forester/` will NOT work. The root .dockerignore keeps the
# context small. The compose/bake orchestration that wires this image together
# with photon, the prover, and postgres lives outside this repo (ops workspace).
#
# rust:1.95: the workspace pulls solana crates that need a recent toolchain.
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

# Repository root as context (kept small by the root .dockerignore, which
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
