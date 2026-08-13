# Build the SPP forester binary.
#
# The forester crate depends on workspace crates (zolana-tree,
# zolana-batched-merkle-tree, zolana-interface, ...), so the build context must
# be the repository root, not just forester/:
#
#   docker build -f forester/Dockerfile .
#
# A bare `docker build forester/` will NOT work; the root .dockerignore keeps the
# context small.
#
# rust:1.95: the workspace pulls solana crates that need a recent toolchain.
#
# Pinned by digest, and to the same digests services/photon/Dockerfile uses: this
# image is attested now, and a mutable tag lets one commit produce different
# bytes depending on when it was built, which is exactly what the attestation is
# supposed to rule out. Sharing photon's pins also shares the base layers.
FROM rust:1.95-slim-bookworm@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082 AS builder
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

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/forester /usr/local/bin/forester
WORKDIR /app

ENTRYPOINT ["/usr/local/bin/forester"]
CMD []
