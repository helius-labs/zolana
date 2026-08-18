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
# No build secret is needed. The workspace's three git dependencies
# (Lightprotocol/groth16-solana, light-program-profiler, token) are all public,
# so the PRIVATE_LIBS_TOKEN that CI's setup-rust action configures is not
# required here. Verify with `git ls-remote` before adding secret plumbing.
#
# Ships NO keys. The forester's signing keypair arrives at runtime as PAYER,
# injected from Secrets Manager by the ECS task definition.

# Pinned by digest, to the same digests services/photon/Dockerfile uses: a
# mutable tag lets one commit produce different bytes depending on when it was
# built, which is what the build attestation exists to rule out. Sharing photon's
# pins also shares the base layers.
#
# rust-toolchain.toml pins 1.97.0, so rustup downloads it over this base on every
# build. That costs ~30s and is harmless: the pinned toolchain is the one that
# compiles. Moving this FROM to a 1.97 digest would remove the download and
# unshare photon's layers.
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
#
# Deliberately not split into a deps-then-source build: pre-building
# dependencies needs every workspace member's Cargo.toml staged first, and this
# workspace has enough members that the manifest list silently goes stale. A
# slower cold build beats a cache that skips a changed crate.
COPY . .
RUN cargo build --release --package forester

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/forester /usr/local/bin/forester

# Runs unprivileged: the forester opens one listening socket and signs with a
# key from the environment. It never writes to disk. 65532 matches the
# distroless `nonroot` uid the prover image uses, so both services present the
# same identity to the platform.
RUN groupadd --gid 65532 nonroot \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin nonroot
USER 65532:65532

WORKDIR /app

# Prometheus metrics, served when --metrics-address is passed. Same port the
# prover uses; the two run as separate ECS services with separate awsvpc ENIs,
# so there is no collision and one scrape config shape works for both.
EXPOSE 9998

ENTRYPOINT ["/usr/local/bin/forester"]
CMD []
