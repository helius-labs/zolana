# The TEE policy freshness Lambda, and the tee-policy CLI beside it.
#
#   docker build -f prover/tee/policy/Dockerfile .
#
# The context is the repository root (kept small by the root .dockerignore):
# the crate reads the SDK's pinned signers from sdk-libs/client.
#
# Lambda runs the image's entrypoint as a custom runtime; lambda_runtime speaks
# the Runtime API, so the base image only needs CA roots. Built and run on the
# same Debian release as the forester, pinned to the same digests.
#
# Keep the builder aligned with rust-toolchain.toml.
FROM rust:1.98.1-slim-bookworm@sha256:ebd900bae66fd508b466cef82d64a83a5fb34682e4c8b2797a42908bddc95a57 AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang \
    cmake \
    pkg-config \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --locked --release --package spr-tee-policy --bins

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/tee-policy-freshness /usr/local/bin/tee-policy-freshness
COPY --from=builder /app/target/release/tee-policy /usr/local/bin/tee-policy
USER 65534:65534
ENTRYPOINT ["/usr/local/bin/tee-policy-freshness"]
