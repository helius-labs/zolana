FROM rust:1.95-slim-bookworm@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082 AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        git \
        libssl-dev \
        pkg-config \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# This Dockerfile is built from the repository root so Photon and its protocol
# dependencies are resolved from the same workspace and lockfile.
COPY . .

RUN cargo build --locked --release -p photon-indexer \
    --bin photon \
    --bin photon-migration \
    --bin photon-snapshotter \
    --bin photon-snapshot-loader

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 photon \
    && useradd --system --uid 10001 --gid photon \
        --home-dir /var/lib/photon --create-home photon

COPY --from=builder --chmod=0755 /workspace/target/release/photon /usr/local/bin/photon
COPY --from=builder --chmod=0755 /workspace/target/release/photon-migration /usr/local/bin/photon-migration
COPY --from=builder --chmod=0755 /workspace/target/release/photon-snapshotter /usr/local/bin/photon-snapshotter
COPY --from=builder --chmod=0755 /workspace/target/release/photon-snapshot-loader /usr/local/bin/photon-snapshot-loader
COPY LICENSE THIRD_PARTY_NOTICES /usr/share/licenses/zolana/

LABEL org.opencontainers.image.title="Zolana Photon" \
      org.opencontainers.image.description="Zolana shielded-pool indexer" \
      org.opencontainers.image.source="https://github.com/helius-labs/zolana" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV HOME=/var/lib/photon
WORKDIR /var/lib/photon
USER photon

EXPOSE 8784
STOPSIGNAL SIGINT
CMD ["photon"]
