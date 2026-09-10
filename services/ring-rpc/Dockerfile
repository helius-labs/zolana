FROM rust:1.98.1-slim-bookworm@sha256:ebd900bae66fd508b466cef82d64a83a5fb34682e4c8b2797a42908bddc95a57 AS builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        git \
        pkg-config \
        protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace

# Built from the repository root so the ring RPC and its protocol dependencies
# resolve from the same workspace and lockfile.
COPY . .

RUN cargo build --locked --release -p zolana-ring-rpc --bin ring-rpc

FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10002 ring-rpc \
    && useradd --system --uid 10002 --gid ring-rpc \
        --home-dir /var/lib/ring-rpc --create-home ring-rpc

COPY --from=builder --chmod=0755 /workspace/target/release/ring-rpc /usr/local/bin/ring-rpc
COPY LICENSE THIRD_PARTY_NOTICES /usr/share/licenses/zolana/

LABEL org.opencontainers.image.title="Zolana Ring RPC" \
      org.opencontainers.image.description="Zolana custom ring audit RPC" \
      org.opencontainers.image.source="https://github.com/helius-labs/zolana" \
      org.opencontainers.image.licenses="Apache-2.0"

ENV HOME=/var/lib/ring-rpc
WORKDIR /var/lib/ring-rpc
USER ring-rpc

EXPOSE 8785
STOPSIGNAL SIGINT
ENTRYPOINT ["ring-rpc"]
CMD ["serve"]
