# Zolana stack (docker)

Photon (Rings indexer) + Postgres + Redis + Prover, plus an optional forester.
One compose file for local dev and remote servers. Build contexts are
repo-root-relative, so run everything from the repo root.

## Run

```bash
# Pull the published images (server-safe; no source tree needed):
docker compose -f docker/docker-compose.yml up -d

# Build from source instead (dev box):
docker compose -f docker/docker-compose.yml up -d --build
```

Copy `docker/.env.example` to `docker/.env` and fill it in first (auto-loaded).

Photon indexes an external host Solana RPC (default `host.docker.internal:8899`)
— run the validator yourself via the zolana CLI / `just`.

## Build photon from source (opt-in)

The default path pulls the published photon image. Building photon from source
is opt-in via the `build-photon` profile; `PHOTON_BUILD_CONTEXT` must point at a
local photon (Rust) checkout current with this repo.

```bash
PHOTON_BUILD_CONTEXT=../photon PHOTON_IMAGE=zolana-photon:local \
  docker compose -f docker/docker-compose.yml --profile build-photon build photon-build
PHOTON_IMAGE=zolana-photon:local docker compose -f docker/docker-compose.yml up -d
```

## Forester (opt-in)

The forester and its dedicated prover/redis are gated behind the `forester`
profile, so a plain `up` never starts them.

```bash
docker compose -f docker/docker-compose.yml --profile forester up -d
```

The forester prover needs its batched tree-maintenance keys staged before a
`--build`:

```bash
cd prover/server && gh release download transfer-keys-v10 \
  --repo helius-labs/zolana --pattern 'batch_address-append_*.key' \
  --pattern CHECKSUM --dir proving-keys --clobber
```

## Publish images (docker-bake.hcl)

Bake reads the build config (contexts, inline Dockerfiles, the `..` patch
context) from `docker-compose.yml`; the HCL only sets platforms, registry tags,
and supplies photon's build context. Run from the repo root. Your local build is
your Mac's arch (arm64); a typical x86 server needs `linux/amd64`.

```bash
# One-time: a builder that can cross-build + push multi-arch manifests.
docker buildx create --name zolana --driver docker-container --use
docker buildx inspect --bootstrap        # installs QEMU emulators

# Publish photon + the SPP prover (add ,linux/arm64 to PLATFORMS for multi-arch):
docker login
REGISTRY=sergeytimoshin TAG=devnet \
  docker buildx bake -f docker/docker-compose.yml -f docker/docker-bake.hcl --push

# Forester prover (stage its keys first; see above):
docker buildx bake -f docker/docker-compose.yml -f docker/docker-bake.hcl prover-forester --push
```

The photon (Rust) amd64 build runs under QEMU emulation on an arm64 Mac and is
slow (tens of minutes); a native amd64 host/CI is faster.
