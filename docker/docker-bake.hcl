# Build + PUBLISH the photon and prover images for a remote server. This is the
# PUBLISH path; the RUN path is the single docker/docker-compose.yml, whose
# services default to PULLING these published images (${PHOTON_IMAGE},
# ${PROVER_IMAGE}, ...) -- `up` pulls, `up --build` builds from source. Run bake
# from the repo root so the repo-relative build contexts (`..`, `../prover/server`)
# resolve.
#
# The build config (contexts, inline Dockerfiles, the `..` patch context) is read
# from docker/docker-compose.yml; this file only overrides the target platform(s),
# registry tags, and -- for photon -- supplies the build context that the compose
# run path omits (compose gates photon-build behind the build-photon profile).
# Images are published under the sergeytimoshin/* Docker Hub account (the same
# tags the compose services default to). Your local build is your Mac's arch
# (arm64) -- a typical x86 server needs linux/amd64.
#
# One-time: a builder that can cross-build + push multi-arch manifests.
#   docker buildx create --name zolana --driver docker-container --use
#   docker buildx inspect --bootstrap        # installs QEMU emulators
#
# Publish (linux/amd64 for an x86 server; add ,linux/arm64 for multi-arch), run
# from the repo root. Using Docker Hub under the `sergeytimoshin` account for now
# (private protocol; switch REGISTRY to ghcr.io/helius-labs once it's
# open-sourced there):
#   docker login
#   REGISTRY=sergeytimoshin TAG=devnet \
#     docker buildx bake -f docker/docker-compose.yml -f docker/docker-bake.hcl --push
#
# NOTE: the photon (Rust) amd64 build runs under QEMU emulation on an arm64 Mac
# and is slow (tens of minutes). Building on a native amd64 host/CI is faster.

variable "REGISTRY" { default = "sergeytimoshin" }
variable "TAG" { default = "devnet" }
variable "PLATFORMS" { default = "linux/amd64" }

# Default = photon + the SPP (client-facing) prover. photon-migration reuses the
# photon image (same tag) at run time, so it must not be a separate push target
# (it carries no registry tag). The forester prover is a separate, explicit
# target (see below) -- one light-prover binary, two images by baked key set.
#
# NOTE: the target name `photon-build` matches the compose service that carries
# photon's build block (the `photon`/`photon-migration` run services are
# image-only and PULL this published image). Bake inherits build config from the
# compose service of the same name, so the publish target must use that name.
group "default" {
  targets = ["photon-build", "prover"]
}

target "photon-build" {
  platforms = split(",", PLATFORMS)
  tags = ["${REGISTRY}/zolana-photon:${TAG}"]
}

# SPP prover: bakes the client transfer + merge keys (~0.5G). This is the
# client-facing prover (and the TEE candidate if hosted proving is ever added).
target "prover" {
  platforms = split(",", PLATFORMS)
  args = { KEY_PROFILE = "spp" }
  tags = ["${REGISTRY}/zolana-prover:${TAG}"]
}

# Forester prover: same binary, but bakes the batch/inclusion tree-maintenance
# keys (GB-scale) instead of the transfer keys -- internal infra that never sees
# client witnesses. NOT in the default group: build it only once the forester
# runs, and only after its keys are staged in prover/server/proving-keys/.
#
# The SPP nullifier forester only needs the batched address-append keys
# (batch_address-append_*.key on the transfer-keys-v9 release). Stage them before
# building (from the repo root):
#   cd prover/server && \
#     gh release download transfer-keys-v9 --repo helius-labs/zolana \
#       --pattern 'batch_address-append_*.key' --pattern CHECKSUM \
#       --dir proving-keys --clobber
# The KEY_PROFILE=forester glob (batch_*.key / *inclusion* / comb_*) then copies
# whatever batch keys are staged into the image.
#   docker buildx bake -f docker/docker-compose.yml -f docker/docker-bake.hcl prover-forester --push
target "prover-forester" {
  inherits = ["prover"]
  args = { KEY_PROFILE = "forester" }
  tags = ["${REGISTRY}/zolana-prover-forester:${TAG}"]
}

# Forester binary (Rust). Built from forester/Dockerfile with the whole zolana
# workspace as context (the crate depends on workspace crates), mirroring how the
# photon build supplies the workspace. NOT in the default group -- the continuous
# worker isn't built yet; the image ships the read-only `info` command for now.
target "forester" {
  context = ".."
  dockerfile = "forester/Dockerfile"
  platforms = split(",", PLATFORMS)
  tags = ["${REGISTRY}/zolana-forester:${TAG}"]
}
