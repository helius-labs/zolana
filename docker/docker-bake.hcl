# PUBLISH path for the photon + prover images (the RUN path is
# docker-compose.yml). Build config (contexts, inline Dockerfiles, the `..` patch
# context) is read from docker-compose.yml; this file only sets platforms,
# registry tags, and photon's build context. Run from the repo root.
# See docker/README.md for the buildx setup + publish commands.

variable "REGISTRY" { default = "sergeytimoshin" }
variable "TAG" { default = "devnet" }
variable "PLATFORMS" { default = "linux/amd64" }

# Default = photon + the SPP (client-facing) prover. The target name
# `photon-build` matches the compose service carrying photon's build block: bake
# inherits build config from the compose service of the same name (the
# `photon`/`photon-migration` run services are image-only and carry no tag).
group "default" {
  targets = ["photon-build", "prover"]
}

target "photon-build" {
  platforms = split(",", PLATFORMS)
  tags = ["${REGISTRY}/zolana-photon:${TAG}"]
}

# SPP prover: bakes the client transfer + merge keys (~0.5G).
target "prover" {
  platforms = split(",", PLATFORMS)
  args = { KEY_PROFILE = "spp" }
  tags = ["${REGISTRY}/zolana-prover:${TAG}"]
}

# Forester prover: same binary, bakes the batch/inclusion tree-maintenance keys
# (GB-scale) instead of the transfer keys. NOT in the default group; stage its
# keys in prover/server/proving-keys/ before building (see README).
target "prover-forester" {
  inherits = ["prover"]
  args = { KEY_PROFILE = "forester" }
  tags = ["${REGISTRY}/zolana-prover-forester:${TAG}"]
}

# Forester binary (Rust). Built from forester/Dockerfile with the whole zolana
# workspace as context. NOT in the default group (the continuous worker isn't
# built yet).
target "forester" {
  context = ".."
  dockerfile = "forester/Dockerfile"
  platforms = split(",", PLATFORMS)
  tags = ["${REGISTRY}/zolana-forester:${TAG}"]
}
