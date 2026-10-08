# Proof backend

A build with the `aeglos` tag proves on the GPU engine by default. A build with
the `aeglos_cpu` tag proves on the Aeglos CPU engine by default. Other builds
prove with Gnark on CPU. `PROVER_BACKEND` set to `gnark`, `aeglos` or
`aeglos-cpu` overrides the default, and startup logs the selected backend.
The two tags exclude each other, and a build with both fails to compile.
The `start` and `prove` commands reject an unknown backend or an unavailable GPU.
Transfers, P256 transfers, merges, custom rings, and forester proofs use the same
backend boundary.

The GPU build requires CUDA 12.8 and Linux x86-64. The private
[Aeglos repository](https://github.com/helius-labs/aeglos) contains the GPU engine.
[aeglos-source.lock](aeglos-source.lock) pins a Git archive by its full revision
and SHA256 digest. `Dockerfile.aeglos` verifies the archive from the
`aeglos_source` named build context before it extracts or compiles source.
A Go workspace contains the prover and the extracted module. The CPU module
has no Aeglos dependency.

Run from the Zolana repository with Git access to Aeglos.

```sh
tools/gpu/fetch-aeglos.sh target/aeglos-source
docker buildx build --platform linux/amd64 \
  --build-context aeglos_source=target/aeglos-source \
  --build-context repository=. \
  --build-arg CUDA_ARCH=sm_89 \
  --file prover/server/Dockerfile.aeglos \
  --tag zolana-prover:aeglos --load prover/server
```

`CUDA_ARCH` is required and must match the deployment GPU, `sm_89` for L4 or
L40S and `sm_120` for RTX 5090. The `repository` context supplies the root
license and third-party notices. Run the image with GPU access
and mount the existing proving keys at `/proving-keys`. UID 65532 must be able
to write that directory, because the default command downloads missing keys on
first use. The CPU Dockerfile remains independent of CUDA.
The [deployment guide](../../../../tools/gpu/README.md) also covers native builds
and colocated Photon deployments on Vast and EC2.

`AEGLOS_MEMORY_LIMIT_BYTES` sets the explicit device allocation budget. An omitted
value uses the engine default. Idle prepared keys are evicted when admission
needs more memory. GPU calls are serialized inside one process. Queue workers
can admit concurrent requests and wait for the GPU. Shutdown drains those
workers before closing the backend.

The `aeglos-cpu` backend needs no GPU, so a TEE prover on it attests no GPU
evidence. `build-aeglos.sh` builds it when it gets `cpu` in place of the CUDA
architecture.
`AEGLOS_CPU_THREADS` sets the engine workers, and unset takes every logical CPU.
`AEGLOS_CPU_FAMILY` pins the arithmetic to `scalar`, `avx512f`, `ifma256` or
`ifma512`, and startup fails on a host without it. Unset or `auto` follows
CPUID. `AEGLOS_MEMORY_LIMIT_BYTES` caps the native allocations of the CPU engine
too, and unset takes 90% of physical memory.

The existing metrics endpoint exposes backend stage durations, cache hits and
misses, cached key count, allocated device bytes, and errors. Stage durations
overlap. Total duration covers backend admission and proof execution. It excludes
HTTP handling and queue delay. Use admission for GPU contention and preparation
with cache misses to identify key churn.

`aeglos-source.lock` pins the GPU build and `aeglos-cpu-source.lock` pins the CPU
build, so one image moves without the other. To pin a new Aeglos commit, archive
it from a checkout and write its digest into the lock of that build:

```sh
lock=prover/server/prover/backend/aeglos-cpu-source.lock
rev=$(git -C ../aeglos rev-parse "COMMIT^{commit}")
mkdir -p target/aeglos-source
git -C ../aeglos archive --format=tar --output="$PWD/target/aeglos-source/aeglos-$rev.tar" "$rev"
(cd target/aeglos-source && shasum -a 256 "aeglos-$rev.tar") > "$lock"
```

`tools/gpu/fetch-aeglos.sh target/aeglos-source cpu` then fetches the same
archive from GitHub and checks it against the CPU lock, and without `cpu` against
the GPU lock. For a build from a local checkout that no lock pins,
`AEGLOS_UNPINNED=1` makes `build-aeglos.sh` take an extracted source tree and
skip the digest check. A release build must not set it.

The fixture export tests check circuit constraints and write two distinct
synthetic witnesses for each shape in `prover/provingkeys/proving-keys.lock`.
Set `AEGLOS_FIXTURES` to a private output
directory and run `TestExportAeglos` in the transfer, merge, forester, and custom
ring test packages. The Aeglos qualification runner checks each key digest,
generates proofs, and verifies them with standard Gnark.
