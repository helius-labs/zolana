# Proof backend

Gnark on CPU is the default. Set `PROVER_BACKEND=aeglos` to select the GPU engine.
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
  --build-arg CUDA_ARCH=sm_89 \
  --file prover/server/Dockerfile.aeglos \
  --tag zolana-prover:aeglos --load prover/server
```

`CUDA_ARCH` defaults to `sm_89` for AWS L40S. Set it to `sm_120` for RTX 5090.
The architecture must match the deployment GPU. Run the image with GPU access
and mount the existing proving keys at `/proving-keys`. The mounted keys must
be readable by UID 65532. The CPU Dockerfile remains independent of CUDA.
The [deployment guide](../../../../tools/gpu/README.md) also covers native builds
and colocated Photon deployments on Vast and EC2.

`AEGLOS_MEMORY_LIMIT_BYTES` sets the explicit device allocation budget. An omitted
value uses the engine default. Idle prepared keys are evicted when admission
needs more memory. GPU calls are serialized inside one process. Queue workers
can admit concurrent requests and wait for the GPU. Shutdown drains those
workers before closing the backend.

The existing metrics endpoint exposes backend stage durations, cache hits and
misses, cached key count, allocated device bytes, and errors. Stage durations
overlap. Total duration covers backend admission and proof execution. It excludes
HTTP handling and queue delay. Use admission for GPU contention and preparation
with cache misses to identify key churn.

The fixture export tests check circuit constraints and write two distinct
synthetic witnesses for each shape in `prover/provingkeys/proving-keys.lock`.
Set `AEGLOS_FIXTURES` to a private output
directory and run `TestExportAeglos` in the transfer, merge, forester, and custom
ring test packages. The Aeglos qualification runner checks each key digest,
generates proofs, and verifies them with standard Gnark.
