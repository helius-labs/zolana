# Proof backend

Gnark on CPU is the default. Set `PROVER_BACKEND=aeglos` to select the GPU engine.
The `start` and `prove` commands reject an unknown backend or an unavailable GPU.
Transfers, P256 transfers, merges, custom rings, and forester proofs use the same
backend boundary.

The GPU build requires CUDA 12.8 and Linux x86-64. Aeglos is not published.
[aeglos-source.lock](aeglos-source.lock) pins a Git archive by its full revision
and SHA256 digest. `Dockerfile.aeglos` verifies the archive from the
`aeglos_source` named build context before it extracts or compiles source.
A Go workspace contains the prover and the extracted module. The CPU module
has no Aeglos dependency.

Run from the Aeglos release repository, with `prover_dir` set to the Zolana
prover directory. The source archive remains outside the Zolana tree.

```sh
prover_dir=/absolute/path/to/zolana/prover/server
archive_context=$(mktemp -d)
revision=63450b2fcde9f2949b794e276889798b06dcbfed
git archive --format=tar --output="$archive_context/aeglos-$revision.tar" "$revision"
docker buildx build --platform linux/amd64 \
  --build-context aeglos_source="$archive_context" \
  --build-arg CUDA_ARCH=sm_89 \
  --file "$prover_dir/Dockerfile.aeglos" \
  --tag zolana-prover:aeglos --load "$prover_dir"
rm -rf "$archive_context"
```

`CUDA_ARCH` defaults to `sm_89` for AWS L40S. Set it to `sm_120` for RTX 5090.
The architecture must match the deployment GPU. Run the image with GPU access
and mount the existing proving keys at `/proving-keys`. The mounted keys must
be readable by UID 65532. The CPU Dockerfile remains independent of CUDA.

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
