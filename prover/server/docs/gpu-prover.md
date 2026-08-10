# GPU prover

The prover server can prove Groth16 on a CUDA GPU. One package,
`prover/gpuprove`, owns backend selection. Every per-request prove call site
goes through `gpuprove.Prove`.

## Build

The default build compiles no CUDA code and behaves exactly like a
CPU-only prover. A GPU build needs two tags together, plus cgo and the
ICICLE libraries installed on the host.

    go build -tags "cuda icicle" .

`cuda` selects this repository's GPU files, `icicle` selects gnark's
accelerated backend. The ICICLE CUDA backend loaded at run time must be built
from the patched icicle-gnark checkout beside this repository. The upstream
backend has an MSM stream-ordering bug that crashes sustained proving of
commitment circuits.

## Selection

`PROVER_GPU=auto|on|off`, read once per process.

- `auto` (default). GPU when the build carries it and CUDA device 0 answers
  a probe. CPU otherwise. A failed backend load or a missing device
  downgrades to the CPU with a warning, it does not panic. Circuits below
  `PROVER_GPU_MIN_CONSTRAINTS` prove on the CPU even when a GPU is present.
  The default threshold is the measured gpu/cpu crossover, pinned by a test
  in `prover/gpuprove`, with the measurements in `BENCHMARKS.md`.
- `on`. GPU required. `Prove` returns an error when the build lacks the GPU
  or no device answers. The size threshold does not apply.
- `off`. CPU, also in a GPU build.

| PROVER_GPU | default build | cuda build, no device | cuda build, device |
|---|---|---|---|
| auto | cpu | cpu | gpu at or above the threshold, cpu below |
| on | error | error | gpu |
| off | cpu | cpu | cpu |

The resolved backend is logged once on the first prove.

## Invariants

A maintainer must not break these.

- One prove in flight per device. The GPU path serializes whole icicle
  `Prove` calls through one worker goroutine for device 0. The ICICLE
  backend holds one NTT domain per device, and its `Prove` runs the CPU
  witness solve internally, so the solve rides inside the serialized
  section. This is also why small circuits lose on the GPU and why auto
  mode routes them to the CPU.
- The worker outlives a panic. `gpuJobs` is unbuffered and never closed, so
  a worker that stops leaves every later caller blocked forever. A panic in
  the device prover becomes a job error and the loop restarts the worker.
- Proving keys allocate through `gpuprove.NewProvingKey`. In a cuda build
  it returns the icicle wrapper type that carries device state, and gnark's
  icicle `Prove` type-asserts it. A key deserialized into the stock type
  panics inside gnark on its first GPU prove. The wrapper embeds the stock
  key, bytes on disk are identical, and the CPU fallback unwraps it. A key
  from an in-process `groth16.Setup` lacks the wrapper and proves on the
  CPU with a warning.
- Fresh blinding per proof. The icicle backend draws fresh randomness
  inside every `Prove` call, the same code path as the CPU prover. No
  proof, witness, or solution is cached or keyed on witness content.
- Proof output is `*groth16_bn254.Proof` on both backends, so the JSON
  shape (`proof_commitment` absent for eddsa, present for P256) is
  backend-independent. The load test pins this.

Key residency follows from the lazy key manager cache, device state
attaches to the cached key object. `PROVER_GPU_PIN_KEYS=1` additionally
keeps every loaded key's vectors resident in GPU memory. Off by default,
the full pinned key set can exceed device memory.

## Benchmarks and load test

`BenchmarkProveTransfer` (circuits/spp_transaction/shared) and
`BenchmarkProveMerge` (circuits/spp_merge) time the production prove path
per circuit type and shape against the pinned keys. `scripts/bench_gpu.sh`
runs both per backend and `scripts/bench_parse.py` renders the table.
Results go into `BENCHMARKS.md`, one dated section per run.

`TestProveLoadMixedShapes` (circuits/spp_transaction/shared) fires
concurrent mixed-shape proves through the production dispatch and verifies
every proof. Gated behind `PROVER_LOAD_TEST=1` because the pinned keys
download on first use. `PROVER_LOAD_SHAPES` picks the request mix and
`PROVER_LOAD_M` the concurrency sweep.

    PROVER_LOAD_TEST=1 go test -run TestProveLoadMixedShapes -v \
        ./circuits/spp_transaction/shared

Add `-tags "cuda icicle"` on a CUDA host to run the same load on the GPU.
