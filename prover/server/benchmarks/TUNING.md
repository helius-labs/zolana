# Proof latency experiments

Run the network benchmark on the target CPU with the release Go toolchain. Use the same proving keys, CPU allocation and background workload for both sides of a comparison. The harness serves valid fixture paths and exercises the production HTTP handler. It does not measure a live indexer database or SDK execution.

From the repository root, select a focused comparison.

```sh
mkdir -p target/network-benchmark/keys
PROVER_NETWORK_BENCH=1 \
PROVER_BENCH_KEYS="$PWD/target/network-benchmark/keys" \
PROVER_BENCH_OUTPUT="$PWD/target/network-benchmark/results.json" \
PROVER_BENCH_MODES=prover_fetch \
PROVER_BENCH_WORKERS=2 \
PROVER_BENCH_CLIENTS=1,4,8 \
PROVER_BENCH_RTT_MS=70 \
PROVER_BENCH_REQUESTS=200 \
PROVER_BENCH_REPEATS=3 \
go -C prover/server test ./prover-test/spp/prover/transaction \
  -run '^TestProofNetworkBenchmark$' -count=1 -v -timeout 60m
```

`PROVER_BENCH_RTT_MS` accepts comma-separated RTTs, including zero. Half the delay is applied to each direction. `PROVER_BENCH_MODES` accepts `direct`, `client_fetch` and `prover_fetch`. Direct requests bypass the delay proxy and use only the first RTT entry. Workers and clients accept comma-separated positive counts. The defaults are 200 requests, three repetitions, workers 1/2/4, clients 1/4/8, all modes and 70 ms RTT. The full default matrix takes longer than a focused comparison.

Each row records the Go version, CPU count, scheduler parallelism, GC environment, calibrated RTT, process CPU seconds and process peak RSS. Peak RSS is cumulative over the test process. CPU and memory measurements include the in-process client and fixture server. Percentiles include successful requests only. Rejections remain in the raw samples and reduce completed throughput. Every returned proof is verified after the measured batch.

## Profiles and build variants

Set `PROVER_BENCH_PROFILE_DIR` to a directory to collect one CPU profile per measured row. Profiling starts after key loading, fixture checks and concurrent warmup. It stops before proof verification. Profiles include the in-process HTTP client and fixture server. Profiled timings are marked by `cpu_profile` in the output and must not be mixed with unprofiled acceptance runs.

Use a separate profile run and a separate measurement run. A profile from the confidential 2-input/3-output fixture covers that workload only. Validate other production circuits before selecting it for a shared prover image.

For local builds, pass `PROVER_PGO` to `build-release.sh`, or pass `-pgo=/absolute/profile.pprof` to `go test`. Docker accepts `GOAMD64` and `PROVER_PGO` build arguments. The profile must be inside the Docker build context. Run amd64 performance comparisons natively on x86 EC2. Emulated amd64 execution on a Mac is a build check only.

Published prover images read `prover/server/release-build.env` in both CI and the local publisher. Commit a winning profile, its workload and toolchain metadata, and the settings change together. That gives the selected build a new source revision and preserves immutable image tags. Keep `GOAMD64=v1` and PGO off until native measurements support a change. An x86 architecture level does not enable Gnark assembly, which is already selected by the dependency.

## Runtime comparisons

Start with workers 1, 2 and 4. Compare the best setting with the full and half CPU allocations. On Linux, apply `--cpuset-cpus` before starting the process. Gnark sizes internal work from `runtime.NumCPU()`, independently of `GOMAXPROCS`.

Then compare `GOGC=100`, `200` and `400`. Set `GOMEMLIMIT` to 80% of the prover container memory allowance and check actual RSS. The memory limit is soft and does not cap total process RSS. Keep GC enabled. The transfer compose profile accepts these environment settings without changing their defaults.

Use three repetitions with at least 200 attempts per row. Select a change only when its P95 or throughput gain exceeds run variation and reaches 5%, without more than 5% regression in the other measures, increased errors or insufficient memory headroom. Repeat the combined configuration under sustained load before deployment.

Prover-side fetching removes the client indexer round trip only when prover-to-indexer traffic is local. Configure the existing SDK options, keep both services in the same availability zone, and reuse HTTP clients. Keep public SDK defaults unchanged.
