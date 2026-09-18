# Proof requests with 70 ms RTT

Measured on an Apple M4 Max with 16 logical CPUs and 128 GiB RAM. The prover runs in a normal optimized Go test process with Go 1.25.6. Existing validator, indexer and desktop processes stayed running.

## Result

With two proof workers and one client, prover-side fetching saves about 68 ms per proof. That removes about 24% of request latency. More workers do not give proportional throughput on this CPU.

Ranges below show the two runs, with 32 attempts per row per run. Failures combine both runs.

| Flow | Workers | Clients | P50 ms | P95 ms | Proofs/sec | Rejected / 64 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Direct, no delay | 1 | 1 | 137.8–146.5 | 158.4–160.9 | 6.83–7.10 | 0 |
| Client fetch | 1 | 1 | 279.6–282.7 | 309.2–317.0 | 3.49–3.52 | 0 |
| Client fetch | 1 | 2 | 324.5–329.7 | 355.1–418.3 | 5.93–5.97 | 0 |
| Client fetch | 1 | 4 | 569.8–594.1 | 610.3–677.7 | 6.55–6.69 | 0 |
| Client fetch | 1 | 8 | 834.6–921.6 | 945.9–1067.8 | 5.97–6.59 | 34 |
| Prover fetch | 1 | 1 | 211.8–212.0 | 224.1–224.3 | 4.70–4.72 | 0 |
| Prover fetch | 1 | 2 | 278.1–302.7 | 331.3–331.7 | 6.55–7.03 | 0 |
| Prover fetch | 1 | 4 | 557.6–582.6 | 605.1–614.0 | 6.71–7.07 | 0 |
| Prover fetch | 1 | 8 | 676.1–925.7 | 815.6–965.8 | 5.60–6.87 | 43 |
| Direct, no delay | 2 | 1 | 139.7–144.8 | 151.2–154.3 | 6.99–7.21 | 0 |
| Client fetch | 2 | 1 | 278.0–282.2 | 289.0–302.0 | 3.53–3.59 | 0 |
| Client fetch | 2 | 2 | 326.6–337.6 | 370.2–399.6 | 5.78–6.09 | 0 |
| Client fetch | 2 | 4 | 490.5–526.5 | 526.4–606.5 | 7.40–8.00 | 0 |
| Client fetch | 2 | 8 | 952.1–1050.2 | 1154.3–1320.2 | 7.07–7.60 | 0 |
| Prover fetch | 2 | 1 | 210.6–214.4 | 217.5–224.4 | 4.67–4.77 | 0 |
| Prover fetch | 2 | 2 | 293.1–296.2 | 340.4–405.3 | 6.41–6.65 | 0 |
| Prover fetch | 2 | 4 | 484.8–541.4 | 525.9–611.6 | 7.28–8.18 | 0 |
| Prover fetch | 2 | 8 | 967.6–1059.5 | 1064.3–1118.4 | 7.33–7.96 | 0 |
| Direct, no delay | 4 | 1 | 143.6–164.9 | 156.6–178.7 | 6.14–6.86 | 0 |
| Client fetch | 4 | 1 | 278.2–283.1 | 288.5–307.5 | 3.49–3.58 | 0 |
| Client fetch | 4 | 2 | 309.4–372.9 | 359.5–416.4 | 5.28–6.29 | 0 |
| Client fetch | 4 | 4 | 501.7–582.6 | 574.0–734.8 | 6.50–7.85 | 0 |
| Client fetch | 4 | 8 | 952.4–1084.5 | 1294.7–1434.4 | 6.76–7.88 | 0 |
| Prover fetch | 4 | 1 | 205.7–221.2 | 224.4–228.8 | 4.53–4.81 | 0 |
| Prover fetch | 4 | 2 | 276.1–320.4 | 326.1–363.6 | 6.25–7.13 | 0 |
| Prover fetch | 4 | 4 | 481.0–614.2 | 589.1–678.6 | 6.61–8.11 | 0 |
| Prover fetch | 4 | 8 | 923.3–1071.2 | 1219.4–1288.2 | 7.08–8.40 | 0 |

Both runs passed. Across 1,728 measured attempts, 1,651 proofs passed verification and 77 attempts received HTTP 429. All rejections occurred with one worker and eight clients. Warmup proofs are excluded from these totals.

## Measurement

The harness starts the production HTTP server and transfer executor. It proves confidential transfers with two real inputs and three real outputs using the pinned Gnark proving key. Each successful response is verified against the expected public witness after the timed batch.

A local HTTP fixture serves valid state inclusion and nullifier noninclusion paths. The client-fetch flow requests both paths in parallel, then calls `/prove`. The prover-fetch flow calls `/prove/indexed`, and the prover requests both paths from the local fixture.

Each remote HTTP request passes through a proxy with 35 ms delay before forwarding and 35 ms before the response returns. The nominal RTT is 70 ms. Health request calibration measures the actual delay, including loopback and timer overhead. Prover-to-indexer traffic has no added delay. The saved RTT depends on that placement.

Latency starts before the optional client indexer fetch and ends after the full proof response arrives. It includes HTTP handling, resolver work, admission wait and proof generation. It excludes transaction construction, initial request encoding, key loading and proof verification. Batch throughput includes request encoding and proof decoding, but excludes verification. The direct baseline sends complete proof inputs without the delay proxy.

Each row has 32 attempts from clients that send their next request after the previous response. Three concurrent warmup rounds precede each row. Each attempt has distinct input commitments within the row. The same statements are reused across rows. The two complete runs use fresh test processes.

Percentiles cover successful requests only. P50 is the upper middle sorted sample. P95 uses nearest rank. Throughput is successful verified proofs divided by the full batch duration. Rejected attempts count toward the batch duration and failure count. A row with rejections does not represent completion of all submitted transfers.

The synchronous admission limit is four waiting callers per worker. Redis and SDK retries are disabled in the harness. HTTP 429 responses measure admission rejection. Other HTTP errors fail the test.

## Scope

These are short proof-service measurements. The harness uses the production Go resolver to model client fetching. It does not run the TypeScript or Rust SDK, read a live indexer database, submit transactions or measure settlement. It does not test cold starts, persistent queue fallback, packet loss, bandwidth limits, TLS setup or alert delivery. The proxy adds HTTP delay rather than changing the machine's network settings.

The results support two proof workers as a starting point on this machine. They do not establish a production capacity limit. More sustained traffic, live indexer work and proof shapes can change throughput. More workers alone did not remove the capacity limit in these runs.

## Reproduce

From the worktree root, use a separate key cache. The key manager downloads and verifies the pinned key when the cache is empty.

```sh
mkdir -p target/network-benchmark/keys
PROVER_NETWORK_BENCH=1 \
PROVER_BENCH_KEYS="$PWD/target/network-benchmark/keys" \
PROVER_BENCH_OUTPUT="$PWD/target/network-benchmark/results.json" \
go -C prover/server test ./prover-test/spp/prover/transaction \
  -run '^TestProofNetworkBenchmark$' -count=1 -v -timeout 15m
```

The [harness](../../prover-test/spp/prover/transaction/network_bench_test.go) saves each completed row. Raw samples are in [run 1](run-1.json) and [run 2](run-2.json). [Machine details and RTT samples](metadata.json) record the production revision and test environment.
