# Local latency tuning results

The changed server measured 203.8–215.0 ms P50 with one client and an emulated 70 ms RTT. The baseline recheck measured 213.4–222.2 ms. These runs do not establish a reliable improvement beyond host variation, and none met a 100 ms total latency target. Release defaults remain `GOAMD64=v1`, PGO off and the existing runtime defaults.

## Comparison

All runs used two workers, prover-side indexer fetching, 200 attempts per row and three repetitions at each client count. Values below are ranges of the three per-run statistics, not pooled percentiles. Each client sends its next request after receiving the previous response.

| Series | Clients | P50 ms | P95 ms | Proofs/sec |
| --- | ---: | ---: | ---: | ---: |
| Initial baseline | 1 | 240.5–307.0 | 268.8–370.4 | 3.19–4.12 |
| Initial baseline | 4 | 626.5–883.5 | 806.9–1075.5 | 4.41–6.12 |
| Initial baseline | 8 | 1265.3–1496.6 | 1382.4–1664.2 | 5.27–6.24 |
| Changed server | 1 | 203.8–215.0 | 211.2–234.9 | 4.63–4.90 |
| Changed server | 4 | 392.5–618.7 | 454.5–713.2 | 6.38–9.99 |
| Changed server | 8 | 823.2–1237.7 | 900.7–1335.5 | 6.40–9.57 |
| Baseline recheck | 1 | 213.4–222.2 | 226.0–238.8 | 4.49–4.68 |
| Baseline recheck | 4 | 529.3–585.6 | 604.9–673.8 | 6.71–7.48 |
| Baseline recheck | 8 | 1061.1–1181.8 | 1150.9–1333.9 | 6.65–7.45 |

All 5,400 measured requests returned HTTP 200 and passed cryptographic verification. Warmup proofs are excluded. Series ran in the order shown. The baseline uses the server before `9c04d4127`; the recheck archives `6a7ce39e1`. The changed server includes `9c04d4127`, which removes request-time memory sampling and records admission wait.

The initial baseline ran during changing background compilation and desktop activity. The changed server also varied substantially at four and eight clients. Repeating the old code produced results much closer to the changed server. The apparent gain against the first baseline must not be attributed to the patch. The cleanup removes avoidable memory sampling and misleading per-proof heap attribution, but a stable latency or throughput gain needs an isolated comparison.

Raw samples and calibration values are preserved in [initial baseline](baseline.json), [changed server](after.json) and [baseline recheck](baseline-repeat.json). Build settings were added to the harness metadata after the initial baseline, so that file lacks the field.

## Measurement scope

The machine is an Apple M4 Max with 16 logical CPUs and 128 GiB RAM. These runs used Go 1.27.1 on Darwin arm64, `GOMAXPROCS=16` and default GC settings. They ran in an optimized Go test process, without profiling. Existing validator and desktop processes remained active. These are local development measurements, not native x86 EC2 measurements.

The harness proves confidential transfers with two real inputs and three outputs, using the pinned proving key and production HTTP handler. A local fixture supplies valid indexer paths. The delay proxy adds 35 ms in each direction; health-request calibration ranged from 71.1 to 74.8 ms. Prover-to-indexer traffic has no added delay.

Latency includes HTTP handling, indexer resolution, admission wait and proof generation, ending after the response arrives. It excludes initial request encoding, key loading and proof verification. Batch throughput includes request encoding and proof decoding. Every response is verified after the timed batch. This does not measure SDK transaction construction, a live indexer database, TLS setup, chain submission or settlement. Process CPU usage includes the harness and fixture server; peak RSS is cumulative over the process.

## Benefit order and deployment status

1. Enable the existing SDK prover-fetch option and keep the indexer close to the prover. The [earlier 70 ms experiment](../network-70ms/README.md) saved about 68 ms by removing the client indexer round trip. That benefit was already present before this cleanup. SDK defaults remain unchanged, and no application deployment was performed here.
2. Reduce client-to-prover RTT through placement and reuse HTTP clients. Every reduction in that round trip reduces the network portion of a warm synchronous request. No routing or infrastructure change was deployed.
3. Measure worker count and CPU allocation on the actual EC2 host. More workers alone did not scale throughput proportionally in the earlier local matrix. The new harness supports controlled repetitions and exposes queue waiting separately through metrics.
4. Compare `GOAMD64=v3`, representative PGO and GC settings natively on the fleet. Their performance benefit is unmeasured. Both image publishing paths now read committed release settings, and compose exposes runtime tuning without promoting speculative defaults.

The available AWS credentials did not identify a running fleet in the configured regions and use a different account from the deployment registry. Native EC2 measurements and deployment remain pending the correct profile or role and region. No infrastructure was provisioned.

## Validation

Focused Go server, build-check and indexed prover tests passed. TypeScript client/indexed-proof tests passed all 45 cases; Rust prover-client tests passed all 19 cases. A separate profiled smoke run verified 56 proofs across direct, client-fetch and prover-fetch paths with 0, 20 and 70 ms delays. Its timings are excluded from this report.

Linux amd64 release builds passed for v1, v3 and v3 with PGO. The PGO build used a local smoke profile only to check the build path. Emulated v1/v3 startup checks passed. These checks establish build compatibility, not native EC2 speed or fleet CPU compatibility. Workflow lint, shell checks and compose validation passed.

Use the focused command and acceptance criteria in [the tuning guide](../TUNING.md) to repeat the comparison on the target machine. Keep profiling separate from acceptance runs and retain portable defaults until gains exceed run variation.
