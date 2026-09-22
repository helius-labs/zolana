# Frankfurt proof latency

Measured on 22 September 2026 from the local client through CloudFront POP
`IST50-P4`. The Frankfurt prover and Photon share a `g7e.2xlarge` with one
RTX PRO 6000 Blackwell GPU. PostgreSQL runs on a separate Frankfurt
`db.m7g.xlarge`. The baseline is the unchanged devnet-c deployment in Stockholm.

## Proof receipt

Each value is the second sample for that shape and deployment. The run made
20 comparison proofs. All passed standard Gnark verification against the pinned
keys and the expected public input. Two earlier smoke requests are excluded.
No transactions were submitted and no load test was run.

| Proof | devnet-c ms | Frankfurt ms | Saved ms | Reduction |
|---|---:|---:|---:|---:|
| Transfer 1×2 | 436.0 | 137.3 | 298.6 | 68.5% |
| Transfer 2×3 | 458.0 | 157.3 | 300.7 | 65.6% |
| Ring transfer 2×3 | 455.9 | 160.4 | 295.4 | 64.8% |
| Merge 8×1 | 858.3 | 175.1 | 683.2 | 79.6% |
| Merge 36×1 | 2733.1 | 256.6 | 2476.5 | 90.6% |

Receipt time starts before SDK proof preparation and ends when the proof response
arrives. `sdk_ready_ms` also includes the SDK response checks. Wallet discovery,
ring configuration reads and independent local verification are outside receipt
time. Their exclusion is recorded in [the measurements](measurements.json).

The widest merge uses two real notes and 34 dummy inputs. Its proof has the full
36×1 circuit cost. It does not measure 36 real indexer lookups. A private SDK
fixture copy selects that shape. The product SDK remains unchanged.

## Frankfurt stages

All values below are milliseconds. The columns sum to proof receipt time.
Transport and edge time is HTTP duration minus the measured server duration.
It includes the network, gateway and response transfer. It is not an ICMP RTT.

| Proof | SDK work | Transport and edge | Indexer fetch | Witness and proof | Other server work |
|---|---:|---:|---:|---:|---:|
| Transfer 1×2 | 22.20 | 78.66 | 6.08 | 28.58 | 1.82 |
| Transfer 2×3 | 28.89 | 87.15 | 8.25 | 29.87 | 3.18 |
| Ring transfer 2×3 | 35.03 | 85.69 | 6.87 | 29.67 | 3.17 |
| Merge 8×1 | 27.11 | 95.31 | 8.76 | 36.91 | 7.04 |
| Merge 36×1 | 86.43 | 79.69 | 14.21 | 52.35 | 23.93 |

Indexer Merkle and non-inclusion requests overlap. Their fetch wall time is
shown once. Other server work includes path validation, parameter decoding,
input encoding and response encoding. GPU admission was below 0.001 ms in these
warm samples. Prepared keys remained cached.

| Proof | CPU witness | CPU proof after witness | GPU witness | GPU FFT | GPU MSM | GPU total |
|---|---:|---:|---:|---:|---:|---:|
| Transfer 1×2 | 18.47 | 86.65 | 15.24 | 0.15 | 12.18 | 28.58 |
| Transfer 2×3 | 31.83 | 139.30 | 15.57 | 0.22 | 13.11 | 29.87 |
| Ring transfer 2×3 | 32.06 | 148.52 | 15.56 | 0.22 | 12.96 | 29.67 |
| Merge 8×1 | 99.67 | 447.21 | 18.03 | 0.89 | 16.85 | 36.91 |
| Merge 36×1 | 445.97 | 1596.31 | 17.40 | 2.83 | 30.27 | 52.35 |

Gnark logs its solver and subsequent prover stages separately. CPU total is their
sum. Aeglos total already includes witness solving. GPU total also contains
small dispatch and proof assembly costs beyond the three displayed stages.

The baseline has no request trace header. Its CPU stages are inferred from
unique log events with matching constraint counts within 500 ms of each HTTP
interval. That window allows for observed clock skew. The raw event times are
included. Candidate stages use request trace headers and backend metric deltas
with exactly one proof between each pair of scrapes.

## Network

The short network check made one connection sample and five warm requests per
deployment. Every response was confirmed as a CloudFront cache miss. These are
HTTP application round trips through the deployed route.

- Baseline median 175.9 ms, range 101.7–247.9 ms.
- Candidate median 70.7 ms, range 65.8–92.1 ms.

The TCP connection samples to the CloudFront edge were about 28–30 ms. Edge
connection time excludes the trip to Frankfurt or Stockholm. No RTT was
simulated. These samples do not establish p95 latency or latency from Portugal.

The 1×2 transfer takes 36.48 ms inside the Frankfurt server and 137.34 ms to
receipt. The complete path does not reach 100 ms from this client. The 36×1 merge
also spends 19.98 ms validating indexer paths and 86.43 ms in client work.

## Deployment and cache

The source build is `e6470a295de7d3bedcf3f3a80ceee8a295a3e760`. The Aeglos source
archive is pinned to `63450b2fcde9f2949b794e276889798b06dcbfed`. CUDA uses `-O3`
and `sm_120`. Go uses `GOAMD64=v3` with compiler optimization and cryptographic
assembly enabled. The image starts with `--require-optimized-build`.

Photon uses the same immutable image as devnet-c. Its persistent state was
copied into a separate database. A bounded PostgreSQL export refreshed the
initial backup copy. The export used one read-only connection with a short
lock timeout. Only the new Photon container stopped for restore. The source
services kept their task revisions, desired counts and running counts. Their
health checks passed after the copy and proof run.

The prover calls Photon on localhost. The authenticated HTTPS endpoint reaches
the instance through a CloudFront VPC origin. The instance accepts gateway
traffic only from the CloudFront service security group. API response caching
is disabled. API keys and database credentials are not committed.

The GPU host costs $5.71915 per hour and RDS costs $0.401 per hour at the checked
on-demand rates. Storage and traffic are additional. L40S instances were
unavailable in the checked Frankfurt zones.

The comparison includes hardware, region, indexer placement and request-path
changes. It does not isolate each contribution. P256, authority, ring-merge,
custom-ring and forester paths were not covered by these live fixtures.
Use the [backend guide](../../prover/backend/README.md) for the optional GPU build.

## L4 comparison

The L4 test used a separate Frankfurt `g6.2xlarge` with the same source revisions,
Photon image and database clone. CUDA targeted `sm_89`. The host has 8 vCPUs,
32 GiB RAM and one L4 GPU. The prover retained six CPU threads and four request
admission slots. Its memory limit was 16 GiB. Photon reported healthy before
the proof run.

Six proofs passed standard Gnark verification. Each shape ran twice. The table
uses the second sample with prepared GPU keys cached. Wallet discovery and
independent verification remain outside receipt time.

| Proof | Blackwell receipt ms | L4 receipt ms | Increase | Blackwell witness and proof ms | L4 witness and proof ms |
|---|---:|---:|---:|---:|---:|
| Transfer 1×2 | 137.3 | 151.6 | 10.4% | 28.58 | 38.42 |
| Transfer 2×3 | 157.3 | 185.9 | 18.2% | 29.87 | 43.27 |
| Merge 36×1 | 256.6 | 443.8 | 72.9% | 52.35 | 196.38 |

| L4 proof | Indexer fetch ms | Witness ms | FFT ms | MSM ms | Full server ms |
|---|---:|---:|---:|---:|---:|
| Transfer 1×2 | 5.89 | 15.47 | 0.29 | 21.51 | 47.22 |
| Transfer 2×3 | 8.00 | 16.35 | 0.52 | 24.81 | 55.74 |
| Merge 36×1 | 15.84 | 19.87 | 11.29 | 159.96 | 246.67 |

The wide merge still uses two real notes and 34 dummy inputs. Its MSM time rose
from 30.27 ms to 159.96 ms. Transfer witness time changed by less than 1 ms.
The idle L4 HTTP round trip had a 89.2 ms warm median, with a
75.2–192.4 ms range. The runs occurred at different times, so receipt
differences include network and client variation. These samples do not establish
sustained TPS or p95 latency.

At the checked on-demand rate, the L4 host costs $892.42 for 730 hours. The same
database brings the total to $1,185.15 before storage and traffic. Host cost is
78.6% lower than Blackwell. See [the L4 measurements](l4-measurements.json) for
all samples, request stages and verification results.

## L4 merge tuning

The experimental build keeps shifted G2 bases in GPU memory and limits registers
in the G2 accumulation kernel. It also uses 17 bit G1 windows. The release source
and devnet-c deployment remain unchanged. The L4 host stays running. Its test endpoint uses the prototype. The original
prover container remains available for rollback.

Four live proofs passed standard Gnark verification. Each merge shape ran twice
through the local Photon and prover. The table uses the second request, with
prepared keys cached. Values are milliseconds.

| Merge | Witness | FFT | MSM | Witness and proof | Indexer fetch | Full server | Client receipt |
|---|---:|---:|---:|---:|---:|---:|---:|
| 8×1 | 18.26 | 2.46 | 36.76 | 59.18 | 16.47 | 84.25 | 183.12 |
| 36×1 | 19.83 | 11.36 | 120.61 | 157.18 | 17.04 | 208.26 | 381.03 |

For 36×1, witness and proof fell from 196.38 ms to 157.18 ms, a 20.0% reduction.
Client receipt fell from 443.77 ms to 381.03 ms, a 14.1% reduction. Network and
client variation contribute to the receipt difference. There is no prior L4
8×1 sample. Its Blackwell reference is 36.91 ms for witness and proof and
175.1 ms to receipt.

The 8×1 server path is below 100 ms. The 36×1 proof remains above 100 ms.
Neither client receipt reaches that target. The wide merge still has two real
notes and 34 dummy inputs. Indexer path validation takes 27.96 ms for that shape,
in addition to the 17.04 ms fetch. Client work takes 84.82 ms and transport takes
87.94 ms.

The isolated 36×1 fixture improved from 210.55 ms to 166.05 ms. Each candidate
ran two proofs and rejected a changed public input. Those fixtures exclude the
indexer and network. Wider G2 windows and the existing cooperative G2 kernel
were slower. Their results remain in [the trial records](l4-hillclimb.json).

Nsight Compute measured 255 registers per thread and 16.62% occupancy in the
G2 accumulation kernel before the register limit. DRAM throughput was 12.72%.
The tested limit reduced register use to 168 per thread. Profiler timings are
excluded because profiling changed the GPU clock and replayed kernels.

Preparing the 36×1 GPU key took 2.92 seconds on first use, compared with
2.22 seconds before tuning. Warm requests exclude that cost. In the isolated
fixture, cached device allocations rose from 5.58 GiB to 6.71 GiB.

The prototype uses fixed precomputation and launch settings for these L4 tests.
It is not part of the release source. Its source archive hash, complete proof
records and stage measurements are in [the evidence](l4-hillclimb.json).
The samples do not establish sustained TPS or p95 latency.
