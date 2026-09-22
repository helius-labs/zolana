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
