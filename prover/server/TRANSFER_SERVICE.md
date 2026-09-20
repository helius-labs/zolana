# Transfer service

Transfers and merges return their proofs in the HTTP response by default.
Forester and custom proofs use the queue when Redis is configured.
`X-Async: true` selects queued delivery, including after a synchronous request
receives `429`. Queue fallback requires Redis.

`PROVER_TRANSFER_CONCURRENCY` bounds direct and queued transfers together
within one process. Its default is one. If unset, the service accepts the
legacy `PROVER_SYNC_CONCURRENCY` setting, then `TRANSFER_WORKER_CONCURRENCY`.
Forester memory settings do not determine transfer capacity.

Waiting HTTP requests are bounded at four times the transfer capacity.
A disconnected request retains its execution slot until proving stops.
Increase capacity only after measuring throughput and latency together.
Each additional service process has its own capacity limit.

## Indexer data

Set `PROVER_INDEXER_URL` to enable `POST /prove/indexed`. The service sends
JSON-RPC requests to that configured URL only. `PROVER_INDEXER_API_KEY` sets
its `api-key` query parameter. `PROVER_INDEXER_CONCURRENCY` bounds preparation requests.
Both delivery paths resolve proofs before acquiring a transfer execution slot.

Select `proofDataSource: "prover"` in the TypeScript client, or
`with_proof_data_source(ProofDataSource::Prover)` in Rust. Reuse the client
between requests. Keep the prover and indexer in the same availability zone
and use the private indexer endpoint to avoid another remote round trip.

The request contains `circuitType`, `prepared`, `trees`, `inputs`,
`publicInputs`, and optional `minContextSlot`. `prepared` uses the selected
circuit's JSON fields with paths, tree slots, and public input hash omitted.
Each tree has its base58 address and raw `id`. Each input has its `treeSlot`
and base58 `commitment`, or `null` for a dummy. `publicInputs` contains the
public transcript fields in circuit order, with the tree slot commitment
omitted. Fields use hex encoding. The resolver inserts that commitment at
position two before hashing the transcript.

State and nullifier requests run concurrently. Real and dummy nullifiers
share one request per tree. The resolver checks leaf, path, root, tree, and
root history position before proving. `minContextSlot` rejects older indexer
responses. Each input tree must contain a real spend.

The returned proof includes `resolution` with the resolved trees, their roots
and history positions, and `publicInputHash`. The caller must bind those trees
to its request and recompute that hash from its intended public transcript
before it builds the transaction. Queued delivery preserves the same fields.
Only concurrent requests share an indexed job. New requests do not reuse a
completed indexed proof because its roots can have expired.

## Release and readiness

Build with `sh build-release.sh`. The release script rejects `GOFLAGS` and
uses Go compiler optimization and cryptographic assembly. The Just binary
recipes and release xtask use the same script. Docker invokes
that script and enables `--require-optimized-build`, which rejects debug
compiler flags, race instrumentation, and `purego` or `noasm` builds.
`GOAMD64=v1` is portable. Select `v3` only for a fleet that supports it.
`PROVER_PGO` can name a representative Go CPU profile at build time.
Published images take these settings from `release-build.env`. Commit a
selected profile and its metadata with the settings change. Local build
and compose overrides are available for experiments. Follow the
[latency experiment guide](benchmarks/TUNING.md) before selecting defaults.

Use `/health` for liveness and `/ready` for load balancer readiness.
`/ready` returns `503` until configured preloads succeed. Proof requests
also return `503` during preload. With `--preload-keys none`, keys load
on demand and readiness does not guarantee a warm proof unless explicit
preload circuits are set. `--preload-circuits transfer-confidential:2:3`
selects one shape. A circuit name without a shape loads its supported shapes.
`rpc` and `local-rpc` preload all transfer and merge shapes. The compose default preloads selected transfer 2×3 shapes and merge 8×1.
Provision memory for the selected keys and workers. Mount the required
proving keys at `/proving-keys`. `Dockerfile.light` contains the binary only.

## Capacity and monitoring

`compose.transfer.yml` builds the current source with two shared transfer
workers, Redis fallback, and a local Prometheus. Start it with
`docker compose -f compose.transfer.yml up --build`. The indexer setting
remains optional. Restrict access and set `PROVER_API_KEY` before exposing
the prover outside the local machine.

Scrape `/metrics` on the metrics port. Transfer capacity and active permits
cover direct and queued execution together. Completion counters cover both
delivery modes. HTTP duration includes indexer preparation and admission.
A queued `202` measures acceptance only. Use queue delay and generation
duration to assess queued work. Network RTT and client polling need client
measurements.

`prover_sync_admission_wait_seconds` separates permit waiting by `admitted`
and `rejected` outcome. `prover_system_memory_bytes` is sampled during each
metrics scrape. The per-proof `prover_proof_memory_usage_bytes` and
`prover_proof_peak_memory_bytes` metrics are removed. Concurrent allocations
cannot be attributed to one proof. Use process memory gauges for capacity.

Load `monitoring/alerts.yml` into Prometheus. Set the throughput target and
latency thresholds to the deployment SLO. The example throughput target is
for the whole `prover` job. Queue depth is shared across replicas, so the
rules use the maximum depth rather than adding duplicate observations.
The throughput alert requires backlog and does not fire for idle service.
Configure an Alertmanager and notification receiver in your deployment to
send alerts. The compose profile exposes firing alerts in Prometheus.
Import `monitoring/dashboard.json` into Grafana and select the Prometheus
data source. Validate rules with `promtool check rules monitoring/alerts.yml`
and `promtool test rules monitoring/alerts.test.yml`.

On saturation, compare completion rate, queue depth, request latency, and
process memory. Increase `PROVER_TRANSFER_CONCURRENCY` one step and repeat
the load test. Add replicas when concurrency raises latency without enough
throughput gain. Gnark can use several CPU cores per proof, so worker count
must not be set equal to CPU count without measurement.
