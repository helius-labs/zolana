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

Use `/health` for liveness and `/ready` for load balancer readiness.
`/ready` returns `503` until configured preloads succeed. Proof requests
also return `503` during preload. With `--preload-keys none`, keys load
on demand and readiness does not guarantee a warm proof unless explicit
preload circuits are set. `--preload-circuits transfer-confidential:2:3`
selects one shape. A circuit name without a shape loads its supported shapes.
`rpc` and `local-rpc` preload all transfer and merge shapes. The compose default preloads selected transfer 2×3 shapes and merge 8×1.
Provision memory for the selected keys and workers. Mount the required
proving keys at `/proving-keys`. `Dockerfile.light` contains the binary only.
