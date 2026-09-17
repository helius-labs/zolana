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
