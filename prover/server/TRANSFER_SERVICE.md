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
