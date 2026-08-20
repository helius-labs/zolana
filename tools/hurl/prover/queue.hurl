# The prover's queue surface: depth, health, maintenance, and explicit enqueue.
#
#   hurl --test --file-root tools/hurl \
#     --variables-file tools/hurl/localnet.env \
#     --variable witness=fixtures/transfer-2x2.json \
#     tools/hurl/prover/queue.hurl
#
# Needs a prover started with --redis-url; without it none of these paths is
# registered and the Go mux answers a plain 404. Only the last entry needs
# `witness`.
#
# Two Redis instances exist in a full stack (docker-compose in ../zolnet): the
# client prover's, and the forester prover's on its own port, so the two never
# race for the same jobs. Point `prover_url` at whichever you mean to inspect.

# Depth per queue. `zk_transfer_queue` carries the transfer and merge shapes;
# `zk_address_append_queue` carries the forester's batch appends, which must go
# async because one batch outlives any sane request timeout.
GET {{prover_url}}/queue/stats
HTTP 200
[Asserts]
jsonpath "$.queues.zk_transfer_queue" isInteger
jsonpath "$.queues.zk_transfer_processing_queue" isInteger
jsonpath "$.queues.zk_address_append_queue" isInteger
jsonpath "$.queues.zk_address_append_processing_queue" isInteger
jsonpath "$.queues.zk_failed_queue" isInteger
jsonpath "$.queues.zk_results_queue" isInteger
jsonpath "$.totalPending" isInteger
jsonpath "$.totalActive" isInteger
jsonpath "$.totalFailed" isInteger
jsonpath "$.timestamp" isInteger

# The same counts plus a verdict. `degraded` means at least one job has sat in a
# processing queue for over two minutes; `unhealthy` means more than 50 failures
# are banked up. Neither is asserted away here -- a run that reports either is
# telling you something.
GET {{prover_url}}/queue/health
HTTP 200
[Asserts]
jsonpath "$.status" == "healthy"
jsonpath "$.queueLengths.zk_transfer_queue" isInteger
jsonpath "$.totalPending" isInteger
jsonpath "$.totalProcessing" isInteger
jsonpath "$.totalFailed" isInteger
jsonpath "$.totalResults" isInteger
jsonpath "$.stuckJobs" isInteger
jsonpath "$.timestamp" isInteger

# Maintenance: expire old requests, requeue or drop stuck processing jobs, and
# trim old failures and result keys. Idempotent, so it is safe to run against a
# live prover.
POST {{prover_url}}/queue/cleanup
HTTP 200
[Asserts]
jsonpath "$.oldRequestsCleanup.success" == true
jsonpath "$.stuckJobsCleanup.success" == true
jsonpath "$.oldFailedCleanup.success" == true
jsonpath "$.oldResultKeysCleanup.success" == true
jsonpath "$.timestamp" isInteger

GET {{prover_url}}/queue/cleanup
HTTP 405
[Asserts]
body == ""

# Enqueue without asking for the proof in the response. Same deduplication as
# /prove with X-Async -- an identical witness already in flight returns that
# job's id with `deduplicated: true` -- and the queue is chosen from the circuit
# type, not from the caller.
#
# This does real work: a worker proves the job and stores the result under a TTL,
# whether or not anyone polls /prove/status for it.
POST {{prover_url}}/queue/add
Content-Type: application/json
file,{{witness}};
HTTP 202
[Asserts]
jsonpath "$.jobId" matches /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
jsonpath "$.status" matches /^(queued|already_queued)$/
jsonpath "$.queue" matches /^zk_(transfer|address_append)_queue$/
jsonpath "$.circuitType" isString
