# The queued rail: submit, poll, and the status endpoint's rejection contract.
#
#   hurl --test --file-root tools/hurl \
#     --variables-file tools/hurl/localnet.env \
#     --variable witness=fixtures/transfer-2x2.json \
#     tools/hurl/prover/prove-async.hurl
#
# Needs a prover started with --redis-url. Without redis there is no queue, so
# /prove answers with the proof (200, not 202) and /prove/status is never
# registered -- a plain 404 from the Go mux, not a JSON error. Every entry here
# fails on such a prover; that is the configuration difference, not a bug.
#
# X-Async is honoured only for a circuit that has a queue (`useQueue` in
# prover/server/server/server.go). Anything else takes the sync path regardless.
# ?async=true is equivalent to the header.
POST {{prover_url}}/prove
Content-Type: application/json
X-Async: true
file,{{witness}};
HTTP 202
[Captures]
job_id: jsonpath "$.jobId"
[Asserts]
jsonpath "$.jobId" matches /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
# `already_queued` rather than `queued` when an identical witness is still in
# flight: requests are deduplicated by input hash and the existing job id comes
# back. Same status code either way; the dedup response also sets
# `deduplicated: true` and carries no `estimatedTime`/`statusUrl`.
jsonpath "$.status" matches /^(queued|already_queued)$/
jsonpath "$.circuitType" isString
jsonpath "$.queue" isString

# Poll until the proof lands. Queued and processing both answer 202, so the retry
# runs until the entry as a whole matches -- 200 with a completed result.
GET {{prover_url}}/prove/status
[Options]
retry: 60
retry-interval: 2000ms
[QueryStringParams]
jobId: {{job_id}}
HTTP 200
[Asserts]
jsonpath "$.jobId" == "{{job_id}}"
jsonpath "$.status" == "completed"
jsonpath "$.result.proof.ar" count == 2
jsonpath "$.result.proof.bs" count == 2
jsonpath "$.result.proof.krs" count == 2
jsonpath "$.result.proofDurationMs" isInteger

# A job id is required, and must be a UUID: the two rejections are distinct so a
# caller can tell a missing parameter from a malformed one.
GET {{prover_url}}/prove/status
HTTP 400
[Asserts]
jsonpath "$.code" == "malformed_body"
jsonpath "$.message" contains "jobId parameter required"

GET {{prover_url}}/prove/status
[QueryStringParams]
jobId: not-a-uuid
HTTP 400
[Asserts]
jsonpath "$.code" == "invalid_job_id"

# A well-formed job id the queue has never seen, or whose result has expired.
# Distinguishable from the above so a client can stop polling rather than retry.
GET {{prover_url}}/prove/status
[QueryStringParams]
jobId: 00000000-0000-4000-8000-000000000000
HTTP 404
[Asserts]
jsonpath "$.code" == "job_not_found"
