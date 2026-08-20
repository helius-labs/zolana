# Prover liveness, its method contract, and its Prometheus surface.
#
#   hurl --test --variables-file tools/hurl/localnet.env tools/hurl/prover/health.hurl
#
# /health is the only path exempt from API-key auth
# (prover/server/server/auth.go), so it answers even on a prover started with
# PROVER_API_KEY set. Every other path then needs `-H 'X-API-Key: <key>'` (or
# `-H 'Authorization: Bearer <key>'`).

# What the CLI waits on before reporting the prover ready (cli/src/prover.rs).
GET {{prover_url}}/health
HTTP 200
[Asserts]
jsonpath "$.status" == "ok"

# Every handler checks the method itself and answers 405 with no body -- not a
# JSON error object, so do not parse one.
POST {{prover_url}}/health
HTTP 405
[Asserts]
body == ""

GET {{prover_url}}/prove
HTTP 405
[Asserts]
body == ""

# The metrics server is a separate listener on its own port, with no auth and no
# CORS: 9998 at offset 0, and the same offset as the prover port thereafter.
#
# Only the label-free families are asserted. A labelled counter such as
# prover_proof_requests_total appears only after the first proof of that circuit
# type, so asserting it here would make this file depend on run history.
GET {{prover_metrics_url}}/metrics
HTTP 200
[Asserts]
header "Content-Type" contains "text/plain"
body contains "prover_active_jobs"
body contains "prover_sync_proofs_shed_total"
