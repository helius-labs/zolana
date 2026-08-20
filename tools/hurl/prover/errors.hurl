# The prover's rejection contract for /prove. No witness and no proving key are
# needed: every entry here is refused before any key is loaded, which is the
# point -- these are cheap to run against any prover.
#
#   hurl --test --variables-file tools/hurl/localnet.env tools/hurl/prover/errors.hurl
#
# Errors are a flat `{code, message}` object (prover/server/server/server.go),
# not JSON-RPC. Two codes matter:
#   malformed_body (400) -- the request could not be read as this circuit's input
#   proving_error  (400) -- the input was read, and proving refused it
#
# Every entry forces the synchronous rail, because only that rail answers with
# the rejection. On a redis-backed prover the default rail enqueues a queueable
# circuit before anything reads the body, so a malformed witness comes back as
# 202 `queued` and only surfaces as a failed job on /prove/status. Measured
# against the devnet prover: the same body is 202 by default and 400 with
# X-Sync. The rejections below are the contract; the rail is what decides
# whether you are told now or later.

# Not JSON at all.
POST {{prover_url}}/prove
Content-Type: application/json
X-Sync: true
```
not json
```
HTTP 400
[Asserts]
jsonpath "$.code" == "malformed_body"
jsonpath "$.message" contains "failed to parse JSON"

# `circuitType` picks the circuit, so nothing can be dispatched without it.
POST {{prover_url}}/prove
Content-Type: application/json
X-Sync: true
{}
HTTP 400
[Asserts]
jsonpath "$.code" == "malformed_body"
jsonpath "$.message" contains "missing or invalid 'circuitType'"

# The zk-compression circuits (inclusion, non-inclusion, combined, append,
# update) were removed from this prover; only address-append, the transfer rails,
# and the merge rails remain. A stale client asking for one is told so.
POST {{prover_url}}/prove
Content-Type: application/json
X-Sync: true
{
  "circuitType": "inclusion",
  "treeHeight": 26
}
HTTP 400
[Asserts]
jsonpath "$.code" == "malformed_body"
jsonpath "$.message" contains "unknown circuit type: inclusion"

# Every circuit except the fixed-shape transfer and merge rails is keyed by tree
# height, and is rejected without one.
POST {{prover_url}}/prove
Content-Type: application/json
X-Sync: true
{
  "circuitType": "address-append"
}
HTTP 400
[Asserts]
jsonpath "$.code" == "malformed_body"
jsonpath "$.message" contains "or 'treeHeight' provided"

# A transfer body is checked against the circuit's fixed public-slot count
# (NPublicSlots = 3) while it is being read, before any key lookup.
POST {{prover_url}}/prove
Content-Type: application/json
X-Sync: true
{
  "circuitType": "transfer-ring",
  "nInputs": 2,
  "nOutputs": 2
}
HTTP 400
[Asserts]
jsonpath "$.code" == "malformed_body"
jsonpath "$.message" contains "public slot count mismatch"

# Transfer proving systems are per-shape, and the supported set is fixed
# (prover/server/prover/common/lazy_key_manager.go, mirrored in
# sdk-libs/client/src/shape.rs and the Go protocol shape list). 7x7 is not in it,
# so the request is refused at key selection rather than by trying to load a key
# that does not exist.
POST {{prover_url}}/prove
Content-Type: application/json
X-Sync: true
{
  "circuitType": "transfer-ring",
  "nInputs": 7,
  "nOutputs": 7,
  "publicAssets": ["0x0", "0x0", "0x0"],
  "publicAmounts": ["0x0", "0x0", "0x0"]
}
HTTP 400
[Asserts]
jsonpath "$.code" == "proving_error"
jsonpath "$.message" contains "no key file mapping for transfer-ring with 7 inputs and 7 outputs"
