# Replay a captured witness on the in-response rail.
#
#   hurl --test --file-root tools/hurl \
#     --variables-file tools/hurl/localnet.env \
#     --variable witness=fixtures/transfer-2x2.json \
#     tools/hurl/prover/prove.hurl
#
# `witness` is a path to a complete request body: the JSON the SDK POSTs
# (sdk-libs/client/src/prover/json.rs), where `circuitType` selects the circuit
# and `nInputs`/`nOutputs` select the proving key. hurl reads file bodies only
# from under --file-root (default: this file's own directory), so pass
# `--file-root tools/hurl` and a path relative to it. A witness cannot be
# hand-written -- every field is Poseidon-consistent with the others -- so
# README.md has the capture recipe.
#
# X-Sync forces the proof into the response even on a redis-backed prover, which
# is what the SDK asks for on transfer and merge shapes: a ~150ms proof is not
# worth an enqueue plus a poll. The prover may still answer 429 `prover_busy`
# when it is at its sync concurrency limit; the SDK's response to that is to
# re-submit on the queue, not to retry synchronously (see prove-async.hurl).
#
# The first request for a shape loads its proving key (~0.5G, lazily), so it can
# take orders of magnitude longer than the warm case. Measure the warm case with
# `hurl --repeat 20 ...` once the key is loaded.
POST {{prover_url}}/prove
Content-Type: application/json
X-Sync: true
file,{{witness}};
HTTP 200
[Asserts]
header "Content-Type" == "application/json"
jsonpath "$.ar" count == 2
jsonpath "$.ar[0]" matches /^0x[0-9a-f]{64}$/
jsonpath "$.bs" count == 2
jsonpath "$.bs[0]" count == 2
jsonpath "$.bs[1]" count == 2
jsonpath "$.krs" count == 2
jsonpath "$.krs[0]" matches /^0x[0-9a-f]{64}$/
# The two rails differ here on purpose, so neither is asserted: transfer_p256
# carries a BSB22 commitment and answers with `proofCommitment` +
# `proofCommitmentPok`, while the eddsa rails are standard Groth16 and omit both
# (the Go side marshals them `omitempty`).
