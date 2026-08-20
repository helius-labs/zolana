# The indexer's rejection contract. Every entry here is a 200 with a JSON-RPC
# error object, and none of them needs indexed data -- they run against a fresh
# stack.
#
#   hurl --test --variables-file tools/hurl/localnet.env tools/hurl/indexer/errors.hurl
#
# Two error families, distinguished by who rejected the request:
#   -32602 "Invalid params" -- serde could not build the request struct. The
#          detail is in `error.data`, not `error.message`.
#   -32600 -- the method ran and rejected the input. The detail IS the message
#          (PhotonApiError's Display, services/photon/src/api/error.rs).

# Only the seven Rings methods plus the health pair are registered
# (services/photon/src/api/rpc_server.rs). Everything Light Protocol's photon
# used to serve is gone, including getCompressedAccount.
POST {{indexer_url}}/getCompressedAccount
Content-Type: application/json
{
  "id": "hurl-unknown-method",
  "jsonrpc": "2.0",
  "method": "getCompressedAccount",
  "params": {}
}
HTTP 200
[Asserts]
jsonpath "$.result" not exists
jsonpath "$.error.code" == -32601
jsonpath "$.error.message" == "Method not found"

# Required field absent.
POST {{indexer_url}}/getShieldedTransactionsByTags
Content-Type: application/json
{
  "id": "hurl-missing-field",
  "jsonrpc": "2.0",
  "method": "getShieldedTransactionsByTags",
  "params": {
    "limit": 1
  }
}
HTTP 200
[Asserts]
jsonpath "$.error.code" == -32602
jsonpath "$.error.message" == "Invalid params"
jsonpath "$.error.data" contains "missing field `tags`"

# Every request struct is `deny_unknown_fields`: a misspelled or stale field is
# an error, never a silently ignored one.
POST {{indexer_url}}/getShieldedTransactionsByTags
Content-Type: application/json
{
  "id": "hurl-unknown-field",
  "jsonrpc": "2.0",
  "method": "getShieldedTransactionsByTags",
  "params": {
    "tags": ["{{tag}}"],
    "ringProgram": "{{ring_program_id}}"
  }
}
HTTP 200
[Asserts]
jsonpath "$.error.code" == -32602
jsonpath "$.error.data" contains "unknown field `ringProgram`"

# `limit` is a newtype with a 1..=1000 range, checked while deserializing.
POST {{indexer_url}}/getEncryptedUtxosByTags
Content-Type: application/json
{
  "id": "hurl-limit-zero",
  "jsonrpc": "2.0",
  "method": "getEncryptedUtxosByTags",
  "params": {
    "tags": ["{{tag}}"],
    "limit": 0
  }
}
HTTP 200
[Asserts]
jsonpath "$.error.code" == -32602
jsonpath "$.error.data" contains "a value between 1 and 1000"

POST {{indexer_url}}/getEncryptedUtxosByTags
Content-Type: application/json
{
  "id": "hurl-limit-over-page",
  "jsonrpc": "2.0",
  "method": "getEncryptedUtxosByTags",
  "params": {
    "tags": ["{{tag}}"],
    "limit": 1001
  }
}
HTTP 200
[Asserts]
jsonpath "$.error.code" == -32602
jsonpath "$.error.data" contains "a value between 1 and 1000"

# A hash is base58 of exactly 32 bytes.
POST {{indexer_url}}/getShieldedTransactionsByNullifiers
Content-Type: application/json
{
  "id": "hurl-short-hash",
  "jsonrpc": "2.0",
  "method": "getShieldedTransactionsByNullifiers",
  "params": {
    "nullifiers": ["zzz"]
  }
}
HTTP 200
[Asserts]
jsonpath "$.error.code" == -32602
jsonpath "$.error.data" contains "wrong size"

# Proof requests are validated before any tree lookup: no leaves at all,
POST {{indexer_url}}/getMerkleProofs
Content-Type: application/json
{
  "id": "hurl-no-leaves",
  "jsonrpc": "2.0",
  "method": "getMerkleProofs",
  "params": {
    "treeAccount": "{{unknown_tree}}",
    "leaves": []
  }
}
HTTP 200
[Asserts]
jsonpath "$.error.code" == -32600
jsonpath "$.error.message" contains "At least one leaf must be provided"

# ...and a leaf outside the BN254 scalar field, which no circuit could accept.
# Rejected before the tree is looked up, so the tree address here is irrelevant.
POST {{indexer_url}}/getNonInclusionProofs
Content-Type: application/json
{
  "id": "hurl-out-of-field-leaf",
  "jsonrpc": "2.0",
  "method": "getNonInclusionProofs",
  "params": {
    "treeAccount": "{{unknown_tree}}",
    "leaves": ["{{out_of_field_leaf}}"]
  }
}
HTTP 200
[Asserts]
jsonpath "$.error.code" == -32600
jsonpath "$.error.message" contains "outside the BN254 scalar field"

# A well-formed address with no indexed tree. This is the error a client gets for
# a tree the indexer has not caught up to, so treat it as retryable rather than
# as a bad request.
POST {{indexer_url}}/getMerkleProofs
Content-Type: application/json
{
  "id": "hurl-unknown-tree",
  "jsonrpc": "2.0",
  "method": "getMerkleProofs",
  "params": {
    "treeAccount": "{{unknown_tree}}",
    "leaves": ["{{unused_nullifier}}"]
  }
}
HTTP 200
[Asserts]
jsonpath "$.error.code" == -32600
jsonpath "$.error.message" contains "Invalid Public Key"
