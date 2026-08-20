# Indexer health: the two GET-proxied endpoints and the JSON-RPC freshness pair.
#
#   hurl --test --variables-file tools/hurl/localnet.env tools/hurl/indexer/health.hurl
#
# /liveness and /readiness are jsonrpsee ProxyGetRequestLayer routes
# (services/photon/src/api/rpc_server.rs): the layer strips the JSON-RPC envelope
# and answers with the bare `result`, which is `null` for both.
#
# Every other call is POST JSON-RPC. The path repeats the method because that is
# how the SDK addresses the indexer (`{base}/{method}`, sdk-libs/zolana-api); the
# server routes on the body's `method` alone and ignores the path.

# Process is up.
GET {{indexer_url}}/liveness
HTTP 200
[Asserts]
body == "null"

# Process is up and its database answers `SELECT 1`.
GET {{indexer_url}}/readiness
HTTP 200
[Asserts]
body == "null"

# Indexed slot is within HEALTH_CHECK_SLOT_DISTANCE (20) of the chain tip. A
# lagging indexer answers -32600 "Node is behind N slots" instead, which is the
# point of the endpoint -- do not soften this assert.
POST {{indexer_url}}/getIndexerHealth
Content-Type: application/json
{
  "id": "hurl-indexer-health",
  "jsonrpc": "2.0",
  "method": "getIndexerHealth"
}
HTTP 200
[Asserts]
jsonpath "$.error" not exists
jsonpath "$.result" == "ok"

# The slot every response's `context.slot` is read from, and the value the SDK's
# `require_slot` freshness gate polls against (sdk-libs/client/src/indexer.rs).
POST {{indexer_url}}/getIndexerSlot
Content-Type: application/json
{
  "id": "hurl-indexer-slot",
  "jsonrpc": "2.0",
  "method": "getIndexerSlot"
}
HTTP 200
[Asserts]
jsonpath "$.error" not exists
jsonpath "$.result" isInteger
jsonpath "$.result" >= 0
