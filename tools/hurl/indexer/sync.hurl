# The indexer half of a wallet sync round, in the order the SDK issues it
# (sdk-libs/wallet/src/wallet_sync.rs runs the three queries concurrently -- they
# are independent methods with disjoint cursor streams), plus the by-signature
# lookup the confirm phase uses.
#
#   hurl --test --variables-file tools/hurl/localnet.env tools/hurl/indexer/sync.hurl
#
# The default `tag` / `nullifier` / `signature` match nothing, so every entry
# returns an empty page and the asserts are envelope-shaped. Pass real values to
# read real data:
#   hurl --variables-file tools/hurl/localnet.env --variable tag=<view tag> ...
#
# Pagination: a full page returns `nextCursor`; feed it back as `cursor` on the
# next request for the same stream, and stop when it is null. Assert on
# `context.slot` to know how fresh the page is.

# Transactions carrying one of our output view tags. This is the stream the
# wallet reconstructs its UTXO set from.
POST {{indexer_url}}/getShieldedTransactionsByTags
Content-Type: application/json
{
  "id": "hurl-transactions-by-tags",
  "jsonrpc": "2.0",
  "method": "getShieldedTransactionsByTags",
  "params": {
    "tags": ["{{tag}}"],
    "limit": {{page_limit}}
  }
}
HTTP 200
[Captures]
tags_cursor: jsonpath "$.result.nextCursor"
[Asserts]
jsonpath "$.error" not exists
jsonpath "$.result.context.slot" isInteger
jsonpath "$.result.context.blockTime" isInteger
jsonpath "$.result.transactions" isCollection
jsonpath "$.result.nextCursor" exists

# Same tags, restricted to one ring. The ring's config account is derived from
# the program id, so this filter needs no indexed registration.
#
# Needs an indexer at or past the ring-association change (#240). Requests are
# `deny_unknown_fields`, so an older indexer does not ignore `ringProgramId` --
# it answers -32602 "unknown field". Adding an optional request field is a
# breaking change against a deployment that has not caught up; measured against
# devnet, which still serves only `tags`, `cursor`, `limit`.
POST {{indexer_url}}/getShieldedTransactionsByTags
Content-Type: application/json
{
  "id": "hurl-transactions-by-tags-ring",
  "jsonrpc": "2.0",
  "method": "getShieldedTransactionsByTags",
  "params": {
    "tags": ["{{tag}}"],
    "limit": {{page_limit}},
    "ringProgramId": "{{ring_program_id}}"
  }
}
HTTP 200
[Asserts]
jsonpath "$.error" not exists
jsonpath "$.result.transactions" isCollection

# Output-level matches for the same tags: the encrypted-utxo stream, which is how
# the wallet picks up proofless deposits.
POST {{indexer_url}}/getEncryptedUtxosByTags
Content-Type: application/json
{
  "id": "hurl-encrypted-utxos-by-tags",
  "jsonrpc": "2.0",
  "method": "getEncryptedUtxosByTags",
  "params": {
    "tags": ["{{tag}}"],
    "limit": {{page_limit}}
  }
}
HTTP 200
[Asserts]
jsonpath "$.error" not exists
jsonpath "$.result.context.slot" isInteger
jsonpath "$.result.matches" isCollection
jsonpath "$.result.nextCursor" exists

# Which of our notes have been spent. `scannedThrough` is present only on a page
# the limit did not truncate, and means "no match exists at or before here" --
# which is what an unspent nullifier looks like.
POST {{indexer_url}}/getShieldedTransactionsByNullifiers
Content-Type: application/json
{
  "id": "hurl-transactions-by-nullifiers",
  "jsonrpc": "2.0",
  "method": "getShieldedTransactionsByNullifiers",
  "params": {
    "nullifiers": ["{{nullifier}}"],
    "limit": {{page_limit}}
  }
}
HTTP 200
[Asserts]
jsonpath "$.error" not exists
jsonpath "$.result.context.slot" isInteger
jsonpath "$.result.transactions" isCollection
jsonpath "$.result.nextCursor" exists

# The confirm phase: a sent transaction is confirmed for the wallet once the
# indexer can name its events. One entry per event index, ordered.
POST {{indexer_url}}/getShieldedTransactionsBySignature
Content-Type: application/json
{
  "id": "hurl-transactions-by-signature",
  "jsonrpc": "2.0",
  "method": "getShieldedTransactionsBySignature",
  "params": {
    "txSignature": "{{signature}}"
  }
}
HTTP 200
[Asserts]
jsonpath "$.error" not exists
jsonpath "$.result.context.slot" isInteger
jsonpath "$.result.transactions" isCollection
