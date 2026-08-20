# Witness fetch for a transfer, and the forester's view of the nullifier queue.
#
# This is what `spend_proofs` in sdk-libs/client/src/indexer.rs asks for before a
# proof: one state-inclusion proof per real input, and one nullifier
# non-inclusion proof per input slot -- padding slots included, because the
# circuit checks non-inclusion for dummies too.
#
# Reads real tree state, so it needs real inputs:
#   hurl --test --variables-file tools/hurl/localnet.env \
#     --variable tree=<pool tree address> \
#     --variable leaf=<indexed UTXO hash> \
#     tools/hurl/indexer/proofs.hurl
#
# `tree` is required by all three entries; `leaf` only by getMerkleProofs. An
# address with no indexed tree answers -32600 "Invalid Public Key", and a leaf the
# indexer has not seen answers -32600 "Record Not Found" -- both are the
# contract, see errors.hurl.
#
# `rootIndex` is resolved against the on-chain root history, so an index that has
# already rotated out answers -32600 "Stale Root". That is retryable: re-request.

# State inclusion. The path is UTXO_TREE_HEIGHT (32) siblings, and `rootIndex`
# is the slot in the tree's root history that the program will verify against.
POST {{indexer_url}}/getMerkleProofs
Content-Type: application/json
{
  "id": "hurl-merkle-proofs",
  "jsonrpc": "2.0",
  "method": "getMerkleProofs",
  "params": {
    "treeAccount": "{{tree}}",
    "leaves": ["{{leaf}}"]
  }
}
HTTP 200
[Asserts]
jsonpath "$.error" not exists
jsonpath "$.result.context.slot" isInteger
jsonpath "$.result.proofs" count == 1
jsonpath "$.result.proofs[0].leaf" == "{{leaf}}"
jsonpath "$.result.proofs[0].merkleContext.tree" == "{{tree}}"
jsonpath "$.result.proofs[0].merkleContext.treeType" == 1
jsonpath "$.result.proofs[0].path" count == 32
jsonpath "$.result.proofs[0].leafIndex" isInteger
jsonpath "$.result.proofs[0].root" isString
jsonpath "$.result.proofs[0].rootSeq" isInteger
jsonpath "$.result.proofs[0].rootIndex" isInteger

# Nullifier non-inclusion. The indexed tree answers with the low element whose
# range covers the value, so the path is DEFAULT_BATCH_ADDRESS_TREE_HEIGHT (40)
# siblings. A value that is already spent or queued is rejected with -32600
# "Nullifier leaf ... is already used or queued", which is why this entry uses a
# value no wallet produces rather than a real nullifier.
POST {{indexer_url}}/getNonInclusionProofs
Content-Type: application/json
{
  "id": "hurl-non-inclusion-proofs",
  "jsonrpc": "2.0",
  "method": "getNonInclusionProofs",
  "params": {
    "treeAccount": "{{tree}}",
    "leaves": ["{{unused_nullifier}}"]
  }
}
HTTP 200
[Asserts]
jsonpath "$.error" not exists
jsonpath "$.result.proofs" count == 1
jsonpath "$.result.proofs[0].leaf" == "{{unused_nullifier}}"
jsonpath "$.result.proofs[0].merkleContext.tree" == "{{tree}}"
jsonpath "$.result.proofs[0].merkleContext.treeType" == 2
jsonpath "$.result.proofs[0].path" count == 40
jsonpath "$.result.proofs[0].lowElement" isString
jsonpath "$.result.proofs[0].lowElementIndex" isInteger
jsonpath "$.result.proofs[0].highElement" isString
jsonpath "$.result.proofs[0].highElementIndex" isInteger
jsonpath "$.result.proofs[0].root" isString
jsonpath "$.result.proofs[0].rootSeq" isInteger
jsonpath "$.result.proofs[0].rootIndex" isInteger

# The nullifiers waiting to be appended, in on-chain input-queue order. This is
# the forester's read: it batches from `startSeq` forward.
POST {{indexer_url}}/getNullifierQueueElements
Content-Type: application/json
{
  "id": "hurl-nullifier-queue",
  "jsonrpc": "2.0",
  "method": "getNullifierQueueElements",
  "params": {
    "treeAccount": "{{tree}}",
    "startSeq": 0,
    "limit": {{page_limit}}
  }
}
HTTP 200
[Asserts]
jsonpath "$.error" not exists
jsonpath "$.result.context.slot" isInteger
jsonpath "$.result.elements" isCollection
