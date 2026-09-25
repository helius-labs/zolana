# Prover data source

`ZolanaClient`, `ProverClient` and `AsyncProverClient` use prover fetching by
default. Configure `PROVER_INDEXER_URL` and, when needed,
`PROVER_INDEXER_API_KEY` on the prover. The indexer must serve the same network.

Opt into client fetching with
`with_proof_data_source(ProofDataSource::Client)`. Set it on `ZolanaClient`
for its transaction methods, or on the prover client passed to custom-ring
proof environments. Both modes support cached spends and merge outputs.
The forester selects client fetching with `--client-proof-data`.

Prover fetching sends locally prepared inputs to `/prove/indexed`. The prover
resolves Merkle paths and root contexts. The SDK binds the returned roots to
its original public statement and verifies the proof before returning
transaction data. `IndexerRpcConfig.require_slot` sets the minimum indexer
context slot for `ZolanaClient` transactions. Wallet discovery and chain
account reads still use the SDK's configured services.

`IndexedTransferPreparation` selects confidential, ring, ring-authority or
P256 authorization. `IndexedMergePreparation` supports both merge rails and
cache outputs. Prepare the request, call `prove_indexed`, then call `finish`
to verify the proof and construct transaction data. Ring merges use
`finish_ring` in place of `finish`.

Transfer, merge and indexed ring policy requests prefer a proof in the HTTP
response. A capacity rejection can retry through the queue when Redis is
available. Indexed deposit audits use synchronous delivery. Forester batch
proofs use queued delivery.
