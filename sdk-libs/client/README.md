# Prover data source

`ZolanaClient` fetches proof data from the indexer by default. Opt into prover fetching with `with_proof_data_source(ProofDataSource::Prover)`. Configure the prover with `PROVER_INDEXER_URL` and, when needed, `PROVER_INDEXER_API_KEY`.

Blocking and async confidential transaction methods then submit locally prepared fields to `/prove/indexed`. The prover resolves paths and root contexts. The SDK binds the returned roots to its original public transcript and verifies the proof before returning transaction data. `IndexerRpcConfig.require_slot` becomes the minimum indexer context slot.

For a merge, construct `IndexedMergePreparation { merge, nullifier_key }.prepare()?`, call `prove_indexed(prepared.request())`, then `prepared.finish(proof)?`. Both owner rails use the same preparation API. The final step verifies the proof and returns merge instruction data.

Custom callers can construct `IndexedProofRequest::new(IndexedProofData { witness, trees, inputs, public_inputs })` for the transfer and merge circuit families. `witness` contains the existing circuit JSON without paths, tree slots, or the public input hash. `public_inputs` contains the circuit transcript without the tree-slot hash at position two. The caller must derive that transcript locally and verify the returned proof before signing. Ring and P256 witness builders remain explicit APIs and do not read the `ZolanaClient` data-source setting.

All transfer and merge requests prefer a proof in the HTTP response. A capacity rejection automatically retries through the queue. Forester and custom circuit proofs retain queued delivery.
