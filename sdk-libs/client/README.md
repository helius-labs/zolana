# Clients

A `ZolanaClient` owns the three services a private transaction needs: the
Solana RPC (`R`), the indexer (`I`) and the prover. The indexer fixes the
client's mode.

## Blocking and async

`ZolanaClient<R>`, over a `ZolanaIndexer`, blocks and implements `Rpc`;
`AsyncZolanaClient<R>`, over an `AsyncZolanaIndexer`, is `async` and
implements `AsyncRpc`. Build either from URLs, naming the mode where nothing
else does, since Rust does not infer a default type parameter:

```rust
let client = ZolanaClient::<_>::from_urls(rpc, indexer_url, prover_url)?;
let client = AsyncZolanaClient::from_urls(rpc, indexer_url, prover_url)?;
```

or from the services themselves: `ZolanaClient::new(rpc, indexer, prover)`.
`from_urls` accepts https, or http to loopback only; `check_service_url` is
that check for a caller building its own services.

A blocking client is the `async` one run on a Tokio runtime it owns, the way
`solana_rpc_client` drives its nonblocking client. Use it from plain threads
or inside a multi-thread runtime; a `current_thread` runtime cannot host it.

## Your own HTTP client

`zolana_api::HttpClient` and `BlockingHttpClient` carry one request and answer
with the server's response, nothing more: routes, retries, polling, timeouts
and TEE encryption stay with the client, so the transport is not trusted with
any of them. `ZolanaApi::with_client`, `ProverClient::with_client` and
`AsyncProverClient::with_client` take an implementation; `HttpResponse`
carries the headers because a TEE prover answers with ciphertext. Give a
blocking client an HTTP client of its own rather than a clone shared with
another runtime.

Without the `reqwest` feature neither crate links reqwest and only
`with_client` builds a client; `solana-rpc` still links it through
`solana-rpc-client`, so a wallet that wants none brings its own `Rpc` too.

## Proving and submitting

```rust
let message = Submission::new(&signed, fee_payer, &authority)
    .finish_unsigned_sync(&client)?;            // async: .finish_unsigned(&client).await
```

`Submission::with_prover(Arc<dyn Prover>)` proves one submission with a
prover of the caller's, such as one on the device; `ZolanaClient::with_prover`
builds a client that proves every submission that way. Either prover only
proves what the client hands it, so the client fetches the proof data itself
and nothing reaches a prover server. The message carries a blockhash fetched
after proving.

A TEE policy belongs to the prover server client: pass
`ProverClient::new(url).with_tee(policy)` to `ZolanaClient::new`.

## In process: litesvm

`Indexer` is open. An indexer is anything that answers the indexer half of
`Rpc` and implements `WitnessReader`, which has a default over `Rpc`:
`impl WitnessReader for MyIndexer {}`. `zolana_program_test::ZolanaProgramTest`
is one: `harness.into_client(ProverClient::local())
.with_proof_data_source(ProofDataSource::Client)` is a client whose RPC and
indexer are the litesvm harness, so a transfer proves, sends and confirms in
one process beside a prover server.

# Prover data source

`ProverClient` and `AsyncProverClient` use prover fetching by default.
Configure `PROVER_INDEXER_URL` and, when needed, `PROVER_INDEXER_API_KEY` on
the prover. The indexer must serve the same network. A prover without an
indexer refuses indexed requests with `ClientError::ProverIndexerUnconfigured`.

Opt into client fetching with
`with_proof_data_source(ProofDataSource::Client)`. A prover URL on a
`*.helius-rpc.com` host's `/v1/zolana` path, the Helius gateway, defaults to
client fetching, sends every proof to the key-less `/v1/zolana/prove`, polls
`/v1/zolana/prove/status`, and refuses indexed requests, which the gateway
does not route. The setting lives on
`ProverClient` and `AsyncProverClient`. The `ZolanaClient` method sets it on
the prover client it holds; a prover given with `with_prover` is handed the
data by the client. Custom-ring proof environments read it from the prover
client they are given.
Both modes support cached spends and merge outputs. The forester selects
client fetching with `--client-proof-data`.

Prover fetching sends locally prepared inputs to `/prove/<key>/indexed`. The prover
resolves Merkle paths and root contexts. The SDK binds the returned roots to
its original public statement and verifies the proof before returning
transaction data. `IndexerRpcConfig.require_slot` sets the minimum indexer
context slot for `ZolanaClient` transactions. Wallet discovery and chain
account reads still use the SDK's configured services.

`IndexedTransferPreparation` selects confidential, ring, ring-authority or
P256 authorization. `IndexedMergePreparation` supports both merge rails and
cache outputs. Pass the prepared request to `prove_indexed`, which checks the
returned roots, verifies the proof and returns transaction data. A ring merge
returns `ProvenIndexedMerge::Ring`.

Transfer, merge and indexed ring policy requests prefer a proof in the HTTP
response. A capacity rejection can retry through the queue when Redis is
available. Indexed deposit audits use synchronous delivery. Forester batch
proofs use queued delivery.
