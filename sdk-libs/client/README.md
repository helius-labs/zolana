# Clients

A client owns the three services a private transaction needs: the Solana
RPC (`R`), the indexer (`I`) and the prover.

## Blocking and async

`AsyncZolanaClient<R, I>` is the client; `ZolanaClient<R, I>` is the same
client for blocking callers, run on a Tokio runtime it owns, over a blocking
`R` and `I` lifted onto the blocking pool by `Blocking`. There is one
implementation of everything; the blocking client runs it to completion.

```rust
let client = ZolanaClient::from_urls(rpc, indexer_url, prover_url)?;
let client = AsyncZolanaClient::from_urls(rpc, indexer_url, prover_url)?;
```

or from the services: `ZolanaClient::new(rpc, indexer, prover)` with a
`ZolanaIndexer` and a `ProverClient`, `AsyncZolanaClient::new` with their
`async` counterparts. `from_urls` accepts https, or http to loopback only;
`check_service_url` is that check for a caller building its own services.

Use the blocking client from plain threads or inside a multi-thread runtime,
as `solana_rpc_client`'s blocking client. Inside a `current_thread` runtime
(a default `#[tokio::main]` or `#[tokio::test]`) every call fails with
`ClientError::BlockingInsideRuntime`; use the `async` client there. A
generic helper over the blocking client bounds its RPC with `BlockingRpc`
and its indexer with `BlockingIndexer`.

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
let signature = Submission::new(&signed, fee_payer, &authority)
    .send_sync(&client, &[&fee_payer_keypair])?;   // async: .send(&client, ..).await
```

proves, signs, sends and waits until the transaction is confirmed and
indexed. `finish_unsigned_sync` / `finish_unsigned` stop at the unsigned
message, for a fee payer whose key lives elsewhere. The message carries a
blockhash fetched beside the proof. If that request is still pending when proving
succeeds, the client cancels it and fetches again immediately. A completed request
is reused only if it succeeded and began at most ten seconds ago, including RPC
response latency. A proof error returns immediately without waiting for the
blockhash request. Merge submissions use the same rule.
The ten-second limit controls prefetch reuse; blockhash expiration follows chain
state and the returned `last_valid_block_height`.

After a lost send response or a restart,
`wait_for_private_transaction_sync(signature, last_valid_block_height)`
(async: `wait_for_private_transaction`) recovers a deposit, transfer, withdrawal
or merge. Save the **signed transaction's signature and last valid block height
before sending**, alongside its wallet reservations. Use `finish_unsigned` and
sign explicitly when the application needs this checkpoint; `Submission::send`
does not persist one for you.

| Outcome | Application action |
| --- | --- |
| `Ok(())` | Private effects are indexed; sync and persist the wallet. |
| Confirmed chain error | Report the rejected transaction and sync before another attempt. |
| `TransactionExpired` | No private effects through the expiry slot; sync before building a replacement. |
| `TransactionNotIndexed` | Confirmed, but effects are not yet readable; keep the checkpoint and wait again. |
| `TransactionOutcomeUnknown` | Keep the checkpoint and reservations; wait again with the same signature. |

`confirm_private_transaction` uses the same recovery engine without an expiry
height. Its unresolved errors are now `TransactionNotIndexed` and
`TransactionOutcomeUnknown`, replacing the former indexer timeout errors.
Both methods stop at the poll limit or a 60-second overall deadline, including
requests; `with_transaction_wait_timeout` adjusts that deadline. Timeouts never
prove expiry. With a blocking RPC adapter, its underlying request may outlive
the wait, so configure the adapter's own transport timeout too.

The RPC and complete private-event indexer must serve the same network, using
confirmed commitment. Registration, arbitrary program calls, and durable-nonce
transactions do not fit this contract. Recovery never sends or rebuilds.
See the [restart recovery example](../../sdk-tests/client/rust/recover_private_transaction.rs).

`Submission::with_prover(Arc<dyn Prover>)` proves one submission with a
prover of the caller's, such as one on the device; `with_prover` on either
client builds one that proves every submission that way. Either prover only
proves what the client hands it, so the client fetches the proof data itself
and nothing reaches a prover server.

A prover server client attests every remote prover, the Helius gateway
included, to the deployment the SDK pins, `tee::DEFAULT_PROVER_URL`, and
encrypts every call to it. Only a loopback prover without a proxy gets
plaintext. `with_tee(policy)` takes another policy. `for_tree_batches()`
sends nullifier-tree batch proofs in plaintext to any prover, as they carry
only public tree data, and refuses every other proof. Pass the prover client to
`ZolanaClient::new`.

For the current devnet deployment, use Photon at
`https://d21d98xh5lgv3b.cloudfront.net` and `tee::DEFAULT_PROVER_URL` at
`https://d1unet9hn0mci0.cloudfront.net`. The default policy pins the PCR0–PCR2
measurements and attested HPKE key of indexed `devnet-d-tee-2`; no caller-supplied
policy is needed. See the [TEE deployment pin](../../prover/tee/README.md#building-on-it)
for its measured-build and policy provenance. Verification still checks the
attestation signature and certificate chain, nonce, freshness, measurements and
HPKE key before encrypting a request.

## Merging

A merge turns up to 52 plain UTXOs of one asset on one tree into one. The
owner enables it once by selecting the merge encryption scheme with
`set_merge_encryption_instruction(owner, MergeEncryptionScheme::PoseidonCtrV1)`,
which the owner signs; after that a merge with that scheme needs no owner
signature.

```rust
let inputs = select_merge(spendable.utxos(), asset, MERGE_DEFAULT_INPUT_COUNT, &reserved)?;
let tree_id = inputs[0].tree_id();
let merge = MergeTransaction::new(inputs)?
    .with_output_tree_id(tree_id)
    .with_expiry(now + 600)
    .encrypt(&keys)?;
let submission = MergeSubmission::new(&merge, owner, &address, &nullifier_key);
let signature = submission.send_sync(&client, &fee_payer)?;
```

`with_output_tree_id` is required in practice: without it the merged UTXO is
appended to tree 0. Pass the inputs' tree, or the tree the indexer names for
new outputs when that one is full or paused.

`prove_sync` checks the owner's record (PoseidonCtrV1 selected, same keys), fetches
the witness, proves and verifies the proof. The proof binds no fee payer, so
the `ProvedMerge` it returns is for any payer: `proved.instruction(payer)` is
the `merge_transact` to put in any message, for example a relayer's.
`finish_unsigned_sync(&client, fee_payer)` builds the message the payer signs
alone; `send_sync` signs, sends and waits as `Submission` does. As for
`Submission`, the generics and the blocking or async choice sit on these
methods, so `MergeSubmission` itself is a plain borrow. Set an expiry: until it passes,
anyone holding the proof can submit it. The proof request carries the
owner's nullifier secret, so a prover other than this process learns it and
every merged amount; `MergeSubmission::with_prover` keeps it in process.

## In process: litesvm

Any indexer serves a client. A blocking one answers the indexer half of
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

The cache and its selected slots are public, so a one-input spend that reads
one slot, publishes no UTXO root and withdraws publicly reveals which cached
output it spends. Use the cache for short-lived batch work such as merges that
feed dependent proofs.
When a spend needs unlinkability, wait for tree inclusion and select no cache
slot. See "Cache privacy" in `docs/spec.md`.

Prover fetching sends locally prepared inputs to `/prove/<key>/indexed`. The prover
resolves Merkle paths and root contexts. The SDK binds the returned roots to
its original public statement and verifies the proof before returning
transaction data. `IndexerRpcConfig.require_slot` sets the minimum indexer
context slot for `ZolanaClient` transactions; `UtxoScan::with_indexer_config`
applies it to wallet discovery, so a spend another client just made is read.
Wallet discovery and chain account reads still use the SDK's configured services.

`UtxoScan` scans the assets in the supplied `AssetRegistry` by default and
reports other asset ids and mints as unknown. Opt into on-chain SPL asset
discovery when the wallet should hold every registered asset:

```rust
let scan = UtxoScan::new(&keys, &assets)
    .with_indexer_config(IndexerRpcConfig::at_slot(confirmed_slot))
    .with_asset_discovery()
    .fetch(&client)?;
assets = scan.asset_registry;
```

An unknown asset triggers one filtered `getProgramAccounts` read of the
pool's SPL registrations, validated by owner, layout and mint PDA. The lookup
requires the greater of `require_slot` and every transaction slot fetched so
far. A lagging Solana RPC fails the scan. Registry validation and merging use
indexed mint lookups, so loading registrations takes linear time.

The scan decrypts its already fetched transactions again and follows newly resolved
nullifiers without repeating tag queries. `fetch_spl_asset_registrations`
exposes the same validated lookup separately with an optional minimum context
slot. Reuse the returned registry to cache mappings across scans; the input
registry is unchanged, including
on failure. Outputs in assets still unresolved after discovery are skipped;
the scan continues following known assets' nullifiers and reports the remaining
ids and mints through `unknown_asset_ids` and `unknown_mints` in both `spendable`
and `history`. These fields indicate outputs omitted from the balances and
history; an unknown id is sender-provided and is not evidence of a valid asset
or balance. RPC failures and invalid or conflicting registrations still fail
the scan. Leave discovery disabled for an explicit asset allowlist.
Custom `Rpc` implementations must support
`get_program_accounts_filtered`, including its minimum context slot; discovery
never falls back to an unfiltered or stale program listing.

`IndexedTransferPreparation` selects confidential, ring, ring-authority or
anonymous EdDSA authorization. `IndexedMergePreparation` supports both merge rails and
cache outputs. Pass the prepared request to `prove_indexed`, which checks the
returned roots, verifies the proof and returns transaction data. A ring merge
returns `ProvenIndexedMerge::Ring`.

Transfer, merge and indexed ring policy requests prefer a proof in the HTTP
response. A capacity rejection can retry through the queue when Redis is
available. Indexed deposit audits use synchronous delivery. Forester batch
proofs use queued delivery.
