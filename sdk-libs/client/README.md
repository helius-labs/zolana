# Clients

A client owns the three services a private transaction needs: the Solana
RPC (`R`), the indexer (`I`) and the prover.

## Blocking and async

`AsyncSprClient<R, I>` is the client; `SprClient<R, I>` is the same
client for blocking callers, run on a Tokio runtime it owns, over a blocking
`R` and `I` lifted onto the blocking pool by `Blocking`. There is one
implementation of everything; the blocking client runs it to completion.

```rust
let policy = TeePolicy::from_file_json(&std::fs::read_to_string(policy_path)?)?;
let client = SprClient::from_urls(rpc_url, indexer_url, prover_url, Some(policy))?;
// AsyncSprClient::from_urls takes an RPC adapter as its first argument.
```

or from the services: `SprClient::from_parts(rpc, indexer, prover)` with a
`SprIndexer` and a `ProverClient`, `AsyncSprClient::new` with their
`async` counterparts. `SprClient::new(url, Some(policy))?` uses the same gateway URL for
RPC, indexer and prover requests. The blocking URL constructors require
`reqwest` and `solana-rpc`. `from_urls` accepts https, or http to loopback only;
`check_service_url` is that check for a caller building its own services.
The fourth argument to both URL constructors (including
`from_urls_allowing_insecure_http`) is the prover's policy. Pass `None` for
loopback development; remote proving without a policy fails before HTTP.

Use the blocking client from plain threads or inside a multi-thread runtime,
as `solana_rpc_client`'s blocking client. Inside a `current_thread` runtime
(a default `#[tokio::main]` or `#[tokio::test]`) every call fails with
`ClientError::BlockingInsideRuntime`; use the `async` client there. A
generic helper over the blocking client bounds its RPC with `BlockingRpc`
and its indexer with `BlockingIndexer`.

## Your own HTTP client

`spr_api::HttpClient` and `BlockingHttpClient` carry one request and answer
with the server's response, nothing more: routes, retries, polling, timeouts
and TEE encryption stay with the client, so the transport is not trusted with
any of them. `SprApi::with_client`, `ProverClient::with_client` and
`AsyncProverClient::with_client` take an implementation; `HttpResponse`
carries the headers because a TEE prover answers with ciphertext. Give a
blocking client an HTTP client of its own rather than a clone shared with
another runtime.

Without the `reqwest` feature neither crate links reqwest and only
`with_client` builds a client; `solana-rpc` still links it through
`solana-rpc-client`, so a wallet that wants none brings its own `Rpc` too.

## Proving and submitting

```rust
let proof_inputs = transaction.encrypt(&sender)?;
let request = TransactionProofRequest::new(proof_inputs, &[&sender])?;
let signature = request.prove_and_send_sync(&client, &[&fee_payer_keypair, &sender])?;
```

For an unsigned message, use the parallel helper:

```rust
let unsigned = request.fetch_and_prove_sync(&client)?;
let signed = sign_transaction(unsigned.message, &[&fee_payer_keypair, &sender])?;
let signature = client.process_transaction(signed)?;
```

The async counterpart is `request.fetch_and_prove(&client).await?`. It runs the
proof pipeline, settlement-account reads, and blockhash fetch concurrently,
then synchronously builds an `UnsignedMessage`. It does not sign or submit.
`prove_and_send` and `prove_and_send_sync` use that helper, sign, submit, and
wait for confirmation and indexing.

Each async operation is also available separately. For caller-controlled
scheduling on the client-fetched-data route:

```rust
let (input_proofs, settlement_accounts, (blockhash, last_valid_block_height)) =
    tokio::try_join!(
        client.fetch_input_proofs(&request),
        client.fetch_settlement_accounts(&request),
        client.get_latest_blockhash(),
    )?;
let transfer: TransferProofResult = request.build(input_proofs)?;
let proof = request.prove(&client, &transfer).await?;
let proved = request.with_proof(transfer, proof)?;
let unsigned = proved.build_solana_message(
    &settlement_accounts,
    blockhash,
    last_valid_block_height,
    client.compute_budget(),
)?;
```

`build` constructs completed prover inputs and their matching instruction data
in one synchronous operation. `TransferProofResult` replaces the extra
`AssembledTransfer` representation. `prove` invokes the selected backend with
those inputs and performs no chain reads. `with_proof` checks the returned
proof's encoding and attaches it. Groth16 verification is performed on chain;
the SDK retains response decoding, proving-key identity, root-resolution,
request-statement, and settlement-account validation.

The helper preserves prover-side fetching when `ProofDataSource::Prover` is
selected. `build_indexed` and `client.prove_indexed` expose that route for
manual composition. A per-request prover override uses the explicit
client-fetched-data route.

A proved result can build another message using a new blockhash without
regenerating its proof. Keep each blockhash paired with the expiry height from
the same response. `proved.instruction(&settlement_accounts)?` supports custom
messages. Cache-write proofs expose `instruction_data()` for a custom
`Transact` builder that supplies the cache writer.

SOL settlement accounts come from the public transfers. SPL settlement fetches
the mint's token program and the deposit token account's authority through the
Solana RPC. The SDK checks the token account's program and mint, and message
construction checks that the supplied account groups match the proved transfers.

Transactions with several nullifier keys pass a slice of authorities. The SDK
matches inputs to authorities by nullifier public key, rejects missing or
ambiguous matches, and returns provider errors.

`TransactionProofRequest::with_prover(Arc<dyn Prover>)` selects a prover for
one request. `SprClient::from_parts` and
`AsyncSprClient::with_prover` accept a custom prover for the client.
In-process provers receive proof data fetched by the client; a supplied
`ProverClient` retains its server transport and indexed route.

A remote prover requires a caller-supplied URL and policy. The SDK pins who
signs each network's prover policy, so a client follows new prover releases
without an SDK release. It downloads the signed policy again whenever it
attests again, every `max_age_secs` of the policy, and never uses it once its
release or its freshness part expires:

```rust
let prover = ProverClient::new(prover_url)
    .with_signed_tee(SignedTeePolicy::for_network(TeeNetwork::Mainnet));
```

An application that reviews each release itself can instead load that
release's policy JSON with `TeePolicy::from_file_json` and pass it to
`with_tee`, or its own release signers to `SignedTeePolicy::new(url, PolicySigners::new(network, keys, threshold)?)`.

The SDK embeds no prover URLs. The same policy parameter works
with a direct prover URL, a unified Helius API URL or a proxy path. Remote calls
without a policy fail before HTTP. Only loopback development without a proxy
permits plaintext. The explicit `for_tree_batches()` mode permits public
nullifier-tree batch proofs in plaintext and refuses every other proof.

The [TEE deployment guide](../../prover/tee/README.md) records the reviewed
policies and measured-build provenance. An older SDK can use a new deployment
policy when its schema, attestation protocol and circuits remain supported.
Image rebuilds and key rotations alone do not require an SDK release.

For readiness through the Helius API, use attestation and proving-key checks.
`check_indexed` and `check_setup(IndexerRequirement::Required)` also call the
operator `/health` route, which is not part of the public gateway API.

## Merging

A merge turns up to 52 plain UTXOs of one asset on one tree into one. The
owner enables it once by selecting the merge encryption scheme with
`set_merge_encryption_instruction(owner, MergeEncryptionScheme::PoseidonCtrV1)`,
which the owner signs; after that a merge with that scheme needs no owner
signature.

```rust
let inputs = select_merge(spendable.utxos(), asset, MERGE_DEFAULT_INPUT_COUNT, &reserved)?;
let tree_id = inputs.first().ok_or(ClientError::NoInputs)?.tree_id();
let merge = MergeTransaction::new(inputs)?
    .with_output_tree_id(tree_id)
    .with_expiry(now + 600)
    .encrypt(&keys)?;
let request = MergeProofRequest::new(merge, &keys)?;
let signature = request.prove_and_send_sync(&client, &fee_payer)?;
```

`with_output_tree_id` is required in practice: without it the merged UTXO is
appended to tree 0. Pass the inputs' tree, or the tree the indexer names for
new outputs when that one is full or paused.

`fetch_and_prove_sync(&client, payer)` checks the owner's record
(PoseidonCtrV1 selected, matching keys), fetches the input proofs and generates
the merge proof while the blockhash request runs. It returns `UnsignedMessage`
with a compute-unit limit of `MERGE_CU_LIMIT` and leaves Groth16 verification
to the program. The async counterpart is `fetch_and_prove`.

For custom composition, call `fetch_record` and `fetch_input_proofs`, then the
synchronous `build`, the async `prove`, and synchronous `with_proof`. The
blocking fetch and prove methods have `_sync` counterparts. The resulting
`ProvedMerge` is reusable with any payer: `proved.instruction(payer)` builds
its instruction and `proved.build_solana_message(payer, blockhash, height,
compute_budget)` builds an unsigned message.

`MergeKeys` provides the shielded address, derivations, and proof-input
completion needed for merging. `ShieldedKeypair` implements it directly.
`LocalMergeKeys::new(address, nullifier_key)?` validates callers' separate
keys. The registry owner is derived from the address's signing public key.
Set an expiry: anyone holding the proof can submit it until then.
`MergeProofRequest::with_prover` selects an in-process prover when the merge
inputs should stay on the device.

## In process: litesvm

Any indexer serves a client. A blocking one answers the indexer half of
`Rpc` and implements `WitnessReader`, which has a default over `Rpc`:
`impl WitnessReader for MyIndexer {}`. `spr_program_test::SprProgramTest`
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
`with_proof_data_source(ProofDataSource::Client)`. Every prover URL, including
the Helius API, submits to `/prove/<key>`, polls `/prove/<key>/status`, and
uses `/prove/<key>/indexed` for prover-fetched data. Prover fetching remains
the default for every host. The Helius deployment must activate these REST
routes, pools and TEE header forwarding; the SDK does not infer capabilities
from the hostname. The setting lives on
`ProverClient` and `AsyncProverClient`. The `SprClient` method sets it on
the requests it makes; a custom in-process prover receives the data
fetched by the client. Custom-ring proof environments read it from the prover
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
its original public statement before returning
transaction data. `IndexerRpcConfig.require_slot` sets the minimum indexer
context slot for `SprClient` transactions; `UtxoScan::with_indexer_config`
applies it to wallet discovery, so a spend another client just made is read.
Wallet discovery and chain account reads still use the SDK's configured services.

`UtxoScan` discovers registered SPL assets by default. The caller supplies
its registry on each fetch and can reuse the scanner after extending it:

```rust
let scanner = UtxoScan::new(&keys)
    .with_indexer_config(IndexerRpcConfig::at_slot(confirmed_slot));
let scan = scanner.fetch(&client, &assets)?;
assets.extend(&scan.asset_registry)?;
```

Use `disable_asset_discovery()` to restrict scanning to the supplied registry.
`AssetRegistry::extend` accepts identical mappings and rejects conflicts
atomically.

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
the scan.
`unresolved_outputs` identifies each unresolved output by transaction,
event index, output slot and output context. Reasons distinguish unknown asset
IDs or mints, decryption failures, framing errors, unsupported encodings and
commitment mismatches. Discovery reprocesses the diagnostics, so resolved
outputs disappear from them. An undecryptable candidate may be another
recipient's output or published padding; it does not establish ownership.
Key-provider failures remain scan errors.

Custom `Rpc` implementations must support
`get_program_accounts_filtered`, including its minimum context slot; discovery
never falls back to an unfiltered or stale program listing.

`IndexedTransferPreparation` selects confidential, ring, ring-authority or
anonymous EdDSA authorization. `IndexedMergePreparation` supports both merge rails and
cache outputs. Pass the prepared request to `prove_indexed`, which checks the
returned roots and returns transaction data; the program verifies the proof. A ring merge
returns `ProvenIndexedMerge::Ring`.

Ring proof builders expose `build`; the encoders in `prover::requests`
produce requests accepted by `Prover::prove` or `AsyncProverClient::prove`.

Transfer, merge and indexed ring policy requests prefer a proof in the HTTP
response. A capacity rejection can retry through the queue when Redis is
available. Indexed deposit audits use synchronous delivery. Forester batch
proofs use queued delivery.
