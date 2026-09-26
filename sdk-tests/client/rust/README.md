# Rust client examples

## Deposit, transfer, withdraw

[`deposit_transfer_withdraw.rs`](deposit_transfer_withdraw.rs) shows the
instruction-level Rust flow to deposit SOL into a private balance, transfer
between private balances, and withdraw from a private balance to a public
balance.

It walks the eight steps of
[`sdk-libs/transaction/README.md`](../../../sdk-libs/transaction/README.md),
which is where each step is described in full. The transfer and the withdrawal
are the same eight steps twice; the deposit is public, so it skips straight to
building an instruction.

### Flow

1. **Sync balances.** Fetch the sender's transactions by view tag,
   `get_shielded_transactions_by_tags`, and decrypt them, `decrypt_transactions`.
   Each note comes back as a `SpendableUtxo` carrying its commitment, its
   nullifier, its tree id and leaf index, and the slot it was published in. An
   `IndexerRpcConfig::at_slot` gate makes the read wait for the transaction
   just sent.
2. **Select input UTXOs.** Pick from the decrypted balance and convert with
   `SppProofInputUtxo::from`, a field move that needs no key because step 1
   already computed everything the proof hashes.
3. **Create output UTXOs.** The shape fixes both slot counts, so the inputs are
   padded to it with `pad_input_utxos` before `ConfidentialTransaction::new`
   opens on them. Then `transfer` or `withdraw`, then `pad_output_utxos` fills
   the free output slots once the change and the recipient are known.
4. **Encrypt.** `encrypt` produces the ciphertexts, the external data hash and
   the private transaction hash in one call.
5. **Prove.** `prove_transact` fetches the witnesses and returns
   `TransactIxData`.
6. **Build.** `Transact { .. }.instruction()`.
7. **Sign.** The fee payer signs; the sender proves ownership as a Solana
   signer.
8. **Submit and confirm.** `create_and_send_transaction`, then read the landed
   slot for the next sync's freshness gate.

Every line prefixed `// SPL:` is the SPL-token variant of the line above it.

### Run

From the repository root:

```bash
just test-client-example
```

The command starts the validator, Photon, and prover, then runs the example.

## Merge and transfer

[`merge_transfer.rs`](merge_transfer.rs) spends a balance that is spread over
more UTXOs than one transaction can take, the direct way: merge, then transfer
the merged output. The transfer proves its input against a Merkle path, so it
cannot be built until the merge has landed, the merged output has been appended
to the tree, and the indexer has served a proof for it.

Two actors: the **sender** owns the UTXOs and signs the transfer, and the
**merge payer** pays for and sends the merge. The sender signs no merge: its
registry record opted into merging, so any caller may merge for it.

### Flow

1. Detect that 36 UTXOs cannot be spent in one transfer.
2. Build the merge proof inputs.
3. Prove and send the merge.
4. Build the transfer over the merged output; `prove_transact` polls the
   indexer for the output's Merkle proof and only then proves.
5. Send the transfer.

Each stage prints as it ends. The run closes with two tables, every stage with
its start, end, and duration, and every prover request with its round trip and
the stage spans the prover reports.

### Run

From the repository root:

```bash
just test-client-example-merge-transfer
```

## Optimized merge and transfer

[`optimized_merge_transfer.rs`](optimized_merge_transfer.rs) removes the
indexer round trip above. The merge writes its output commitment into a cache
PDA, and the transfer proves that input against the cache, so the transfer
proof is generated concurrently with the merge proof rather than after it.

Two actors: the **sender** owns the UTXOs and signs the transfer, and the
**rent sponsor** funds the cache, is its write authority, and sends the merge.
The sender signs no merge: its registry record opted into merging, and the
cache's write authority decides which outputs reach its slots. The transfer
proof still proves the sender owns every input it draws from the cache.

### Flow

1. Detect that 36 UTXOs cannot be spent in one transfer.
2. Build the merge proof inputs for one slot of one cache account, and the
   transfer proof inputs from the merge's predicted output.
3. Prove the merge and the transfer concurrently.
4. Send the merge, with the idempotent cache creation in the same transaction.
5. Wait for the commitment to appear in the cache slot the transfer committed
   to.
6. Send the transfer, spending the merged output straight out of the cache, and
   close the cache to refund the rent sponsor.

Step 2 works because the merged output's blinding is derived rather than
random: the client knows the output commitment before the merge is submitted.

The run prints the same stage and prover tables, and the ordering shows up in
them: the transfer proof ends long before the merge lands.

Helpers keep both examples down to their flow. `src/merge.rs` holds what they
share: the `Timeline`, `MergeRequest` for proving a merge by either proof data
route, and the `assert_*` checks. `src/cached_merge.rs` holds the cache-specific
parts: `CachedTransfer` proves a spend whose input names its cache slot with
`with_cache_slot` and whose proof inputs name the cache with `with_read_cache`,
and `wait_for_cache_commitment` polls the account. The SDK derives the cache
selection itself, and because every input of the transfer's tree is cached or
padding, it publishes no state root for that tree.

### Run

From the repository root:

```bash
just test-client-example-optimized-merge-transfer
```

The `merge_36_1` proving key is 240 MB and the prover loads it on the first
request, so a cold run pays that load once.

### What the two timelines do and do not show

On localnet the totals are close, 2.26s sequential against 2.17s cached, because
the tree holds a handful of leaves and Photon runs on the same machine: the
indexer round trip the cache removes measures about 120ms here. Two things widen
the gap in production. The indexing wait grows with tree depth and indexer load,
and the transfer proof grows with its shape -- a wide transfer proof costs
seconds, and in the cached flow all of it overlaps the merge proof instead of
following it.

## Measure against a deployed prover

Both merge examples also run against an existing deployment, where the numbers
include a real network and a real cluster. The programs and the tree must already
exist there.

```bash
ZOLANA_EXAMPLE_PAYER=~/devnet-payer.json \
ZOLANA_RPC_URL=https://RPC \
ZOLANA_INDEXER_URL=https://INDEXER \
ZOLANA_PROVER_URL='https://PROVER?api-key=KEY' \
ZOLANA_PROOF_DATA_SOURCE=prover \
  cargo run -p client-example --example optimized_merge_transfer
```

- `ZOLANA_EXAMPLE_PAYER` names a funded keypair file. Setting it selects this
  mode. The payer funds a fresh sender and rent sponsor and gets back what they
  hold when the run exits, after an error or a panic too. A failure during setup
  or a killed process strands those funds, a cache left open keeps its rent, and
  the deposits always stay in a private balance whose keys the run discards.
- `ZOLANA_PROOF_DATA_SOURCE` is `prover`, the default, where the prover
  fetches the Merkle data from its own indexer, or `client`, where the example
  fetches it. The prover route needs a prover started with an indexer.
- `ZOLANA_TREE_ID` selects the tree, `0` by default.
- The prover table shows server spans only from a prover started with
  `PROVER_REQUEST_TIMING=true`. Without it the table shows round trips alone.

