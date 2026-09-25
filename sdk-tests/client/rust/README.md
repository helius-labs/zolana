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

```text
t+  0.000s  merge proof requested
t+  1.102s  merge proof ready
t+  1.625s  merge transaction confirmed
t+  1.748s  merged output indexed, transfer proof ready
t+  2.262s  transfer transaction confirmed
```

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

The run prints its own timeline, which is where the ordering shows up:

```text
t+  0.000s  merge and transfer proofs requested
t+  0.061s  transfer proof ready
t+  1.131s  merge proof ready
t+  1.652s  merge transaction confirmed
t+  1.652s  cache slot 0 holds the merge output
t+  2.168s  transfer transaction confirmed
```

Helpers keep both examples down to their flow. `src/merge.rs` holds what they
share: the timeline log, the merge proof packing, and the `assert_*` checks.
`src/cached_merge.rs` holds the cache-specific parts: `assemble_cached_transfer`
fetches the nullifier proofs for a spend whose input names its cache slot with
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
