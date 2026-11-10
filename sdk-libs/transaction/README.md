# spr-transaction

UTXO serialization and private transaction construction: the encrypted and
plaintext UTXO layouts, the builder that turns input and output UTXOs into a
balanced transaction, and the hashes and proof inputs a prover consumes.

The crate holds no state and performs no IO. Fetching transactions, proving and
submitting are `spr-client`. A wallet syncs by fetching the transactions for its
tags and decrypting them (step 1); the SDK keeps no wallet state.

Key material stays behind two traits. `ShieldedKeys` (this crate) answers
decryption, nullifier and transaction-viewing-key requests and returns results,
not keys; `ShieldedKeypair` and `LocalShieldedKeys` implement it in process.
`ProofAuthority` (`spr-client`) puts the nullifier secret into the witness just
before proving. Every other step runs on values.

## Transaction flow

```rust
let scan = UtxoScan::new(&keypair, &assets)
    .with_indexer_config(IndexerRpcConfig::at_slot(confirmed_slot))
    .fetch(&client)?;
let inputs = select_spend(scan.spendable.utxos(), mint, amount)?;
let mut transaction = ConfidentialTransaction::new(inputs, fee_payer.pubkey())?;
transaction.transfer(&recipient, mint, amount)?;
let signed = SignedPrivateTransaction {
    transaction: transaction.encrypt(&keypair)?,
    settlement_transfers: Vec::new(),
};
let signature = Submission::new(&signed, fee_payer.pubkey(), &keypair)
    .send_sync(&client, &[&fee_payer])?;
```

1. **Sync balances**

    `UtxoScan::fetch` (`spr-client`) does this step; by hand it is:

    1. request the transactions by view tag,
       `get_shielded_transactions_by_tags`, as `ShieldedTransaction`s
    2. decrypt them, `decrypt`, into a `DecryptionResult` of candidate
       `WalletUtxo`s: the note, its commitment, nullifier, tree id, leaf
       index, slot and signature. Decryption checks nothing yet; the tree
       account is `pda::tree(tree_id)` wherever one is needed.
    3. verify them, `verify_spendable`: keep the notes the keys own whose
       commitment recomputes under their tree id, derive each nullifier again
       and drop the notes spent within the batch. `decrypt_spendable` runs 1.2
       and 1.3. Spends in other transactions come from
       `get_shielded_transactions_by_nullifiers`, which `UtxoScan` follows
       until a round finds nothing new.
    4. **result:** a `SpendableDecryptionResult`: per-asset `balances` and the
       ring- or data-bearing `utxos_with_data`. `UtxoScan` also stamps each
       UTXO with the indexer's newest output tree (`latest_tree_id`) and its
       first-spend transaction viewing key (`with_transaction_keys`).

2. **Select input UTXOs**

    `select_spend(spendable.utxos(), asset, amount)` takes default-ring UTXOs of
    one asset, the largest first, until they cover the amount, within
    `MAX_SPEND_INPUTS` inputs and `MAX_INPUT_TREES` trees.
    `select_spend_excluding` leaves out the UTXOs of a spend that is prepared
    but not sent. A balance that needs more inputs or trees is merged first
    (see Merge). Custom selection works on the same `WalletUtxo` values.

3. **Create output UTXOs**

    1. open the builder on the inputs, in the caller's order,
       `ConfidentialTransaction::new(inputs, payer)`. It requires a real input
       in slot 0 and checks each real input's commitment. Variants:
       `new_compact` pads with compact padding, `new_with_ring` builds in a
       custom ring, `new_with_addresses` reserves addresses, and
       `from_proof_inputs` takes `SppProofInputUtxo`s a program SDK assembles
       itself.
    2. add outputs and public transfers: `transfer`, `transfer_sol`,
       `transfer_with_ring`, `deposit`, `deposit_sol`, `withdraw`,
       `withdraw_sol`, `withdraw_to`, or a custom `SppProofOutputUtxo` through
       `add_output_utxo`
    3. optionally pick the output tree, `with_output_tree_id` (default: the
       first real input's `latest_tree_id`, else tree 0), and the accounts
       expected to sign, `with_transaction_signers`, which selects the
       in-proof EdDSA rail for an owner that will not sign
    4. optionally fix the shape, `pad_utxos(shape, &sender)`; otherwise step 4
       picks it
    5. **result:** a configurable `ConfidentialTransaction`

4. **Finalize and encrypt**

    `ConfidentialTransaction::encrypt(&keys)` is `finalize(&sender)` followed
    by `FinalizedTransaction::encrypt_with_keys`.

    1. finalize, keyless, into a `FinalizedTransaction`
        1. calculate change per asset and, unless `pad_utxos` already ran,
           choose the cheapest supported shape that fits, `canonical_shape`;
           not every input/output combination has one
        2. pad without moving existing slots. Change follows the caller's
           outputs in asset first-use order, then dummy outputs. Each dummy
           publishes the view tag of the first input owner other than the fee
           payer, else of a real output owner, the sender first; a transaction
           naming neither keeps a zero-amount SOL change for the sender. Dummy
           inputs follow the real ones. A `new_compact` transaction pads with
           compact padding instead: each padding slot publishes 0, the
           instruction leaves it out, and the transaction reveals its real
           input and output counts.
        3. derive each output's blinding from the first input nullifier, the
           blinding seed and the slot's final position
        4. resolve each output's owner tag and the settlement transfers
    2. encrypt
        1. take the transaction viewing key cached on the first input, or
           request it from `keys` for the first nullifier
        2. draw a fresh salt, `random_salt`
        3. encrypt each real output to the owner it names; a dummy slot carries
           random bytes of a real slot's length, and compact padding carries
           nothing
    3. **result:** `SppProofInputs`: the final input and output slots, the
       blinding seed, output tree, payer, cache accounts and the
       `ExternalData` the instruction publishes, with each output's
       commitment, owner tag and ciphertext. Its hashes are computed from
       these fields:
        - `ExternalData::hash`: the outputs, the transaction viewing pubkey,
          the salt, the interface transfers, the settlement accounts and the
          resolved owner tags. The Solana program recomputes it from the
          instruction data and accounts.
        - `padding_independent_private_tx_hash`: the input and output
          commitments, zero for padding, and the private transaction blinding
          derived from the first nullifier and the seed. Each chain folds only
          its nonzero entries, so padding does not change it, and the blinding
          stays private, so the published hash cannot be tested against
          guessed inputs.
        - `message_hash`: `sha256(private_tx_hash || external_data_hash)`,
          which an owner on the in-proof EdDSA rail signs

5. **Prove**

    `SprClient::prove_transact(proof_inputs, config, &authority)` returns
    `TransactIxData`.

    1. by default the prover fetches the state-inclusion and nullifier
       non-inclusion witnesses itself; `ProofDataSource::Client` fetches them
       in the client
    2. `authority` fills in the nullifier secret of the inputs it owns
    3. the client verifies the proof against the statement it computed and
       compresses it for the program
    4. `prove_transact_confidential_eddsa` proves the in-proof EdDSA rail, with
       the owner signing `message_hash`

6. **Build the transaction**
    1. build the `transact` instruction, `Transact { .. }.instruction()`
       (`spr-instruction`), with the payer, input trees, output tree, owner
       signers (`SppProofInputs::owner_signer_pubkeys`), settlement accounts
       (`withdraw_to` returns them) and the instruction data
    2. compile the v1 message with its compute budget in the header,
       `compile_message` with `ComputeBudgetConfig`, over a blockhash fetched
       beside the proof
    3. **result:** unsigned Solana transaction

7. **Sign**

    `sign_transaction`: the fee payer and each owner signer sign; an owner
    authorized inside the proof does not.

8. **Submit and confirm**
    1. send the transaction
    2. `SprClient::confirm_private_transaction` waits for Solana confirmation
       and for the indexer to index it
    3. pass the landed slot to the next sync, `IndexerRpcConfig::at_slot`
    4. **result:** confirmed transaction visible to the next sync

`Submission` (`spr-client`) runs steps 5 to 8: `send_sync` proves, signs, sends
and confirms, and `finish_unsigned_sync` stops at the unsigned message for a fee
payer whose key lives elsewhere.

## Merge

A merge turns up to `MAX_MERGE_INPUTS` plain UTXOs of one asset on one tree into
one: `select_merge` picks them, `MergeTransaction::new(inputs)` validates them,
and `encrypt(&keys)` returns `MergeProofInputs`, padded with compact padding to
the circuit width the input count selects. `MergeSubmission` (`spr-client`)
proves and submits it; see the [client README](../client/README.md#merging).

## Construction invariants

A `WalletUtxo` converts into an `SppProofInputUtxo` by moving fields, never by
rehashing: its commitment and nullifier are the published values. Construction
checks each real input's commitment against its fields, tree id and data
hashes, but trusts the supplied nullifier. A padding input that changes tree
must be rebuilt, for example with `SppProofInputUtxo::dummy_with_blinding`; a
real input must keep describing its existing tree leaf.

The builder stays configurable until `finalize` consumes it. Finalizing fixes the
first input nullifier and every output position before deriving blindings, so
the ciphertexts, commitments and hashes agree. `SppProofInputs` keeps public
fields, and nothing in the type stops a caller from changing a slot, the output
tree or the external data after encryption and making them disagree.
