# zolana-transaction

UTXO serialization and private transaction construction: the encrypted and
plaintext UTXO layouts, the builder that turns input and output UTXOs into a
balanced transaction, and the hashes and proof inputs a prover consumes.

The crate holds no state and performs no IO. Fetching transactions and proofs is
`zolana-client`; wallet state and sync orchestration are `zolana-wallet`.

Steps marked ***(tvc)*** need key material. The rest run on values. The flow
below describes the intended API; the Status section lists the remaining
implementation differences.

## Transaction flow

1. **Sync Balances**
    1. request encrypted UTXOs from the indexer by view tag,
       `ZolanaClient::get_shielded_transactions_by_tags` ***(client)***
    2. decrypt them, `Tvc::decrypt` ***(tvc)*** or `decrypt_transactions` when
       the keypair is local, into `SpendableUtxo`s: commitment, nullifier, raw
       tree id, leaf index, asset id, slot, and signature. The indexer reports
       the tree id with the slot, and decryption checks it by recomputing the
       commitment under it; the tree account is `pda::tree(tree_id)` wherever
       one is needed.
    3. drop notes whose nullifier is already published ***(client)***: within a
       batch from the nullifier lists it contains, which is all
       `decrypt_transactions` uses, across batches through
       `get_shielded_transactions_by_nullifiers`
    4. **result:** unspent UTXOs as values

2. **Select Input UTXOs (Client)**

    Selection defines what the transaction spends and stays open to custom
    selection and merging strategies and to PDA-owned UTXOs with data. It is an
    iterator over the notes from step 1; only 2.4 is a call.

    1. filter by asset, spend tree, and eligible kind, skipping the zero-amount
       notes that padding and empty change leave behind
    2. sort largest first
    3. take UTXOs until the amount is covered, within the supported input count
    4. convert each to an `SppProofInputUtxo`, `SppProofInputUtxo::from`, a
       field move that takes no key. Dummies and UTXOs the indexer did not
       return go through `SppProofInputUtxoParams`, which applies the key last.
    5. **result:** list of `SppProofInputUtxo`, each with its commitment and
       nullifier

3. **Create Output UTXOs (Client)**

    Outputs define what the transaction produces: custom program logic, and
    multi-transfer, withdrawal, or deposit flows.

    1. instantiate from the input UTXOs and fee payer,
       `ConfidentialTransaction::new`
    2. add outputs directly, or through `transfer`, `withdraw`, and `deposit`,
       which declare the private and public transfers to balance
    3. optionally pin the sender rail and the output tree, `with_sender_rail`,
       `with_ring_program_id`, `with_output_tree_id`
    4. optionally choose a supported shape, calculate change, and pad the slots
       explicitly
    5. **result:** a configurable `ConfidentialTransaction`

4. **Encrypt Output UTXOs**

    `ConfidentialTransaction::encrypt` consumes the builder, completes any
    preparation the caller omitted, and returns an immutable transaction for
    authorization and proving. Preparation supplied earlier must still agree
    with the builder contents; a conflict is an error.

    1. complete preparation ***(client)***
        1. net public amounts per asset, calculate missing SOL and SPL change,
           and determine the required output count
        2. choose a supported shape that fits both sides, or validate the
           caller's; not every input/output combination has one
        3. pad both sides, validate balance, and fix slot order and tree
           assignment: group inputs by tree, real input first, and build each
           input dummy for its assigned tree. Output padding creates
           zero-amount sender-owned notes.
        4. take the first nullifier from the final input order; it seeds the
           output blindings and the transaction viewing key
    2. derive the slot values ***(client)***
        1. derive each output's blinding from one seed, the nullifier fixed in
           4.1, and the slot's final position
        2. compute each output's commitment and owner tag
    3. encrypt ***(tvc)***
        1. derive the transaction viewing key from the first nullifier
        2. take the caller's salt (`random_salt`, or a constant in a fixture)
        3. encrypt each slot to the owner it already names, attaching that
           owner's view tag
    4. hash the external data, `ExternalData::hash` ***(client)***
        1. serialize the filled slots with their owner tags, the transaction
           viewing pubkey, the salt, and the interface transfers
        2. append the settlement accounts and the resolved owner tags
        3. the Solana program recomputes this hash from the instruction data
           and accounts
    5. hash the private transaction, `PrivateTxHash::new(..).hash()`
       ***(client)***
        1. input commitments from step 2 and output commitments from 4.2: zero
           for circuit dummy slots, the real commitment for sender-owned
           zero-value outputs
        2. the external data hash
        3. the private transaction blinding, derived from the first nullifier
           and the seed. It stays private, so the published hash cannot be
           tested against guessed inputs.
    6. **result:** an immutable transaction with every slot filled, its
       commitments, `external_data_hash`, and `private_tx_hash`, which the
       proof covers and the transact instruction publishes

5. **Prove (TVC)**

    `ZolanaClient::prove_transact`

    1. on the P-256 rail, sign `sha256(private_tx_hash)` as the authorization,
       `Tvc::sign_p256`. The transact rail authorizes through the Solana signer
       in step 7 instead.
    2. send the input commitments; the prover fetches the state-inclusion and
       nullifier non-inclusion witnesses itself
    3. assemble the witness and request the proof,
       `ProverClient::prove_transact`; the nullifier key enters here
    4. verify the proof locally, `verify_confidential_transfer_inputs`
    5. compress it for the Solana program, `ProofCompressed::to_transact_proof`
    6. **result:** `TransactIxData`

6. **Build Transaction (Client)**
    1. validate the settlement accounts against the interface transfers,
       `SettlementAccountValidation`
    2. build the transact instruction with payer, trees, owner signers,
       settlement accounts, proof, and data, `Transact::instruction`
    3. set the compute budget in the v1 message header, `ComputeBudgetConfig`,
       applied by `compile_message`
    4. fetch the latest blockhash, after proving
    5. **result:** unsigned Solana transaction

7. **Sign (Client)**
    1. fee payer signs the Solana transaction, `sign_transaction`
    2. each distinct input owner signs on the Ed25519 rail
    3. **result:** signed Solana transaction

8. **Submit and Confirm (Client)**
    1. send the transaction, `Rpc::create_and_send_transaction`
    2. wait for Solana confirmation
    3. wait for the indexer, `ZolanaClient::confirm_private_transaction`;
       `IndexerRpcConfig::at_slot` then gates the next sync
    4. **result:** confirmed transaction visible to the next sync

Split and merge are intended to follow the same lifecycle: a builder consumed
by `encrypt`, then authorization, proving, and submission.

## Construction invariants

An input's commitment and nullifier must agree with its UTXO fields, tree id,
and data hashes. Build through `SppProofInputUtxoParams` or convert from a
verified `SpendableUtxo`, and do not modify the committed fields afterwards. A
padding input that changes tree must be rebuilt, for example with
`dummy_with_blinding`; a real input must keep describing its existing tree leaf.

The builder stays configurable until `encrypt` consumes it. `encrypt` fixes the
first input nullifier and every output position before deriving blindings, then
produces ciphertexts, commitments, and hashes that agree. The returned
transaction must prevent mutation of those values and their nested inputs and
outputs; consuming the builder does not enforce that while the returned fields
stay public.

## Status

`SppProofInputUtxo` holds no key material, decryption returns a `SpendableUtxo`
that converts into one by moving fields, and `ProofAuthority` completes the
witness with the nullifier secret before proving. The remaining differences from
the flow above:

- `ConfidentialTransaction::new` still requires a shape and inputs padded to it,
  and callers must call `pad_output_utxos` before `encrypt`. Automatic
  completion of omitted preparation is not implemented.
- `encrypt` stores output commitments in `external_data.outputs` but returns the
  ingredients for both hashes rather than the hashes; `message_hash` and witness
  assembly recompute the commitments from the output UTXOs.
- `SpendableUtxo`, `SppProofInputUtxo`, and `SppProofInputs` still expose public
  mutable fields, so nothing enforces the immutability above.
- `PrivateTxHash::new` has two call sites: `spp_proof_inputs.rs`, which builds
  its vectors from the output UTXOs and their dummy flags, and
  `assembly::private_tx_hash`, which every prover rail goes through.
- Merkle witnesses are still fetched by the client rather than the prover.
- Split and merge still use `prepare`/`finalize`.
