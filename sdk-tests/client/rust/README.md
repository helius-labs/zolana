# Rust client example

[`deposit_transfer_withdraw.rs`](deposit_transfer_withdraw.rs) shows the
instruction-level Rust flow to deposit SOL into a private balance, transfer
between private balances, and withdraw from a private balance to a public
balance.

It walks the eight steps of
[`sdk-libs/transaction/README.md`](../../../sdk-libs/transaction/README.md),
which is where each step is described in full. The transfer and the withdrawal
are the same eight steps twice; the deposit is public, so it skips straight to
building an instruction.

## Flow

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

## Run

From the repository root:

```bash
just test-client-example
```

The command starts the validator, Photon, and prover, then runs the example.
