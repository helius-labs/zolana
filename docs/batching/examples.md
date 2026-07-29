# Batching examples

How to use batching well, and what not to do. Every path below is runnable
code.

## SDK surface

| Layer | Entry point | Use it for |
| --- | --- | --- |
| App | `zolana_client::plan_batch_transact` | Validate N `TransactIxData` entries and decide batched against solo by the measured transaction size |
| App | `ZolanaClient::send_batch_transact_sync` | Plan and submit in one call |
| Wallet | `zolana_wallet::create_batch_transfer_sync` | Build N pure-shielded transfers with same-tree and no-UTXO-overlap checks |
| Wallet | `zolana_wallet::build_batch_private_transaction_sync` | Sign, prove, and wrap the entries per the size plan |
| Raw | `zolana_interface::instruction::BatchTransact` | Hand-built entries for custom protocols |

The plan has a size gate. It returns one `BatchTransact` instruction when the
serialized transaction fits a 1232-byte packet. It returns N solo `Transact`
instructions when it does not. Callers never do worse than solo submission.

## When batching engages

- Compact app entries fit today. (1,1) entries without inline ciphertexts
  batch at N=2 in a transaction of about 950 bytes and save a measured 13.6%
  CU ([measured.md](./measured.md)).
- Standard wallet transfers do not fit at N=2. Every wallet-built output
  carries a length-matched ciphertext. A (2,3) transfer entry measures
  773 bytes and the N=2 batch probe 1831 bytes
  (`just test-client-batch-example`), so the plan falls back to solo. Under a
  4096-byte packet the wallet shape saves a measured 12.4% at N=2 and 21.7% at
  N=4 ([measured.md](./measured.md)).
- The program caps a batch at `MAX_BATCH_TRANSACT` (4) entries.

## Batch payout through the client SDK

`sdk-tests/client/examples/batch_transfer.rs` (`just test-client-batch-example`).
Alice deposits two UTXOs, builds one transfer per recipient, proves each entry
with `client.prove_transact`, and submits through `send_batch_transact_sync`.
The example prints the plan decision and the measured sizes. Both recipients
decrypt their balances on either branch.

## Dapp policy plus a `BatchTransact` CPI

`sdk-tests/batch-payout/` is a minimal program that checks an admin config PDA
and then CPIs shielded-pool `BatchTransact` with the forwarded entries:

```text
batch-payout PAYOUT
  -> require the admin signature (app policy, no app proof)
  -> CPI shielded-pool BatchTransact   // one same-vk RLC over N entries
```

The app proof never enters the fold. The e2e
(`cargo test -p batch-payout-test`) builds compact (1,1) entries with
proofs from public SDK crates only, so custom protocols can copy it.

## Same-vk nullifier many (forester)

N address-append proofs under one key, one `BatchUpdateNullifierTreeMany`.
Measured 22.5% CU saving at N=2 ([measured.md](./measured.md)). Runnable:
`nullifier_tree_many_executes_n2` in
`program-tests/shielded-pool/tests/batch_dual_cu.rs`.

## Legacy swap take (correct product path)

One app take proof (solo verify in the swap program) plus an SPP `Transact`
CPI. Do not replace this with a compose or RLC twin for compute. The measured
duals were worse: [no-boost.md](./no-boost.md).

## Do not: mixed-key k=2 for CU

The RLC pays the multi-key structure and the cheap app proof does not
amortize. Atomicity alone is not a reason to pay more CU on the hot path.
Numbers: [no-boost.md](./no-boost.md).

## Do not: BSB22 on the batch rail

Committed and Pedersen proofs (`take_ve`) stay on solo verify. The batch fold
rejects committed keys.

## Localnet note

The shielded-pool binary links the BN254 batch syscalls. A stock
`solana-test-validator` rejects it at load. Localnet recipes default to the
pinned agave build through `ZOLANA_TEST_VALIDATOR_BIN`. Setup:
`third-party/agave-bn254/README.md`.

## Checklist before a new batch path

1. Same verifying key? If no, stop. Mixed-key k=2 is no-boost.
2. Two or more proofs?
3. Does a full-path dual clear the 10% gate?
4. Does the transaction fit 1232 bytes, or is the row labeled as a 4096 size
   simulation?
5. Add a row to [measured.md](./measured.md) and link it from the
   [README](./README.md).
