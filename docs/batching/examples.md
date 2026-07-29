# Batching examples

How to use batching well — and what not to do. Every path below is runnable
code, not a sketch.

## SDK surface

| Layer | Entry point | Use it for |
| --- | --- | --- |
| App | `zolana_client::plan_batch_transact` | Validate N `TransactIxData` entries and decide batched vs solo by measured transaction size |
| App | `ZolanaClient::send_batch_transact_sync` | Plan and submit in one call |
| Wallet | `zolana_wallet::create_batch_transfer_sync` | Build N pure-shielded transfers with same-tree and no-UTXO-overlap checks |
| Wallet | `zolana_wallet::build_batch_private_transaction_sync` | Sign, prove, and wrap the entries per the size plan |
| Raw | `zolana_interface::instruction::BatchTransact` | Hand-built entries (custom protocols) |

The plan is size-gated: it returns one `BatchTransact` instruction when the
serialized transaction fits a 1232-byte packet, and N solo `Transact`
instructions when it does not. Callers are never worse off than solo
submission.

## When batching engages

- **Compact app entries fit today.** (1,1) entries without inline ciphertexts
  batch at N=2 (~950-byte transaction) and save a measured **13.6%** CU
  ([measured.md](./measured.md)).
- **Standard wallet transfers do not fit at N=2.** Every wallet-built output
  carries a length-matched ciphertext: a (2,3) transfer entry measures
  773 bytes and the N=2 batch probe 1831 bytes (`just
  test-client-batch-example`), so the plan API falls back to solo
  automatically. Larger packets (SIMD-0296) change this.
- The program caps a batch at `MAX_BATCH_TRANSACT` (4) entries; entry count
  above 2 needs larger packets for complete bodies anyway.

## Do: batch payout through the client SDK

`sdk-tests/client/examples/batch_transfer.rs` (`just test-client-batch-example`):
Alice deposits two UTXOs, builds one transfer per recipient, proves each entry
with `client.prove_transact`, and submits through
`send_batch_transact_sync`. The example prints the plan decision and the
measured sizes; both recipients decrypt their balances whichever branch runs.

## Do: dapp policy + `BatchTransact` CPI (the sanctioned app pattern)

`sdk-tests/batch-payout/` — a minimal program that checks an admin config PDA
and then CPIs shielded-pool `BatchTransact` with the forwarded entries:

```text
batch-payout PAYOUT
  → require admin signature (app policy, no app proof)
  → CPI shielded-pool BatchTransact   // one same-vk RLC over N entries
```

The app proof never enters the fold. The e2e
(`cargo test -p batch-payout-test`) builds compact (1,1) entries with
proofs from public SDK crates only, so it doubles as copy-paste material for
custom protocols.

## Do: same-vk nullifier many (forester)

N address-append proofs under one VK, one `BatchUpdateNullifierTreeMany`.
Measured **22.5%** CU saving at N=2 ([measured.md](./measured.md)). Runnable:
`nullifier_tree_many_executes_n2` in
`program-tests/shielded-pool/tests/batch_dual_cu.rs`.

## Do: legacy swap take (correct product path)

One app take proof (solo verify in the swap program) + SPP `Transact` CPI. Do
**not** replace this with a compose/RLC twin for compute; measured duals were
slightly worse: [no-boost.md](./no-boost.md).

## Don’t: mixed-key k=2 for CU

```text
// Anti-pattern — removed from sdk-tests examples
MAKE_BATCH / TAKE_BATCH / CANCEL_BATCH
  → pack foreign VK account
  → compose hub (foreign + spp)      // one RLC, k=2 — removed with the twins
```

The RLC pays multi-VK structure and the cheap app proof does not amortize.
Atomicity alone is not a reason to pay more CU on the hot path.

## Don’t: BSB22 on the batch rail

Committed / Pedersen proofs (`take_ve`) stay on solo verify. Batch fold rejects
committed VKs.

## Localnet note

The shielded-pool binary links the BN254 batch syscalls. A stock
`solana-test-validator` rejects it at load. Localnet recipes default to the
pinned agave build (`../agave/target/release/solana-test-validator`) via
`ZOLANA_TEST_VALIDATOR_BIN`; see `third-party/agave-bn254/README.md`.

## Checklist before adding a new batch twin

1. Same VK? If no → stop (mixed-key k=2 is no-boost unless re-measured).
2. N ≥ 2?
3. Dual full-path CU vs best legacy: **≥10%**?
4. Packet size @1232 (or explicit 4096-sim label)?
5. Docs: add a row to [measured.md](./measured.md); link from [README](./README.md).
