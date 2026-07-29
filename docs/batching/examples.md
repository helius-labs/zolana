# Batching examples

How to use batching well — and what not to do.

## Do: same-vk `BatchTransact` (N=2)

Two pure-shielded transfers, **same circuit**, one verify.

```rust
// Sketch: builders and account lists follow zolana_interface.
// Both bodies: pure shielded, identical circuit tag, no interface_transfers.

use zolana_interface::instruction::BatchTransact;

let ix = BatchTransact {
    // fee payer, tree accounts, … same as multi pure-shielded layout
    entries: vec![transact_body_a, transact_body_b],
}
.instruction(/* accounts */);
```

**Checks the program enforces for you:**

- `count ∈ 1..=MAX_BATCH_TRANSACT` (currently 4)
- every entry same `circuit`
- no public settlement legs in a batch entry

**Size:** N=2 fits comfortably under 1232 (measured ~741 legacy / ~715 v0+ALT). N=4 is tight (~1201 / ~1175).

**CU:** only claim a win after a dual full-path bench ≥10% vs two solo `Transact`s. Until then treat this as atomic multi-apply + shared verify path.

Runnable size packing: `cargo test -p zolana-groth16-batch --test matrix_measure -- --nocapture`.

Runnable e2e with proofs: `batch_transact_executes_n2` and
`nullifier_tree_many_executes_n2` in
`program-tests/shielded-pool/tests/batch_dual_cu.rs` (needs `just build-programs`).

## Do: same-vk nullifier many (forester)

```rust
// N proofs under the address-append VK, one BatchUpdateNullifierTreeMany (or
// equivalent builder). Prefer N=2 or 4 under today's 1232 packet limit.
// N=8/16 need larger-tx sim or future packet limits for size — CU can still
// be measured independently of network acceptance.
```

Measured sizes: [same-vk-batch.md](./same-vk-batch.md).

## Do: legacy swap take (correct product path)

One app take proof (solo verify in the swap program) + SPP `Transact` CPI. This is the supported make/take/cancel shape.

```text
swap TAKE
  → verify take Groth16 (app VK)
  → CPI shielded-pool Transact (SPP VK)
```

Do **not** replace this with a compose/RLC twin for compute. Measured duals were slightly worse: [no-boost.md](./no-boost.md).

## Don’t: mixed-key k=2 for CU

```text
// Anti-pattern — removed from sdk-tests examples
MAKE_BATCH / TAKE_BATCH / CANCEL_BATCH
  → pack foreign VK account
  → compose hub (foreign + spp)      // one RLC, k=2 — removed with the twins
```

Why it fails the ≥10% bar: RLC pays multi-VK structure; the cheap app proof does not amortize. Atomicity alone is not a reason to pay more CU on the hot path.

If you need single-transaction atomicity across two proof systems without a CU claim, that is a product decision — document it as such, not as “batching savings.”

## Don’t: BSB22 on the batch rail

Committed / Pedersen proofs (`take_ve`) stay on solo verify. Batch fold rejects committed VKs.

## Future (document only)

| Idea | Status |
| --- | --- |
| N=8/16 nullifier many under 4096 packets | Size table exists (4096-sim); not a mainnet claim |
| Operator same-vk stuffing, two-phase enqueue/execute | Design: [proof-batching-programming-models.md](../alt-designs/proof-batching-programming-models.md) Model B |
| Multi-order same-vk **app-only** RLC (no SPP in the fold) | Not measured; only consider if a dual clears ≥10% |

## Checklist before adding a new batch twin

1. Same VK? If no → stop (mixed-key k=2 is no-boost unless re-measured).
2. N ≥ 2?
3. Dual full-path CU vs best legacy: **≥10%**?
4. Packet size @1232 (or explicit 4096-sim label)?
5. Docs: add a row to [measured.md](./measured.md); link from [README](./README.md).
