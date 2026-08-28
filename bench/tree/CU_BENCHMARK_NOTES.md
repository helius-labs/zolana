# Tree CU Benchmark -- Notes

Analysis notes for `CU_BENCHMARK.md`. That file is regenerated (truncated and
rewritten) by `just bench-tree`, so notes live here instead.

## Nullifier insert: why x10 is not 10x x1

The cost is not linear because the first insert into a hash chain is a special
case. In `Batch::add_to_hash_chain`
(`program-libs/batched-merkle-tree/src/batch.rs`), the first insert
(`num_inserted == 0`) stores the value directly into the hash-chain slot, while
every later insert combines it with `Poseidon::hashv([existing, value])`.
Each insert also pays a fixed amount of base work (canonical field check, queue
position check, hash chain insert). The current queue-only measurements are 391
CU for the first insert and 11,398 CU for ten inserts, or about 1,223 CU for
each subsequent Poseidon-backed insert. Nullifier marker PDA creation happens
in the shielded-pool program, not in this crate, and is measured by the
shielded-pool program benches.

```
total(N) ~= 391 + (N - 1) * 1,223
total(10) = 391 + 9 * 1,223 = 11,398
```

`num_inserted` resets when a zkp batch fills, so the first insert of each zkp
batch is again the cheap no-Poseidon case.

## Address tree batch update x120

Worst-case finalize transaction for the changelog-based address-append update
(`update_tree_from_address_queue`). Foresters submit proofs for zkp-batch
indices `1..=119` first; each caches a `ChangelogEntry` and applies nothing
because index 0 is still missing. The measured transaction submits index 0: it
verifies that one proof, caches it, then applies all 120 contiguous cached
entries in a single cascade.

The post-change profile was regenerated with `just bench-tree` on 2026-08-28
and reports two functions:

- `apply_cached_tree_updates` (19,978 CU): the 120-entry cascade, ~166 CU
  per applied zkp batch. Each apply advances `next_index`, appends a root to the
  root-history ring, marks the zkp batch inserted, and clears its cached update.
  The final apply advances `close_before_index` from the completed batch's start
  index; no root-history slots or bloom-filter slices are zeroed. The cascade
  re-verifies no proofs; the submit path already did.
- `bench_batch_address_update` net (96,047 CU): the index-0 submit path,
  dominated by the single Groth16 proof verification (alt_bn128 pairing).

Total is 116,025 CU, well under the 1.4M per-transaction limit, so a backlog of
120 zkp batches applies in one transaction.

The benchmarked tree uses `zkp_batch_size = 10` (`batch_size = 1200`,
`ZKP = 120`) rather than the production address-tree `zkp_batch_size = 250`,
because only the `batch_address-append_40_10` proving key is available locally.
The root history is sized to production (`RH = 120`), exactly one batch of ZKP
update roots, so a fully applied successor naturally overwrites all older roots.
