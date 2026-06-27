# Tree CU Benchmark -- Notes

Analysis notes for `CU_BENCHMARK.md`. That file is regenerated (truncated and
rewritten) by `just bench-tree`, so notes live here instead.

## Nullifier insert: why x10 is not 10x x1

The cost is not linear because the first insert into a hash chain is a special
case. In `Batch::add_to_hash_chain`
(`program-libs/batched-merkle-tree/src/batch.rs`), the first insert
(`num_inserted == 0`) stores the value directly into the hash-chain slot, while
every later insert combines it with `Poseidon::hashv([existing, value])`
(~830 CU). Each insert also pays ~595 CU of base work (bloom filter bit-sets,
non-inclusion check, hash chain insert).

```
total(N) = 595 + (N - 1) * (595 + ~830)
total(10) = 595 + 9 * 1,425 ≈ 13,402
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

The shape reports two functions:

- `apply_cached_changelog_updates` (~36,429 CU): the 120-entry cascade, ~304 CU
  per applied zkp batch. Each apply advances `next_index`, appends a root to the
  root-history ring, marks the zkp batch inserted, and zeroes a slice of the
  previous batch's bloom filter. The cascade re-verifies no proofs; the submit
  path already did.
- `bench_batch_address_update` net (~96,293 CU): the index-0 submit path,
  dominated by the single Groth16 proof verification (alt_bn128 pairing).

Total is ~132,722 CU, well under the 1.4M per-transaction limit, so a backlog of
120 zkp batches applies in one transaction.

The benchmarked tree uses `zkp_batch_size = 10` (`batch_size = 1200`,
`ZKP = 120`) rather than the production address-tree `zkp_batch_size = 250`,
because only the `batch_address-append_40_10` proving key is available locally.
The bloom filter is sized to production (`NUM_ITERS = 10`, `BLOOM = 575384`) so
the per-apply `zero_out_previous_batch_bloom_filter` cost is representative.
