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
