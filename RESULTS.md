# Direct-spend pipeline experiment

Historical measurements. See the [final aligned comparison](https://github.com/helius-labs/zolana/blob/experiment/merge/second-gkr/MERGE_EXPERIMENTS.md) for the current conclusions.

2026-09-16. Local branch `experiment/merge/10x-direct`, based on the existing direct-spend working tree. Historical checkpoint; the experiment is now preserved on the branch above.

## Aligned localnet results

Both successful runs below use 144 original notes, warm proving keys, fresh note proofs, the CPU prover with one server permit, Surfpool, Photon, and v1 transactions with a 256 KiB heap. Final outputs use the existing confidential encryption format. The recipient wallet decrypts the indexed transaction and verifies the complete balance.

| Mode | Witness | Input preparation | Final proving | Submission | Recipient visible after Send | Total excluding key warmup | Transactions | Total CU |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Unprepared | 580 ms | Included in proving/submission | 5,058 ms for all proofs | 1,241 ms | 6,493 ms | **7,074 ms** | 3 | 1,146,007 |
| Prepared certificates | 621 ms | 6,181 ms | 28 ms for balance | 672 ms | **901 ms** | 7,704 ms | 2 before Send + 1 after | 1,147,122 |

The first row's Send timer begins after witness lookup; use **total** for comparison with the cache benchmark. The prepared row separates prior work rather than subtracting it from the total. Its input proofs took 5,061 ms within preparation. Key warmup was 4,268 / 4,231 ms, and fixture setup was 33,987 / 34,495 ms; both are separately recorded and excluded.

The completed PR #320 cache path with warm keys and packing took **8,721 ms** including recipient decryption, used five transactions, and consumed 1,336,497 CU. This direct implementation is therefore **1.23× faster** and uses about **14% less CU** in these samples. It is not a 10× architecture win. Cache merges can also be prepared before Send, so the prepared direct result must not be compared with unprepared cache as proof of an architectural speedup.

These are individual exploratory samples, not p50/p95 estimates, GPU measurements, or consensus-network latency. They use one owner, one asset, tree 0, and no competing traffic. Direct uses two final outputs; the available cached circuit uses three. The pending-nullifier table is configured for a 1,000-entry input queue in this fixture, smaller than the production default. Root-expiry/refresh cost is absent here.

## Matching four-permit settings

A final successful run set `PROVER_SYNC_CONCURRENCY=4` and `GOMAXPROCS=18` on both fresh prover processes, with explicit key warmup and no concurrent benchmark. Direct server startup logged `max_waiting=16 permits=4`.

| Warm keys, unprepared 144-input payment | PR #320 cache | Direct |
|---|---:|---:|
| Proving | 3,974 ms | 3,930 ms |
| Witness generation | 968 ms | 616 ms |
| Submission | 2,704 ms | 1,283 ms |
| Total to indexed, decrypted recipient | 7,659 ms | **6,023 ms** |
| Transactions | 5 | 3 |
| CU | 1,328,588 | 1,147,452 |

This is **1.27× faster end to end and 13.6% less CU**, still far from 10×. Direct key warmup was 4,392 ms and fixture setup 34,787 ms, excluded and reported separately. Raw output: `bench-results/encrypted-144-warm-permits4.log`. The proof totals are nearly identical; most latency savings come from fewer transactions and fewer witness lookups.

## Changes

- Fetch all original nullifier witnesses together and build every proof statement before submitting transactions.
- Issue proof requests in bounded concurrent batches. The measured server permits one proof at a time; client concurrency is four.
- Pack buffer creation, writes, certificate preparation, and final payment using the existing SDK transaction-size calculation. Two certificate preparations fit in 3,818 bytes; the encrypted payment uses 1,332 bytes.
- Accept the existing confidential ciphertext envelope on direct outputs. The existing payment intent binds ciphertext, viewing tags, salt, viewing key, and recipients; no circuit or key change is needed. Plaintext/custom-data output support remains outside this prototype.
- Validate the full recipient balance using the existing wallet decryption path. The fixture uses the same input/output tree 0 as the cache benchmark because existing wallet sync hardcodes tree id 0.

The unprepared case still verifies eight input proofs plus one balance proof. Transaction packing does not remove that cryptographic work.

## Reproduce

Build the shielded-pool SBF program in this worktree with `bpf-entrypoint`, keeping its output in this worktree's `target/deploy`. The runner reuses existing local CLI, Photon, prover binaries, and direct proving keys from `zolana-direct-spend`.

```sh
E2E_BENCH_INPUTS=144 E2E_BENCH_WARM_KEYS=1 ZOLANA_PROVER_URL=http://127.0.0.1:3102 bench-results/run-localnet.sh
E2E_BENCH_INPUTS=144 E2E_BENCH_WARM_KEYS=1 E2E_BENCH_PREPARED=1 ZOLANA_PROVER_URL=http://127.0.0.1:3102 bench-results/run-localnet.sh
```

Do not run another localnet harness concurrently: the CLI stops existing service processes globally. Warm key mode explicitly proves representative statements before measurement and reports that warmup separately.

## Evidence

- `bench-results/encrypted-144-warm.log`: successful unprepared wallet-visible run.
- `bench-results/encrypted-144-prepared.log`: successful prepared wallet-visible run.
- `bench-results/packed-144-cold.log`: earlier 12,156 ms result with unencrypted outputs and five transactions; not used for the aligned comparison.
- `bench-results/encrypted-144-cold.log`: rejected benchmark due to the existing wallet's tree-id-0 assumption; chain execution succeeded but the wallet check failed. Not a completed E2E result.
- Interface ciphertext/intent-binding test passed; localnet target compiled; SBF built; both aligned runs passed; `git diff --check` clean.

Shielded-pool SBF SHA256: `dfe4a5a3e304719949c37917c2280ed2a7322d10259beb6856a87e1e7a2b6568`.
Reused prover SHA256: `832f46384e0f0ee005467f419450772750a13fb1d5f312d27265bd8475e1ee6d`.
