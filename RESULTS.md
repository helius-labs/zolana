# Cache baseline, 2026-09-16

Historical measurements. See the [final aligned comparison](https://github.com/helius-labs/zolana/blob/experiment/merge/second-gkr/MERGE_EXPERIMENTS.md) for the current conclusions.

The actual PR #320 cached-commitment path is now runnable. Successful isolated localnet samples:

| Mode | Inputs | Proofs | Transactions | Total CU | Witness/cache setup | Proving | Submission | Confirmed | Recipient decrypted |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Cold keys, unprepared payment, separate | 144 | 5 | 6 | 1,332,761 | 1,490 ms | 8,613 ms | 2,697 ms | 12,801 ms | 12,812 ms |
| Warm keys, unprepared payment, packed, 1 permit | 144 | 5 | 5 | 1,336,497 | 976 ms | 5,026 ms | 2,707 ms | 8,709 ms | 8,721 ms |
| Warm keys, unprepared payment, packed, 4 permits | 144 | 5 | 5 | 1,328,588 | 968 ms | 3,974 ms | 2,704 ms | 7,647 ms | 7,659 ms |

The six transactions are cache creation, four 36-input merges, and one cached 4-input/3-output transfer. The normal Squads wrapper succeeds with a 256 KiB heap set in the v1 transaction header. The earlier conclusion that the wrapper cannot carry 36 nullifier accounts was incorrect. Its overhead is included here.

All five witnesses are available before the first merge. All proof requests are submitted concurrently; the first two samples use the CPU prover's default `PROVER_SYNC_CONCURRENCY=1`, which serializes proof execution. The third sample enables four actual server proof permits. No indexer wait occurs between merges and final transfer. The final encrypted recipient output is indexed, decrypted by the recipient wallet, and checked against the complete input balance. Deposits and registration took 76,954 ms separately, outside spend timing.

These are individual samples, not a statistical estimate or evidence of 10× performance. Raw benchmark output is in [cache144-cold.log](docs/benchmarks/cache144-cold.log) and [cache144-warm-packed.log](docs/benchmarks/cache144-warm-packed.log). Reproduction steps and protocol boundaries are in [cache-e2e.md](docs/benchmarks/cache-e2e.md).

## Local artifacts

The original cached circuit is unchanged. Its prover-server and SDK dispatch were missing and are now implemented. A locally generated cached 4×3 proving key requires the matching generated verifying-key change in this worktree. This is a development setup, not a production trusted setup. The key is gitignored. This branch now preserves the source snapshot; development proving keys remain local. Artifact hashes are in [cache-artifacts.sha256](docs/benchmarks/cache-artifacts.sha256).

The merge keys and Squads/user-registry binaries came from the existing PR #320 benchmark artifacts. The shielded-pool binary was rebuilt here with the matching cached verifying key.

## Warm keys

Both measured rows are **unprepared payments**: all five usable spend proofs are generated inside the measured spend. Warm keys excludes loading the proving systems, not proof generation or prior consolidation.

`E2E_BENCH_WARM_KEYS=1` first proves one representative merge and the final cached transfer to load both proving systems. These proofs are discarded. Warmup occurs before the measured proving/submission timer and is reported as `warmup_ms`. Witness/cache setup remains included in confirmed and recipient-visible totals. The benchmark then proves all five statements again and performs the complete spend.

The baseline run used Surfpool, Photon, the CPU Go prover, v1 transactions, 1,400,000 CU per transaction, a 256 KiB heap, local ports 9099/8984/3201, default server proof concurrency, and no background benchmark. The warm packed run excluded 4,890 ms of representative-key warmup and 76,424 ms of deposits/registration. Cache creation fits alongside the first merge: 3,267 bytes. Each remaining merge is 3,191 bytes. The cached transfer is 1,329 bytes and does not fit alongside the final merge, so the SDK's exact size check retains five transactions. All five passed and recipient decryption succeeded.

## Validation

The cached localnet path passed in all three configurations. The two new Go tests cover cached witness/JSON roundtrip and retaining mandatory nullifier-root validation when the state root is absent. Existing Rust prover JSON tests passed after serializer refactoring. The benchmark target compiles and `git diff --check` is clean.

## Server concurrency experiment

The original cold and warm-key samples used `PROVER_SYNC_CONCURRENCY` unset; the server startup logs confirm one permit. `GOMAXPROCS` was not explicitly configured and its runtime value was not logged.

The additional warm-key, unprepared-payment run uses a fresh prover at `127.0.0.1:3202` (metrics `10199`) with `PROVER_SYNC_CONCURRENCY=4` and explicit `GOMAXPROCS=18`. Host logical CPU count is 18. The new startup log confirms `gomaxprocs=18 max_waiting=16 permits=4`. Raw startup settings are preserved in [cache-server-settings.log](docs/benchmarks/cache-server-settings.log).

The four-permit run passed with five transactions and recipient wallet decryption. It excluded 4,667 ms of key warmup and 77,028 ms of deposits/registration. Compared with the previous one-permit warm sample, proving fell from 5,026 to 3,974 ms (1.26× faster, 20.9% less time); recipient-visible latency fell from 8,721 to 7,659 ms (1.14× faster, 12.2% less time). Submission remained essentially unchanged at 2.704 seconds. These are single samples; the previous runtime GOMAXPROCS value was not recorded, so this is indicative rather than a controlled statistical estimate. It provides no 10× result.

The complete run output is [cache144-warm-packed-permits4.log](docs/benchmarks/cache144-warm-packed-permits4.log); the fresh prover's complete startup/proving log is [cache144-warm-packed-permits4-server.log](docs/benchmarks/cache144-warm-packed-permits4-server.log). Run the reproduction command with `ZOLANA_PROVER_URL=http://127.0.0.1:3202 PROVER_SYNC_CONCURRENCY=4 GOMAXPROCS=18 E2E_BENCH_WARM_KEYS=1` to select this configuration. All samples spend fresh original notes; none excludes merge/proof preparation from payment latency.
