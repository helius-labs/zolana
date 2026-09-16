# PR320 scheduling comparator

Based on `12e303f7e`, in branch `experiment/merge/10x-cache-scheduling`. The published `zolana-10x-settlement` worktree and its earlier measurements are unchanged. No program or circuit changes are made here.

The final cached-transfer proof is scheduled first alongside merge proofs. A bounded worker pool immediately picks up another proof when a worker finishes, rather than waiting for the entire current wave. Completed merges are greedily packed and submitted while remaining proofs run. Each submitted transaction reaches confirmed commitment before the next dependent transaction is sent. The final transfer follows every merge confirmation. Cache creation stays in the first packed merge transaction.

`E2E_BENCH_OVERLAP=0` disables streaming submission but keeps the improved proof scheduler. The usual packed, unprepared, warm-key benchmark behavior remains. `E2E_BENCH_INDEXER_POLL_MS` and `E2E_BENCH_POLL_MS` must match the admitted route. The former defaults to 500 ms; the latter retains the SDK default when absent.

The payment timer begins before operation-ID and cache-PDA derivation and ends only after the recipient decrypts the full balance. Witness time includes every source and merged-note proof fetch and all local construction. `membership_fetch_ms`, `nullifier_fetch_ms` and `witness_local_ms` split that work. `prove_ms` records the last proof worker's completion. `chain_send_ms` sums all confirmed transaction submissions; `submit_ms` is the remaining submission tail after the proof workers join. Overlapping durations are not additive. Recipient-indexer wait and decryption are separate fields.

Use the admission worktree's `tools/bench-direct-spend.py` with this path as `--cache-worktree` and this worktree's `target` as `--cache-target-dir`. Choose the same `--profile` for all routes. Artifacts in `target/deploy` and the key directory point to the existing cache artifacts; source changes affect only the client and benchmark.

Compilation passed for `cargo test -p spp-test-validator --test proof_cu cached_merge_spend_e2e_benchmark --no-run -j4`. The final matched 144-input localnet smoke passed both cold and warm complete payments, including the cache and nullifier-PDA postconditions. No result from the published baseline is relabeled as a result of these scheduling changes.

After the recipient timer stops, validation also checks the cache's owner, tree, operation, frozen state, expected merge commitments and unused slots. The existing nullifier-PDA assertion validates every merge and final-transfer nullifier. These checks complement wallet decryption and all-transaction compute accounting; they do not redefine the measured endpoint.

## Final validation

The latest native target compiled successfully. The final matched 144-input interleaved smoke passed, with one measured warm-key sample per route: cached 6,031 ms, five proofs, five transactions and 1,321,972 CU; admitted 3,757 ms, one proof, three transactions and 556,118 CU. These are correctness-validation samples, not a new statistical headline.

Both used the dev native profile, GOMAXPROCS=18, four prover permits, client concurrency 4, overlap enabled, 25 ms confirmed polling and 500 ms indexer polling. All recipient balances decrypted correctly. Cache ownership, tree, operation, frozen state, every merge commitment, empty unused slots and all spent-nullifier PDAs passed verification after the timer stopped. Logs and manifests are in the admission worktree's `target/admission-bench/final-smoke`. Source is frozen after these checks.
