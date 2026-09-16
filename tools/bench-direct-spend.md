# Direct spend localnet benchmark

The harness compares PR #320 cached merge → transfer, the conventional direct certificate/freshness/balance route, and one fused GKR payment. Every measured spend uses fresh notes and includes witness construction, all usable proofs, transaction submission and confirmation, recipient indexing, and successful decryption of the complete balance. CU reads, event assertions, and extra output Merkle checks happen after the timed endpoint.

Run `bench-direct-spend.py --help` for artifact arguments. The default matrix is 144/512 selected notes, resident prover keys, three samples per cell, and all three routes: 18 measured spends plus 18 excluded warmups. Key loading is excluded from payment performance, matching servers that keep their keys resident. Cases run sequentially. The fixture resets the local validator globally; other localnet jobs must be stopped first. The runner never builds keys or SBF programs. Build matching artifacts before running it.

```sh
GOMAXPROCS=18 PROVER_SYNC_CONCURRENCY=4 E2E_BENCH_CONCURRENCY=4 \
python3 tools/bench-direct-spend.py \
  --cache-worktree ../zolana-10x-settlement \
  --target-dir ../zolana-pr320-bench/target \
  --cache-target-dir ../zolana-10x-cache/target \
  --cli /absolute/path/to/zolana \
  --photon /absolute/path/to/photon \
  --gkr-prover /absolute/path/to/gkr/prover-server \
  --cache-prover /absolute/path/to/cache/prover-server \
  --output /absolute/path/to/new-results-directory
```

Use `--routes gkr --inputs 144 --states cold --layouts clustered --runs 1` for a smoke case. The default interleaved layout deposits one decoy between selected notes. This tests a noncontiguous wallet inside a small tree prefix, not uniformly random 32-bit positions. Both worktrees use the same eight-output deposit helper, packing four deposit instructions per setup transaction; deposits and fixture funding are setup costs outside the spend timer.

Each sample explicitly restarts the prover through the CLI and verifies that its listening PID changed. “Cold” means no resident proving key in this fresh process; it does not flush the operating system's file cache. For a warm sample the harness first completes a separate paid spend, then creates fresh validator state, notes, owner and recipient while retaining that prover process. Warmup is logged separately and excluded unless `--paired` is selected. No proof or witness from warmup is reused. The fresh tree also prevents warmup nullifiers from consuming the measured fixture's queue capacity.

`E2E_BENCH_RUNS` works directly in both Rust harnesses. The runner defaults it to three and forces `E2E_BENCH_PREPARED=0`, packed submission, and 25 ms confirmation polling. It defaults both provers to `GOMEMLIMIT=24GiB`. Recipient indexing retains its existing 500 ms retry interval. Every sample reports the configured CPU limit, server proof concurrency, client concurrency, proof count, transaction count, CU, and stage timings. The manifest records artifact SHA-256 hashes; logs include prover restart PIDs and a prover log snapshot after each paid spend. `samples.jsonl` contains individual warmup and measured rows; `summary.json` gives medians and ranges, without treating three samples as a production latency distribution.

## Comparator differences

The cache route retains PR #320's configured merge authority, registry and Squads wrapper. Direct and GKR use the owner's transaction signature. They all spend plain Ed25519-owned notes; the authorization plumbing and number of proofs are architectural differences recorded in transaction and CU totals.

At 144 inputs, cache performs four 36-input merges and its existing cached 4×3 transfer. Its final instruction has three physical output slots; direct/GKR have two. Each route pays the complete balance to one real recipient. Padding cache144 to 36×2 merely to match output-slot count would penalize its fastest supported shape.

At 512 inputs, cache performs fourteen 36-input merges and one 8-input merge, then a cached 36×2 transfer with compact change and 21 dummy input slots. The cached circuit and program are unchanged. A small SDK extension marks only the 15 real cached inputs in the bitmap, supplies non-inclusion witnesses for dummy nullifiers, and hashes zeros for unselected commitments. Because the existing program resolves a state root whenever any input is uncached, the padded transfer binds an existing pre-merge state root; it remains in root history throughout this fixture. Fully cached144 keeps its canonical zero state root. The new SDK tests check bitmap/commitment padding, preservation of that state root, dummy nullifier binding, and rejection of absent or malformed padding witnesses.

Both direct and GKR emit two real encrypted output records, one carrying the balance and one carrying zero; the cached SDK uses its usual recipient and dummy-output encoding. The recipient-decrypted balance is the common endpoint. These tests do not claim byte-identical output encodings or identical service authorization.

For optional startup diagnostics, `--paired` also includes each warmup as a cold observation in the summary. Both reach recipient decryption. Raw rows retain their `warmup`/`measured` phase labels; the paired summary groups by actual `key_state`. Cold rows are excluded from the payment comparison. They measure process-cold keys already present on local disk, not downloads or a flushed OS file cache.

Use separate `--target-dir` and `--cache-target-dir` paths. Sharing one Cargo artifact directory between these different source snapshots can reuse stale workspace dependencies; each route must build against its own instruction definitions and verifying keys.
