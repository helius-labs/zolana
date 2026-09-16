# Payment scheduling

`E2E_BENCH_MODE=admitted` builds one membership-and-balance proof, with canonical zero freshness and no nullifier non-inclusion request. It uses a newly activated historical nullifier filter. `gkr` retains the existing membership, freshness and balance proof; `direct` retains the certificate route.

`E2E_BENCH_OVERLAP=1` starts proving and uploads the immutable statement concurrently. With `E2E_BENCH_CHUNKED=1` (default), allocation and the first complete statement chunks share one confirmed transaction. Remaining chunks are greedily packed and confirmed by bounded, work-conserving workers; their order is irrelevant. Once every prefix chunk confirms, the final proof chunks and commit are submitted. The builder binds the statement, payload length, variant and circuit capacity. Every transaction is included in timing and compute accounting. Set `E2E_BENCH_CHUNKED=0` for the older ordered append-only route, or `E2E_BENCH_OVERLAP=0` to start uploads after proving.

All payment work starts inside the measured interval: note hashes, membership requests, nullifier requests when required, local witnesses, encryption, proof construction, buffer uploads, confirmation and recipient decryption. Warm keys come from a complete preceding payment, followed by a fresh fixture; its work is reported separately. Account activation and funding are protocol setup, outside both payment measurements.

The report separates membership and nullifier RPC time, remaining local witness time, proof time, confirmed prefix upload time, final submission time, recipient-indexer wait and decryption. Prefix upload overlaps proof time, so those component durations must not be summed to infer total latency. `total_ms` is measured from the original payment start.

`E2E_BENCH_INDEXER_POLL_MS` changes only test-helper polling and defaults to 500 ms. `E2E_BENCH_POLL_MS` selects the confirmed-RPC polling interval. Both values must match the comparator. `tools/bench-direct-spend.py` records them, overlap mode, native build profile and artifact hashes. `--profile dev|release` selects the same native profile for all routes.

The independently edited comparator is `/Users/tsv/Developer/zolana/zolana-10x-cache-scheduling`, branch `experiment/merge/10x-cache-scheduling`, based on `12e303f7e`. It keeps PR320 circuits, cache accounts, normal Squads authorization and the recipient-decryption endpoint. Its bounded proof workers schedule the transfer first and claim another merge as soon as a worker finishes. Completed merges enter a greedy packed, confirmed transaction stream while remaining proofs run; the final transfer follows all merge confirmations. Cache creation is packed with the first merge. This follow-up changes its shared client hash/encoding code and benchmark settings; the comparator circuits and deployed SBF artifacts are unchanged.

Checks completed: staged serialization, statement, variant and capacity binding tests 3/3; admitted request format and nonzero-freshness rejection tests 2/2; both direct localnet and proof test targets compiled. No performance result is implied by these checks. Subsequent localnet results belong in their raw run artifacts.

Filter activation uses an untimed bounded setup pipeline: first creation confirms, then batches of up to eight commutative growth transactions are broadcast and all confirm before the next batch. Every message has a distinct CU-limit header; an explicit send-time account-lock rejection can retry identical signed bytes, at most four times. Other submission errors and any confirmed execution error stop setup. The final account read checks full size, filter header and empty-history sequence. `E2E_BENCH_SETUP_CONCURRENCY=1..32` controls the bound and is recorded in the run manifest. These setup writes are separate from payment uploads and do not affect the measured payment interval.

## Earlier validation (before chunked uploads)

The latest native localnet target compiled successfully. A matched 144-input, interleaved localnet smoke then passed one complete cold payment and one fresh warm-key payment per route. It used the mixed-tree-capacity-fixed SPP artifact with SHA256 `d956663fc1d503d479a9063f9b56b4298c0bd2859e5fc6ff2fc5afbbbf164eda`.

Both admitted fixtures completed all 410 setup allocations with concurrency 8, validated the completed filter, confirmed the staged payment and decrypted the recipient's full balance. The comparator also passed its new cache and nullifier-PDA postconditions. This is final correctness validation, not a statistical performance claim.

| Warm validation sample | Recipient-visible | Proofs | Transactions | Total CU |
| --- | ---: | ---: | ---: | ---: |
| Admitted 144 | 3,757 ms | 1 | 3 | 556,118 |
| Cached 144 | 6,031 ms | 5 | 5 | 1,321,972 |

Settings matched: native dev profile, GOMAXPROCS=18, four prover permits, client concurrency 4, overlap enabled, 25 ms confirmed-RPC polling and 500 ms indexer polling. Raw logs, artifact manifest, timing rows and summary are in `target/admission-bench/final-smoke`. These samples predate the chunked upload and witness optimizations described in `notes/client-witness.md`.
