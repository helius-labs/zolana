# Merge and direct-spend experiments

The latest matched 512-note CPU localnet sample completes in **5.056 s with standard admission** and **3.563 s with conditional DAG admission**, versus **17.059 s for optimized PR #320**. That is **3.37×** and **4.79×** faster respectively. **10× end-to-end remains unproven.** Each route has one measured resident-key sample, so these results are preliminary.

## Latest aligned comparison

| 512 inputs | PR #320 cache | Standard admission | DAG10 admission |
| --- | ---: | ---: | ---: |
| Complete payment | 17.059 s | 5.056 s | 3.563 s |
| Witness construction | 2.705 s | 1.096 s | 1.251 s |
| Proof stage | 12.147 s | 2.837 s | 1.122 s |
| Prefix upload, overlapping proving | — | 1.089 s | 1.176 s |
| Proofs | 16 | 1 | 1 |
| Transactions | 15 | 7 | 7 |
| Total CU | 4,574,430 | 1,292,847 | 1,293,138 |

The timer starts before input hashing and membership lookup and ends after the recipient decrypts the complete balance. All payment-specific witness work, DAG construction, encryption, proof service, buffer allocation, uploads and confirmation remain timed. Proving keys stay resident after a separately reported complete warmup payment. Protocol setup, deposits and filter activation are excluded for both routes.

Both use the same CLI/Photon artifacts, native dev profile, 18 Go CPUs, four proof permits, client concurrency four, 25 ms confirmation polling and 500 ms indexer polling. Cases run sequentially without other proving/build workloads. Input notes alternate with other-owner notes in a small occupied tree prefix. This is neither a mature random 32-bit tree measurement nor a GPU/production-network benchmark. PR #320 retains its Squads/registry authorization; admission uses the owner's transaction signature.

[Raw samples, settings and artifact hashes](prover/server/benchmarks/chunked-localnet-512.json).

## What changed

Admission retains private membership, ownership, nullifier derivation, value conservation and output binding. It removes nullifier-tree proofs: SPP checks complete historical spentness through a monotone filter plus the pending table. Exact-proof spending remains the fallback for filter positives, and all spending routes must update the same history atomically. [Protocol](docs/admitted-payments.md).

DAG10 computes shared Merkle parents once and binds both private hashes and positions through lookup tables. Its fixed 512-input circuit has a distinct public domain and verifying key. **The accepted root must have no occupied leaves beyond index 1,023.** Selecting 512 notes from a larger occupied root does not qualify. Its three verified resident backend samples have a 1.024 s median; that is a prover result, not the complete-payment time. [Circuit evidence](prover/server/benchmarks/admitted-payment.md).

Immutable note/proof binding removes duplicate client hashes. Native Poseidon parameter reuse, plain-note hash constants and direct hexadecimal encoding improve both routes. The SDK preserves the different field schemas used by direct and cached requests. Independently indexed buffer chunks remove per-chunk confirmation dependencies while rejecting holes and conflicting retries. Allocation remains inside the payment timer. [Witness work](notes/client-witness.md), [chunk protocol](notes/chunked-spend-buffer.md).

The comparator schedules its final transfer proof first, keeps workers busy and submits completed merges while other proofs run. Its deployed SBF artifacts and circuits are unchanged by this follow-up; shared client optimizations apply equally.

## Simulator correction

Earlier Surfpool runs left diagnostic instruction profiling enabled. That mode re-executes instruction prefixes before normal execution, adding overhead that depends on transaction packing. Both harnesses now disable it for performance runs and record the setting. This is a measurement correction, not an architectural gain. [Source evidence and flag](notes/simulator-profiling.md).

The otherwise matched profiling-enabled smoke measured 16.731 s cached, 6.239 s standard admission and 5.915 s DAG10. The latest profiling-disabled pair above supersedes that comparison. Retain the old labels: neither the old 21.846 s nor the earlier 17.033 s comparator is the denominator for the new ratios. [Diagnostic samples](prover/server/benchmarks/chunked-localnet-profiled-512.json).

## Assessment and remaining work

Direct admission substantially reduces proofs and chain work: the latest standard route uses 71.7% fewer total CU. DAG10 helps eligible roots, but its faster prover translates to a smaller full-payment improvement. It is an optional path, not a generic replacement for arbitrary mature-tree balances.

A 10× payment against this comparator must finish within **1.706 s**. The full-height admitted proof stage alone took 2.837 s. Even DAG10 still spends 1.251 s constructing witnesses and 1.176 s uploading the prefix; upload and proving overlap, so these values must not be blindly added. Next measurements should target client work and transport under matched production profiles and polling. A general 10× route still needs a larger proof or state-architecture improvement. [Options and tradeoffs](notes/tenfold-next-options.md), [resident-key analysis](notes/resident-key-options.md).

The filter is a protocol change with release gates. It activates only on compact trees that have never processed a spend; existing deposits qualify. Authenticated migration for already-spent trees is unimplemented. The 4 MiB filter costs about 29.19 SOL rent and needs 410 allocation instructions in this fixture. This shared setup is reported separately, not free. At two million inserted nullifiers, the modeled chance of at least one filter false positive in a 512-note payment is about 15%; exact fallback and irreversible retirement preserve correctness. Mature-history lifecycle and broader integration coverage remain necessary. [Audit](notes/admission-filter-audit.md), [migration design](notes/admission-history-migration.md).

Validation includes native hash/encoding parity, SDK witness checks, chunk coverage/retry/ownership/rollback tests, actual 512-input DAG proof verification with statement/selector/history/replay rejection, and twelve complete localnet payments across the two three-route smoke runs, including warmups. These are correctness checks and small performance samples, not a security audit or a production latency distribution. Synthetic pending-table clearing in the replay test is not forester/pruning coverage. Development proving keys remain local; published keys are verifying keys.

## Earlier evidence

The earlier three-sample matrix measured 9.983 s GKR direct versus 21.846 s PR #320 at 512 inputs, a 2.19× result under its original settings. [Report](docs/gkr-localnet.md).

The separate **14.02× proving result** was 40.313 s → 2.875 s with resident keys and four Go CPUs. It required one complete, aligned subtree of owned notes and external historical admission. Sequential nullifier leaves alone do not produce that gain; it is not an end-to-end or arbitrary-layout result. GKR and clustering gains cannot be multiplied. [Original experiment](https://github.com/helius-labs/zolana/blob/experiment/merge/10x-proving/docs/direct-spend-cold-proving.md), [combination results](docs/hybrid-cluster-gkr.md).

## Published branches

All experiment branches use `experiment/merge/`. The active implementation/comparator pair is `10x-admission` and `10x-cache-scheduling`; the remaining branches preserve earlier research snapshots.

| Suffix | Contents |
| --- | --- |
| [10x-admission](https://github.com/helius-labs/zolana/tree/experiment/merge/10x-admission) | Admission, DAG10, chunked uploads, current results and assessment |
| [10x-cache-scheduling](https://github.com/helius-labs/zolana/tree/experiment/merge/10x-cache-scheduling) | Optimized PR #320 comparator and matching benchmark settings |
| [second-gkr](https://github.com/helius-labs/zolana/tree/experiment/merge/second-gkr) | Earlier integrated GKR payments and three-sample matrix |
| [10x-settlement](https://github.com/helius-labs/zolana/tree/experiment/merge/10x-settlement) | PR #320 comparator for the earlier matrix |
| [10x-proving](https://github.com/helius-labs/zolana/tree/experiment/merge/10x-proving) | Clustered proofs and conditional 14.02× prover result |
| [10x-nullifier-filter](https://github.com/helius-labs/zolana/tree/experiment/merge/10x-nullifier-filter) | Standalone historical spentness filter |
| [second-private-dag](https://github.com/helius-labs/zolana/tree/experiment/merge/second-private-dag) | Initial shared private Merkle-path experiment |
| [direct-spend](https://github.com/helius-labs/zolana/tree/experiment/merge/direct-spend) | Initial direct-spend implementation |
| [pr320-e2e-bench](https://github.com/helius-labs/zolana/tree/experiment/merge/pr320-e2e-bench) | Initial PR #320 benchmark harness |
| [10x-direct](https://github.com/helius-labs/zolana/tree/experiment/merge/10x-direct) | Earlier direct-spend localnet measurements |
| [10x-cache](https://github.com/helius-labs/zolana/tree/experiment/merge/10x-cache) | Earlier cached-transfer measurements |
| [10x-settlement-direct](https://github.com/helius-labs/zolana/tree/experiment/merge/10x-settlement-direct) | Earlier direct settlement and wire comparison |
