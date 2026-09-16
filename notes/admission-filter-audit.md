# Historical nullifier admission

The filter can justify a negative only when it covers every earlier nullifier in the same tree domain. It is an acceleration of existing exact spentness, not a replacement for the indexed nullifier tree and recent-nullifier guard. A positive requests the ordinary NIP route; it never means that a note was necessarily spent.

## Implemented contract

`program-libs/tree/src/nullifier_filter.rs` stores a 64-byte header followed by a power-of-two bitmap. The header binds the full tree pubkey, version, probe count, and next covered queue sequence. Sequence starts at one, matching the tree's sentinel leaf. `record_batch` accepts only the tree's pre-insertion queue sequence, rejects duplicate/noncanonical/zero nullifiers, hashes each nullifier once with the existing Keccak implementation, and changes no bits or header on an error. It checks all negatives against the pre-transaction bitmap before recording any member of the batch.

The integrated path can reuse pending-table validation through `PendingNullifiers::insert_batch` and `NullifierFilter::record_pending_batch`. Successful insertion returns a receipt with private fields binding the tree, first sequence and immutable nullifier slice. The receipt lifetime holds the pending-table borrow until consumption. The filter still checks its tree binding, complete sequence coverage, maximum batch, overflow and all pre-batch negatives; only the repeated canonical-value scan and duplicate sort are omitted. The standalone filter API retains those validations. A failed pending batch may have tentative earlier inserts, exactly as the previous program loop did; callers must propagate its error so Solana rolls the transaction back. Invalid or duplicate batches never return a receipt.

All 20 pending/filter library tests passed after this change, including six receipt regressions: immutable values/sequence/tree binding, invalid and duplicate rejection, 512-input bitmap equivalence with the standalone path, cross-tree/history-gap rejection, forced-positive fallback with pending rollback, and maximum-batch enforcement. Native test time does not establish CU savings; the SBF result below measures the integrated path.

The subsequent real-proof SBF check completed at **1,300,491 CU for 512 inputs**, below the unchanged 1.4M limit, with all tested statement/commitment/history/replay mutations rejected. Raw output: `target/admitted-proof-512-receipt.log`. This fixture has two outputs without encrypted payload data, so its 99,509-CU margin is not the final confidential localnet transaction's measured margin. The receipt change removed the observed compute blocker; mature-history and actual forester/pruning validation remain outstanding.

One Keccak digest derives a start and odd stride through the power-of-two bit space. This avoids repeated probe positions within the configured maximum of 32 probes. Hashing uses a versioned domain and the full tree pubkey. Probe derivation is an ordinary double-hashing Bloom construction; the false-positive estimates below use the usual approximately independent-probe model and must be measured. Grinding can increase false positives or fill the filter, but cannot produce a false negative for a recorded nullifier. Fees and a bounded lifecycle matter for availability.

Tree metadata uses `_reserved[1]`: `Off -> Active -> Retired`. Activation requires compact nullifier admission plus `next_index == queue_next_index == 1`. A drained queue after historical spending is insufficient. Existing deposited notes in a never-spent domain qualify; this does not require recreating their UTXOs. Retired domains cannot activate another empty filter. Raw account loaders reject invalid modes or active/retired modes without the compact guard.

Program integration validates the filter PDA, program ownership, writability, header domain, and contiguous coverage sequence. Every accepted old/new spend on an Active domain must record the same full nullifiers. A missing or lagging filter fails closed. Retirement requires protocol authority and prevents admitted proofs from settling; legacy NIP-plus-pending admission remains available. The current retire instruction changes the mode but does not close the filter or refund its rent.

The entire transaction must roll back if an exact proof, queue insertion, output append, fee transfer, event, or later instruction fails. Transact and merge currently invoke the shared admission helper before proof verification; their exact admission flag is safe only because the later proof check is mandatory and transaction rollback includes both bits and coverage.

## Route audit

All current SPP queue insertions use three call sites:

| Entry points | Shared path |
|---|---|
| Transact, RingTransact, RingAuthorityTransact; confidential, EdDSA, authority and P256 circuit variants | `instructions/transact/tree.rs::apply_input_trees` |
| MergeTransact and RingMergeTransact | `instructions/merge/processor.rs::process_merge_core` |
| Prepared-certificate, fused, GKR and admitted direct payments | `instructions/direct_spend/commit.rs::process_commit` |

Each calls `create_nullifier_pdas`, which handles both pending and historical admission. Deposits create notes without spending nullifiers. Preparing a certificate records proof validation but does not spend; final commit records its original nullifiers. Forester updates consume an already-recorded queue, and closing old nullifier PDAs does not erase Bloom bits.

Custom-ring policy entry creation/update now reads the tree's filter mode and consumes the extra writable filter before `entries` only when Active. Entry and high-level ring-transfer builders carry the tree metadata already read while proving and apply the shared interface pending/filter adapters. Off/Retired compact trees use pending only; legacy trees retain individual PDAs. The existing namespace CPI bound of eight forwarded accounts accommodates Active mode. Low-level builders without a tree read, including custom-ring merge, still require callers to apply the shared adapters explicitly. Parser tests stop at the SPP CPI; SPP retains responsibility for PDA/domain checks.

The fresh custom-ring SBF build passed with v1.54. All 44 SDK library tests and all 50 policy Mollusk tests passed, including create/update routing through all four account layouts and rejection of missing, read-only, or extra filters. These tests validate wrapper compatibility; they do not constitute a real-proof custom-ring settlement against the full SPP program.

## Capacity, rent and execution cost

Default bitmap: 4,194,304 bytes, 12 probes; account size: 4,194,368 bytes. At the inspected default rent rate of 6,960 lamports per byte plus 128 bytes of account overhead, rent exemption is approximately 29.19369216 SOL. This is recoverable account capital, not a per-payment fee. The core caps bitmaps at 8 MiB to remain below the 10 MiB account limit; the current program fixes 4 MiB.

The first 512-input smoke exceeded the unchanged 1.4M CU transaction ceiling. The default was reduced from 23 probes to 12 to reduce bitmap work, retaining the same versioned Keccak scheme and per-account probe count. This changes false-positive availability, not soundness: recorded notes remain positive. Existing 23-probe filters retain their stored count. At one million spends the modeled 512-note fallback frequency increases from 0.00511% to 0.02794%; at two million spends fewer probes help because the bitmap is less saturated. The integrated CU result above includes the subsequent typed-receipt optimization; it does not isolate the saving from reducing probes.

For `m = 33,554,432` bits, `k = 12`, and `n` inserted distinct nullifiers, the model is `p ≈ (1-exp(-kn/m))^k`. Batch fallback probability is approximately `1-(1-p)^b` for a batch of `b` fresh nullifiers:

| Historical spends | Per-note false positive | 144-input fallback | 512-input fallback |
|---:|---:|---:|---:|
| 500,000 | 3.71e-10 | 0.00000535% | 0.0000190% |
| 1,000,000 | 5.46e-7 | 0.00786% | 0.02794% |
| 1,500,000 | 2.62e-5 | 0.377% | 1.334% |
| 2,000,000 | 0.0003165 | 4.456% | 14.962% |
| 4,000,000 | 0.03761 | 99.600% | approximately 100% |

These are model values, not measured timings. A fixed 4 MiB filter cannot promise fast negatives for an arbitrarily mature tree. Saturation requires exact fallback or irreversible retirement. New domains or carefully specified sharding/epochs can bound active-filter state; a historical note must still consult every relevant lifetime epoch or use exact fallback. Starting an empty replacement for the same domain is unsafe.

The core performs one 87-byte Keccak over three slices per nullifier, at most 12 bit reads and 12 bit writes, plus exact batch duplicate detection. At 512 inputs that is 512 syscalls and at most 6,144 probes in each pass; hash scratch is 8 KiB and duplicate-sorting scratch is 4 KiB on 64-bit targets, not a bitmap copy. The program additionally holds the 16 KiB nullifier vector and existing transaction structures. Conditional profiler annotations separate batch validation, hashing, and the remaining filter work; enable the tree library's `profile-program` feature for those markers.

The locally inspected Agave hash syscall schedule charges 85 CU base plus `max(10, slice_len/2)` per slice: 128 CU for these three slices, or 65,536 CU for 512 hashes alone. This excludes all SBF instructions, sorting, bitmap access, account loading, queue writes, proof verification and CPIs. It is a source-derived hash subtotal, not a measured CU result. The actual SBF instruction must be measured with the deployed validator build.

Initialization uses existing 10 KiB account growth steps: a 4 MiB filter needs 410 allocation calls. That setup and rent cannot be hidden in a first-use benchmark. Avoid scanning or copying the full bitmap per spend. An untrusted indexer may predict positives so the client need not download 4 MiB each time; current on-chain bits decide correctness. A race that creates a positive after proving must trigger exact fallback, not override the check.

## Migration and validation gates

No historical migration is implemented. Enabling an old spent domain requires authenticated complete coverage of all historical indexed nullifiers and all queued/recent entries, with a frozen checkpoint or dual-write watermark. Counting client-supplied entries is insufficient. Their positions/coverage must be authenticated, and activation must bind the resulting bitmap and coverage cursor. This work can be shared across wallets, but is not free or an already delivered legacy speedup.

The source-grounded frozen and online migration designs are in [admission-history-migration.md](admission-history-migration.md). They require new protocol state and import instructions; current genesis-only activation must remain until that implementation is verified.

Required program integration tests:

1. Every legacy route records its full nullifier batch on an Active tree, including multi-tree transfers and real dummy-input nullifiers; supplied account order remains correct.
2. Invalid legacy proofs after tentative recording roll back bitmap, coverage, queue, pending table, outputs and fees.
3. A valid admitted payment rejects a prior legacy or admitted spend, including after the recent guard entry becomes reclaimable. Restore the uploaded buffer to isolate spentness from buffer replay protection.
4. A forced false positive returns `NullifierProofRequired` without mutation; the same fresh note succeeds via valid NIP and current pending admission.
5. Missing/wrong-tree/wrong-owner/read-only filter accounts, coverage gaps, mixed duplicates, and stale roots fail without partial writes.
6. Activation rejects historical and queued spends; partial allocation stays Off; retirement is irreversible and admits only the exact route afterward.

Tree tests passed: eight core tests, four lifecycle tests, and the existing compact migration test. All five tests in the new `nullifier_filter_admin` target also passed against the newly built SBF program in LiteSVM (0.34 seconds after compilation), covering allocation state, authority/PDA checks, genesis-only activation, reinitialization, retirement, and transaction rollback. The command was `cargo test -p shielded-pool-tests -j2 --test nullifier_filter_admin --offline -- --test-threads=1`. These are correctness tests, not proving or localnet latency benchmarks.

The direct-payment test source now exercises both ordinary GKR and admitted proofs on an Active tree. It mutates commitments, commitment knowledge proofs, capacity, outputs and nullifiers; evicts accepted state/nullifier roots; checks coverage mismatch and retirement; restores the upload buffer to isolate replay protection; and removes the synthetic pending fixture to confirm historical rejection. The pending reset is deliberate test-state injection, not a real forester/root-history/pruning transition. The source also saturates the bitmap: admitted proofs reject without mutation, while the exact-proof fixture succeeds with the saturated bitmap retained. Those are separate fixture runs, not an automatic client retry. This review found no blocking soundness issue in the direct test flow; actual runs belong to the root agent's integration validation.

A valid mature-history benchmark must separate real reachable state from population modeling. Run normal localnet lifecycle tests with enough valid spends/forester updates to cross root-history and recent-guard pruning boundaries. Separately populate the filter with 0.5M/1M/1.5M/2M known distinct canonical nullifiers, preserving the coverage cursor, and measure distributions for 144/512 fresh queries, confirmed replays, forced positives and full fallback. A synthetic mature snapshot is acceptable for execution measurements only if explicitly labeled, with exact history/root/pending state consistent for any exercised fallback. Arbitrary random bits or an empty exact tree do not establish mature-history end-to-end correctness. Report population creation, migration, first-use allocation and resident-key online payment separately.

## Final source review

The final review traced every production nullifier-queue insertion, both legacy proof-verification tails, direct-payment proof selection, Active account routing, typed receipt construction/consumption, activation, retirement, and custom-ring forwarding. It found one account-capacity regression: 35 legacy inputs plus one input from an Active compact tree need 37 nullifier accounts, exceeding the parser's old 36-account buffer. The buffer now allows `MAX_INPUTS + MAX_INPUT_TREES`. The focused parser regression passed for legacy, compact Off, Active and Retired layouts, in both tree orders, checking that the trailing owner signer remains correctly parsed. No remaining security or correctness blocker was found to committing this experiment.

The targeted native regression and normal SBF v1.54 build passed; logs are `target/admission-final-capacity-test.log` and `target/admission-final-capacity-sbf.log`. The rebuilt program SHA-256 is `d956663fc1d503d479a9063f9b56b4298c0bd2859e5fc6ff2fc5afbbbf164eda`. The 512-input timing below precedes this account-capacity fix; the final smoke must use the rebuilt artifact.

The typed receipt cannot be constructed with unchecked values or for another tree through its public API. Sequential pending insertion catches duplicates within the batch as well as existing live entries; the first sequence is at or above the reclamation watermark. The filter independently verifies the full tree domain and exact next coverage sequence. Legacy proof failures propagate after tentative writes, so the enclosing transaction rolls back the queue, pending table, filter and other mutations. No production path resets filter bits, clears coverage, reactivates a retired domain, or spends on an Active domain without recording the full nullifier batch.

The parent agent reports a matched resident-key localnet sample of 6.586 seconds and 1,287,625 total CU for admitted 512-input payment, versus 17.033 seconds for optimized PR #320: approximately 2.59× faster. This is one warm sample, not a 10× result, mature-history distribution, or migration result. The unchanged 1.4M CU ceiling leaves 112,375 CU in that measured transaction.

Before production deployment, complete the real forester/pruning replay test and the Active-filter legacy-route matrix, including multi-tree and custom-ring settlement with real proofs. Historical migration and automatic client fallback are not delivered. Multi-step initialization should be performed while the tree is paused: a spend while allocation is incomplete correctly prevents activation, but leaves the allocated account and its rent stranded until an explicit cleanup design exists. Retirement currently preserves the account and its rent as well.
