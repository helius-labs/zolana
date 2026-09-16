# Cold proving experiments

These are circuit/prover experiments, not deployed instructions or end-to-end wallet measurements. They include fresh proofs for every note. Setup and key loading are separate from proof time.

Machine: Apple M5 Pro, 18 CPU cores, 48 GiB RAM, arm64, Go 1.27.1. Timed proving uses `GOMAXPROCS=4` and native BN254 Groth16. Every timed proof is verified.

## Actual proving, 512 inputs and two outputs

| Statement | Constraints | Proof trials, ms | Median, ms |
| --- | ---: | --- | ---: |
| Existing fused payment | 10,728,434 | 41314.760, 40312.743, 40238.146 | 40312.743 |
| Complete private subtree plus external admission | 668,507 | 2873.810, 2897.192, 2875.214 | 2875.214 |

This is **14.02× faster actual Groth16 proving**, with six verified proofs. It is conditional on the layout and admission requirements below. It is not a 14× wallet or localnet result.

The existing 3.5 GiB baseline key was loaded read-only. Its serialized R1CS matched a fresh compilation after removing only source-location/debug metadata: SHA-256 `f86cf9f8f251517c15131e3d39fb6c91a1da19b9c95eaa724b145c13847e6fc8`. Baseline compilation took 23.727 s; key loading and digest checking took 93.899 s. The compact circuit's compilation and one-time setup took 44.293 s. These costs are excluded from the proof medians. Keys were resident and each proof recomputed its circuit solution; no input certificate was prepared beforehand. The benchmark sets `GOMEMLIMIT=16GiB`. Swap-in and swap-out counters remained zero; the OS compressed memory.

To avoid using an unnecessarily expensive wide baseline as the only denominator, the same run timed the actual existing merge circuits with their existing keys and checked their R1CS digests:

| Merge shape | Proof trials, ms | Median, ms |
| --- | --- | ---: |
| 8 inputs | 973.443, 1012.914, 1009.008 | 1009.008 |
| 36 inputs | 3090.950, 3061.368, 3038.337 | 3061.368 |

A 512-input merge workload comprises fourteen 36-input merges and one 8-input merge: **43.868 s of estimated serial proving from these measured medians**, before the cached transfer proof. The compact proof is 15.26× below that estimate. This is a proof-work estimate; concurrent merge proving and transaction latency are not measured by it.

Raw console output: `prover/server/benchmarks/wide-cold-proving.log`.

## Full circuit costs

Actual R1CS compilation, 512 inputs and one output:

| Statement | Constraints | FFT domain | Constraint reduction |
| --- | ---: | ---: | ---: |
| Existing fused payment | 10,727,510 | 16,777,216 | 1× |
| One shared private nullifier predecessor | 4,986,854 | 8,388,608 | 2.15× |
| Complete private state subtree plus shared predecessor | 1,077,149 | 2,097,152 | 9.96× |
| Complete private state subtree plus external nullifier admission | 667,577 | 1,048,576 | 16.07× |

The subtree statement proves all notes occupy one aligned 512-leaf subtree. The base position, all indices, and all paths remain private. It is useful only when the wallet actually owns the entire subtree; unrelated notes spread through the global tree do not qualify.

Shared predecessor means every nullifier lies in the same authenticated gap. An empty nullifier tree satisfies this naturally. Mature random nullifiers almost never share one gap. The experiment authenticates the predecessor once and proves `0 < (nullifier - low mod p) < high - low`, with canonical field comparisons and `low < high` established once. Modular subtraction cannot admit a nullifier below `low`: its wrapped difference exceeds the interval width. Reusing the bound nullifier-list hash avoids hashing the same list twice.

External admission removes the freshness statement completely. It requires the program to reject historical spends and transaction duplicates using an exact set, or a monotone Bloom-negative check with a sound positive fallback. That program rule is not implemented by this experiment. This row is not a standalone safe payment protocol.

The membership optimization also supports multiple complete subtrees at unrelated private positions:

| 512-input layout with external admission, one output | Constraints | FFT domain |
| --- | ---: | ---: |
| 64 subtrees of 8 notes | 1,098,368 | 2,097,152 |
| 32 subtrees of 16 notes | 872,576 | 1,048,576 |
| 16 subtrees of 32 notes | 763,536 | 1,048,576 |

The 16-note layout reduces actual compiled constraints 12.29×. It was validated with two privately located four-note groups at leaf positions 0 and 1024; moving a group without updating the authenticated tree fails. The 512-input runtime above measures one complete 512-note subtree, not these fragmented layouts. Raw compilation output: `prover/server/benchmarks/compact-clusters.log`.

At 36 inputs, existing circuits compile to 319,334 constraints for the certificate and 436,848 for freshness. A fused payment has 758,447; the current merge circuit has 780,681. Fusion alone barely changes cold work. The existing 16-certificate/two-output balance circuit has 12,462 constraints.

## Actual proving, 32 inputs

Three proofs per complete experimental statement; keys resident, no input proofs prepared beforehand. All notes are real, share one owner and asset, occupy one complete aligned subtree, and use an initially empty nullifier tree.

| Statement | Constraints | Proof trials, ms | Median, ms | Speedup |
| --- | ---: | --- | ---: | ---: |
| Existing fused payment | 674,867 | 3088.638, 3134.075, 3094.370 | 3094.370 | 1× |
| Shared predecessor | 330,372 | 1620.376, 1597.523, 1632.898 | 1620.376 | 1.91× |
| Subtree plus shared predecessor | 90,272 | 439.722, 435.259, 436.956 | 436.956 | 7.08× |
| Subtree plus external admission | 53,660 | 327.175, 323.688, 327.051 | 327.051 | 9.46× |

These 32-input experimental shapes are not SDK endpoints. The measured proof times cannot be substituted for 512-input latency or end-to-end confirmation time.

## Limits of other changes

A deterministic sample of 512 uniformly dispersed indices in a tree with `2^20` occupied leaves needs 5,687 distinct state parent hashes, versus 16,384 independent path hashes. The analogous 40-level nullifier tree needs 5,695, versus 20,480. That is a 3.24× combined hash-count reduction before private routing and other constraints. At `2^32` occupied positions the combined reduction is only 1.56×. These counts are ideal multiproof budgets, not a compiled private multiproof implementation.

Actual isolated hash constraints are 241/298/403/610 for Poseidon arity 2/4/8/16. Gnark's default two-input Poseidon2 compression uses 187. A hash substitution alone cannot deliver 10× and changes existing roots and protocol hashes. Larger tree arity also incurs private child-selection costs omitted by isolated hash counts.

The installed gnark version contains an ICICLE backend, but the application calls the native `groth16.Prove` path. No GPU result was measured.

For arbitrary legacy notes with unchanged privacy, the experiments do not establish a 10× cold improvement. The concrete 10×-class compiler candidate combines a layout that preserves shared private membership with chain-enforced nullifier admission. It requires a protocol change and a layout strategy for future notes; it cannot rearrange existing notes for free.

## Reproduce

Run from `prover/server`:

```sh
go test ./circuits/direct_spend -run 'Test(CompactPaymentWitness|IntervalBounds|MerkleUnionBudget|HashBudget)$' -v
COMPACT_CONSTRAINT_BENCH=1 go test ./circuits/direct_spend -run TestCompactPaymentConstraints -v
COMPACT_PROVING_BENCH=1 GOMAXPROCS=4 go test ./circuits/direct_spend -run TestCompactPaymentProving -v
COMPACT_CONSTRAINT_BENCH=1 go test ./circuits/direct_spend -run 'TestCompactCluster' -v
COMPACT_BASELINE_KEY=/path/to/direct-payment_512_2.key COMPACT_MERGE_KEYS=/path/to/merge-keys GOMAXPROCS=4 GOMEMLIMIT=16GiB go test ./circuits/direct_spend -run 'Test(MergePaymentProving|WideCompactPaymentProving)$' -timeout 15m -v
```

The interval test checks all 343 triples from seven boundary values, including zero and values near the field modulus. The compact circuit tests reject wrong membership roots, spent interval endpoints, amount inflation, recipient substitution, and misaligned state positions.
