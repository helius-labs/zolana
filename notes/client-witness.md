# Client witness and upload work

The earlier 512-note admitted sample spent 1,401 ms on local witnesses and 435 ms on membership RPC. The client previously hashed every note before lookup and again when constructing the certificate, converted every path field through `BigUint`, cloned the JSON witness during request serialization, and constructed Poseidon's fixed parameters for each hash.

`InputNote` now owns an immutable note and its computed commitment. Batch membership lookup uses that commitment; consuming `with_proof` verifies the returned leaf before creating an immutable `Input`. Certificate construction can reuse this binding without a second note hash. Hashes are still computed inside the payment timer.

Both admission and the PR320 comparator use the same native, thread-local Poseidon parameter cache, byte-to-hex field codec, and generated Poseidon(0,0) constant for plain-note ring fields. The cache falls back to a fresh hasher on a reentrant borrow; malformed input cannot poison its state. Native no-std and Solana syscall paths retain their previous behavior. Direct request serialization borrows its witness instead of cloning it.

The chunked buffer schedule packs creation, required growth, and initial statement chunks in the first transaction. It confirms this allocation before dispatching remaining independently indexed chunks through bounded workers. Every prefix confirmation completes before the final proof chunks and commit. All allocations, uploads and confirmations remain inside the spend timer; all signatures and transaction CU are reported. `allocation_ms` includes the first transaction's packed statement chunks. An explicit send-time account-lock rejection retries the identical signed message up to four times; other failures stop the payment.

The benchmark reports input hashing separately and records certificate, output encryption, balance and fused-request construction. `ZOLANA_TIMING=1` additionally reports request serialization. Overlapping component durations are not additive.

`admitted-dag10` is an optional, fixed-512 circuit route. Its historical state root must authenticate an entirely empty region above leaf 1023. SDK construction verifies that condition from private paths, memoizes each distinct parent hash, rejects inconsistent paths and roots, and emits the circuit's fixed private row/reference layout. It adds all DAG assembly to fused-witness time. No input-count claim implies eligibility for this route on a larger occupied tree.

## Validation

- Native hasher parity across all supported arities, malformed-input recovery, reentrancy and thread isolation: passed.
- SDK prover unit tests: 50 passed, including immutable leaf binding, valid DAG path reconstruction, invalid paths, out-of-range indices and occupied upper siblings.
- Plain/ring note commitments and byte-field encoding parity: passed in both worktrees.
- Admission localnet and proof-test targets, and optimized PR320 benchmark target: compiled.
- Runner syntax and whitespace checks: passed.

The first real request exposed a field-encoding regression: direct witnesses require exactly 32 hexadecimal bytes, while legacy merge requests use minimal-width numbers. Separate wrappers now share byte emission while preserving each schema. Serialized certificate/DAG request tests check every field, and the corrected 512-input request passed the actual proof and SBF mutation/replay suite. Native checks alone make no end-to-end latency claim; matched localnet results are in [the assessment](../MERGE_EXPERIMENTS.md).

## Native hash sample

One isolated dev-profile sample, 512 sequential hashes per arity, compared fresh parameters with reused parameters. Dependency optimizations are the repository's existing dev profile. This is a hash microbenchmark, not a payment benchmark.

| Arity | Fresh parameters | Reused parameters |
| --- | ---: | ---: |
| 2 | 95,942 µs | 81,950 µs |
| 3 | 130,045 µs | 116,070 µs |
| 4 | 186,275 µs | 166,001 µs |
| 5 | 244,313 µs | 219,649 µs |
| 9 | 561,323 µs | 520,504 µs |

Reproduce with `cargo test -p zolana-hasher --lib benchmark_native_poseidon_reuse -- --ignored --nocapture` in an exclusive CPU window. The improvement is approximately 1.08–1.17× per hash; full-payment gains need matched localnet measurements.
