# Payments with historical nullifier admission

The admitted payment circuit proves ownership, private membership in the existing UTXO tree, note ranges, nullifier derivation, value conservation and output binding. SPP checks spentness against an append-only historical filter and the existing pending-nullifier table. A payment no longer needs a nullifier-tree witness or a nullifier root inside its proof.

The statement uses domain `0x44535032` and the existing certificate and balance fields. The `AdmittedPayment` payload carries the normal payment, one Groth16 proof and its BSB22 commitment. Its freshness field must be canonical zero. Standard GKR handles the private membership hashes; request JSON cannot change the transcript or circuit configuration.

Every spending instruction on an active tree must supply its pending-nullifier account followed by its historical-filter account. Legacy proofs still establish historical nonmembership and may pass filter positives; admitted proofs require every nullifier to test negative. Both paths reject current duplicates and update the same full nullifiers. All state changes roll back if proof verification or any later instruction fails.

The filter header binds its tree pubkey and tracks the next covered queue sequence. Recording must start at the tree's actual pre-insertion sequence. A missed update therefore disables subsequent admission instead of silently creating incomplete history. Bits are never cleared. Within-payment duplicates are rejected before recording.

Activation requires compact pending-nullifier mode and a tree whose historical and queued nullifier indices are both at their initial value of one. Existing deposits are allowed, but an already-spent tree cannot start with an empty filter. Retirement permanently disables this fast path for that tree; legacy proof-based spending remains available. Authenticated migration of old spent history is not implemented.

The prototype allocates 4 MiB plus a 64-byte header and uses 12 probes derived from one Keccak hash per nullifier. It is a bounded fast path: at one million inserted nullifiers the theoretical probability of any false positive in a 512-note payment is about 0.0279%; at two million it is about 15.0%. Positives require the existing exact proof. Neither saturation nor retirement permits clearing history and re-enabling the same domain. The account's default rent exemption is about 29.19 SOL. See the [filter audit](../notes/admission-filter-audit.md) for assumptions and remaining integration coverage.

The client uploads the immutable payment statement while the prover works. The original append buffer remains supported. The new chunked buffer accepts independently indexed writes, rejects conflicting retries and requires complete coverage before verification. Allocation and initial chunks share one transaction; remaining chunks can be submitted concurrently. The upload helper binds the statement, serialized length, payload variant and circuit capacity. See [chunked uploads](../notes/chunked-spend-buffer.md).

The optional `direct-payment-admitted-dag10` circuit shares private Merkle parents through hash-and-index lookup tables instead of repeating every path. It has a distinct domain, `0x44535033`, and a fixed 512-input, two-output shape. Its accepted root must have no occupied leaves beyond index 1,023. This condition concerns the whole authenticated root, not just the selected notes; ordinary admission remains necessary for larger occupied trees. The SDK checks paths and constructs the DAG inside the payment timer.

## Measurements

On the same Apple M5 Pro, with resident keys, `GOMAXPROCS=18` and three verified samples per shape:

| Inputs | Constraints | Median backend proving |
| ---: | ---: | ---: |
| 144 | 1,232,023 | 2.203 s |
| 512 | 1,754,522 | 2.916 s |

These backend measurements include witness decoding, solving, GKR, Groth16 and proof serialization; they exclude witness construction, key loading, proof verification and all chain/indexer work. The conditional DAG10 backend has 835,655 constraints and a 1.024 s median across three verified resident requests. Neither backend measurement establishes a complete-payment speedup. See [prover evidence](../prover/server/benchmarks/admitted-payment.md) and the latest matched localnet results in [the assessment](../MERGE_EXPERIMENTS.md).

One paired resident-key localnet sample at 512 inputs completed in 6.586 s versus 17.033 s for the PR #320 comparator with improved proof scheduling and streamed merge submission. Total CU was 1,287,625 versus 4,581,518. This preliminary 2.59× ratio includes witness construction, proof service, uploads, confirmation, indexing and recipient decryption. The admission prefix upload overlapped proving but took 3.554 s, longer than its 3.011 s proof. See [the assessment](../MERGE_EXPERIMENTS.md) and [raw results](../prover/server/benchmarks/admitted-localnet-512.json) for setup costs, settings and limitations.

Validation includes circuit mutation checks, strict request/shape selection, real development proof verification, 20 pending/filter library tests, five SBF/LiteSVM admin tests, staged-upload/SDK request tests, and custom-ring SDK/policy tests. A 512-input real-proof SBF test consumed 1,300,491 CU and rejected altered statements, commitments, capacity, history gaps, retirement and replay. An ordinary GKR proof passed with a saturated filter, exercising exact fallback. Clearing pending entries in the replay fixture is synthetic test-state injection, not actual forester/pruning coverage. Production key generation, mature-history lifecycle testing, broader real-proof legacy-route coverage and release integration remain outstanding.

The DAG10 route passed the same real 512-input proof/settlement checks, including a wrong-selector rejection, at 1,300,547 CU. Its circuit tests also reject incorrect in-range parent and leaf references and mismatched positions with equal leaf hashes. Chunked-buffer tests cover missing chunks, retries, ownership, sealed buffers, rollback and unchanged append behavior. Development proving keys remain local artifacts.
