# Payments with historical nullifier admission

The admitted payment circuit proves ownership, private membership in the existing UTXO tree, note ranges, nullifier derivation, value conservation and output binding. SPP checks spentness against an append-only historical filter and the existing pending-nullifier table. A payment no longer needs a nullifier-tree witness or a nullifier root inside its proof.

The statement uses domain `0x44535032` and the existing certificate and balance fields. The `AdmittedPayment` payload carries the normal payment, one Groth16 proof and its BSB22 commitment. Its freshness field must be canonical zero. Standard GKR handles the private membership hashes; request JSON cannot change the transcript or circuit configuration.

Every spending instruction on an active tree must supply its pending-nullifier account followed by its historical-filter account. Legacy proofs still establish historical nonmembership and may pass filter positives; admitted proofs require every nullifier to test negative. Both paths reject current duplicates and update the same full nullifiers. All state changes roll back if proof verification or any later instruction fails.

The filter header binds its tree pubkey and tracks the next covered queue sequence. Recording must start at the tree's actual pre-insertion sequence. A missed update therefore disables subsequent admission instead of silently creating incomplete history. Bits are never cleared. Within-payment duplicates are rejected before recording.

Activation requires compact pending-nullifier mode and a tree whose historical and queued nullifier indices are both at their initial value of one. Existing deposits are allowed, but an already-spent tree cannot start with an empty filter. Retirement permanently disables this fast path for that tree; legacy proof-based spending remains available. Authenticated migration of old spent history is not implemented.

The prototype allocates 4 MiB plus a 64-byte header and uses 12 probes derived from one Keccak hash per nullifier. It is a bounded fast path: at one million inserted nullifiers the theoretical probability of any false positive in a 512-note payment is about 0.0279%; at two million it is about 15.0%. Positives require the existing exact proof. Neither saturation nor retirement permits clearing history and re-enabling the same domain. The account's default rent exemption is about 29.19 SOL. See the [filter audit](../notes/admission-filter-audit.md) for assumptions and remaining integration coverage.

The client can upload the immutable payment statement while the prover works. After every prefix write is confirmed, it appends the proof and commits. The upload helper checks that the final statement, serialized length and circuit capacity match the staged bytes. This preserves the existing ordered append-only buffer.

## Measurements

On the same Apple M5 Pro, with resident keys, `GOMAXPROCS=18` and three verified samples per shape:

| Inputs | Constraints | Median backend proving |
| ---: | ---: | ---: |
| 144 | 1,232,023 | 2.203 s |
| 512 | 1,754,522 | 2.916 s |

These backend measurements include witness decoding, solving, GKR, Groth16 and proof serialization; they exclude witness construction, key loading, proof verification and all chain/indexer work. The 512-input result improves on the previous standard GKR backend median of 4.889 s, but already exceeds the 2.185 s complete-payment target. It does not establish 10× end-to-end performance.

One paired resident-key localnet sample at 512 inputs completed in 6.586 s versus 17.033 s for the PR #320 comparator with improved proof scheduling and streamed merge submission. Total CU was 1,287,625 versus 4,581,518. This preliminary 2.59× ratio includes witness construction, proof service, uploads, confirmation, indexing and recipient decryption. The admission prefix upload overlapped proving but took 3.554 s, longer than its 3.011 s proof. See [the assessment](../MERGE_EXPERIMENTS.md) and [raw results](../prover/server/benchmarks/admitted-localnet-512.json) for setup costs, settings and limitations.

Validation includes circuit mutation checks, strict request/shape selection, real development proof verification, 20 pending/filter library tests, five SBF/LiteSVM admin tests, staged-upload/SDK request tests, and custom-ring SDK/policy tests. A 512-input real-proof SBF test consumed 1,300,491 CU and rejected altered statements, commitments, capacity, history gaps, retirement and replay. An ordinary GKR proof passed with a saturated filter, exercising exact fallback. Clearing pending entries in the replay fixture is synthetic test-state injection, not actual forester/pruning coverage. Production key generation, mature-history lifecycle testing, broader real-proof legacy-route coverage and release integration remain outstanding.
