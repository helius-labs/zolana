# Double-spend analysis

**Answer: yes, on every instruction that consumes a UTXO a spent note cannot be spent again; the one qualification is that the guarantee rests on two mechanisms in sequence (a per-batch bloom filter, then root-history zeroing) rather than on the nullifier tree alone, and I verified the handoff between them closes rather than leaves a gap.**

A second, separate finding fell out of the same reading: the circuit leaves a padding dummy input's public nullifier column unconstrained, and the program inserts it anyway. That cannot un-nullify a note, so it is not a double spend, but it can permanently wedge the nullifier queue and freeze every shielded balance. It is written up in [Secondary finding](#secondary-finding-a-chosen-padding-nullifier-can-wedge-the-queue) with a minimal fix in prose. It does not change the answer above.

**For the zone-containment ruling:** double spending holds on the withdrawal path. Nullification and public-leg settlement are in one instruction, in that order, with no partial-application path (see [Withdrawal atomicity](#withdrawal-atomicity)). Whether a zone authority may pay value out through a public leg is therefore a free policy choice; the invariant does not force it.

## Evidence standard

| Claim | How established |
| --- | --- |
| A replayed landed spend is rejected | Execution |
| The same spend twice in one Solana transaction is rejected | Execution |
| The same nullifier in two input slots of one proof is rejected | Execution |
| A zeroed root-history slot is unusable | Execution |
| A padding dummy carrying nullifier `0` lands on chain | Execution |
| `0` is already a nullifier-tree leaf and cannot be appended again | Execution |
| Nullifier derivation is pinned to the specific UTXO in-circuit | Reading |
| Every UTXO-consuming instruction nullifies every input | Reading |
| Clearing a bloom filter leaves only roots that already contain the batch | Execution (existing library test, run) |
| That handoff holds under a real forester with real proofs | Reading (arithmetic checked by hand) |
| Two transactions in the same slot serialise | Reading (Solana write-lock semantics) |

My tests live in `program-tests/shielded-pool/tests/transact/double_spend.rs` (committed; 8 tests, all passing). One further piece of execution evidence is an existing library test I ran rather than wrote, `test_zero_out` in `program-libs/batched-merkle-tree/src/merkle_tree.rs:903`.

## The mechanism

A nullifier is `Poseidon(utxo_hash, blinding, nullifier_secret)` (`docs/spec.md:521`), computed in-circuit by `NullifierGadget` (`prover/server/circuits/spp_transaction/inputs.go:149-163`).

Three constraints make it unique to one UTXO and unforgeable by anyone but its owner:

1. **Pinned to the published value.** `inputs.go:112`, `assertEqualWhen(api, spendOrAddress, nullifier, in.Nullifier)`. The public nullifier column must equal the computed value for every real spend.
2. **Bound to the same UTXO that is proved included.** The `utxoHash` fed to the nullifier (`inputs.go:107-111`) is the same `utxoHash` whose Merkle inclusion is checked at `inputs.go:72-82`, and the same `blinding` feeds both the UTXO hash and the nullifier. So one UTXO yields exactly one nullifier.
3. **Bound to the owner's secret.** `nullifier_secret` produces `nullifier_pk`, which enters `owner_hash` (`inputs.go:100-104`), which must equal the UTXO's committed `owner` (`inputs.go:104`). An attacker cannot pick a different secret without breaking the owner-hash binding of a UTXO already in the tree.

The circuit also proves **non-inclusion** of the nullifier against a nullifier-tree root (`inputs.go:114-125`) using an indexed-tree low-element bracket. The range check is strict on both sides: `AssertStrictlyOrdered` (`inputs.go:165-187`) asserts `IsLessLimbs(lo, mid) == 1` and `IsLessLimbs(mid, hi) == 1` over canonical full-field limbs. There is no `<=` off-by-one.

On the program side, `apply_tree` reads the roots the proof will be checked against and inserts each nullifier into the queue (`programs/shielded-pool/src/instructions/transact/processor.rs:212-227`, insertion at `:219-221`).

The queue insert is the synchronous double-spend check. `BloomFilter::insert` (`program-libs/bloom-filter/src/lib.rs:78-108`) sets each probe bit and tracks whether any bit was newly set; if all bits were already set it returns `Err` (`:103-107`). `Batch::insert` then also checks the *other* batch's filter (`program-libs/batched-merkle-tree/src/batch.rs:289-320`, `check_non_inclusion` at `:377-385`). Both live filters are therefore consulted on every spend.

So the protection is layered: the circuit proves the nullifier is absent from the *tree*, and the program proves it is absent from the *queue*. Neither alone is sufficient; together they cover the full lifetime of a nullifier.

## Per-instruction enumeration

Dispatch is `programs/shielded-pool/src/lib.rs:50-75`. Every instruction, with a verdict:

| Instruction | Consumes UTXOs | Nullifies every input | Verdict |
| --- | --- | --- | --- |
| `Transact` | Yes | `transact/processor.rs:212-227` | **Safe** |
| `ZoneTransact` | Yes | Same code path | **Safe** |
| `ZoneAuthorityTransact` | Yes | Same code path | **Safe** |
| `MergeTransact` | Yes (8 fixed) | `merge/processor.rs:135-154` | **Safe** |
| `ZoneMergeTransact` | Yes (8 fixed) | Same, plus the single-use tag at `:158-162` | **Safe** |
| `Deposit` / `ZoneDeposit` | **No** (outputs only) | n/a | **Safe (vacuous)** |
| `BatchUpdateNullifierTree` | No (forester append) | n/a | **Safe (vacuous)** |
| `CreateTree`, `CreateAssetCounter`, `CreateSplInterface`, protocol-config and zone-config instructions, `PauseTree`, `EmitEvent` | No | n/a | **Safe (vacuous)** |

Two structural points make this enumeration robust rather than a list of separately-audited paths:

- **The three transact variants share one implementation.** `zone_transact` and `zone_authority_transact` both funnel into `process_transact_core` (`zone_authority_transact/processor.rs:45-52`, `zone_transact/processor.rs`), which calls the same `apply_tree`. There is no second, divergent nullification routine to get wrong.
- **The loop cannot under-count.** In `transact` the loop is `for (i, input) in ix.inputs.iter().enumerate()` and the *same* `ix.inputs.len()` selects the verifying key (`transact/verify.rs:118-120`, `:253-274`). A proof verified for N inputs therefore always nullifies exactly N. In `merge` the loop is a fixed `0..MERGE_INPUT_COUNT` with `ix.nullifiers.get(i).ok_or(shape)?` (`merge/processor.rs:135-138`), so a short array errors rather than silently skipping. There is no `continue` on dummy inputs anywhere; dummies are nullified too.

Deposits genuinely consume nothing: `programs/shielded-pool/src/instructions/deposit/processor.rs` contains no reference to nullifiers or inputs at all.

`merge_zone` additionally inserts its `merge_view_tag` into the same queue (`merge/processor.rs:158-162`) to make the tag single-use. This shares a namespace with nullifiers, but a collision would require hitting a specific Poseidon/HKDF output, so it is not a forgery route. It does consume queue capacity, which matters for the secondary finding below.

## The batching window

This is where this class of protection usually leaks, so it gets the most detail. It does not leak here.

Nullifiers are **not** written into the tree by the program. `insert_address_into_queue` puts them in a bloom filter plus a hash chain; the forester later appends them in batches via `BatchUpdateNullifierTree`, which is gated on `check_forester_authority` (`batch_update_nullifier_tree.rs:21-28`). So there is a real window between "spend accepted" and "nullifier in tree".

Live parameters (`program-libs/batched-merkle-tree/src/constants.rs:5-21`): two batches, 30 000 nullifiers each, 250 per ZKP batch (so 120 ZKP batches per batch), root history capacity 120, bloom filter 4 603 072 bits with 10 hashes (false-positive rate 1e-12 at capacity).

**What closes the window.** During the window the nullifier is in a bloom filter, and every spend checks both filters. A second spend is rejected outright. The interesting question is what happens when a filter is *cleared*, because at that instant the bloom protection disappears and the tree protection must already be in force.

Clearing is not forester-discretionary. `zero_out_previous_batch_bloom_filter` (`merkle_tree.rs:452-504`) is called automatically from inside the append path (`merkle_tree_update.rs:242`), and only fires when the previous batch is fully `Inserted` **and** the current batch is at least 50% full. At that moment it also calls `zero_out_roots(seq, root_index)` (`merkle_tree.rs:396-427`).

**The arithmetic, checked by hand.** When a batch finishes appending, `mark_as_inserted_in_merkle_tree` records `batch.sequence_number = tree.sequence_number + root_history_capacity` and `batch.root_index = r`, the index of the first root containing the batch's values (`batch.rs:392-417`, assignment at `:412-413`). Later, when the filter is cleared with `RH = 120`:

- `overlapping_roots_exist = seq > tree.sequence_number`. Each append increments the sequence by one (`merkle_tree_update.rs:222`), so if 120 or more roots have been written since `r`, the whole ring has turned over and every surviving root already contains the batch, so there is nothing to do, and the code correctly does nothing.
- Otherwise `num_remaining = seq - tree.sequence_number = 120 - appended_since`, and the loop zeroes `num_remaining - 1` roots starting from the oldest. The oldest index is `(r + 1 + appended_since) mod 120`; advancing `119 - appended_since` slots lands exactly on `r + 120 ≡ r (mod 120)`.

So precisely the roots older than `r` are zeroed, and `r` and everything newer survive. The code asserts this identity rather than assuming it (`merkle_tree.rs:422-425`).

**The handoff is therefore gapless.** Before clearing, the bloom filter rejects the replay. After clearing, every root a proof could still name contains the nullifier, so the circuit's non-inclusion proof is unsatisfiable. The two windows abut exactly; neither leaves a moment where a value is both absent from the filters and absent from every reachable root.

**Confirmed by execution, not only by the arithmetic above.** An existing library test, `test_zero_out` (`program-libs/batched-merkle-tree/src/merkle_tree.rs:903`), drives nine batch-state scenarios and asserts the strongest form of the property directly: after `zero_out_previous_batch_bloom_filter` runs with overlapping roots present, it rebuilds the expected account and zeroes *every* root slot except `root_index`, then asserts full equality (`:1283-1290`). The only root left standing is the one that already contains the batch. I ran it and it passes.

**That test does not run in CI.** It is gated behind the `test-only` feature, and no `just` recipe or workflow job builds this crate's tests: `rust.yml` runs `test-cli`, `test-shielded-pool`, `test-sdk-libs`, `test-programs`, `test-user-registry-litesvm`, and `test-client-integration`, none of which include `zolana-batched-merkle-tree`. Reproducing it needs `cargo test -p zolana-batched-merkle-tree --lib --features test-only`. The mechanism is correct and it is tested; the test simply is not wired up, so a regression in the one routine that closes this window would land silently. Wiring it in is a test-infrastructure change, not a program change, and it is the cheapest risk reduction available here.

The on-chain half of the root half is `get_nullifier_tree_root`, which rejects any zeroed slot (`program-libs/tree/src/lib.rs:238-250`, the `root == [0u8; 32]` check at `:246-248`), surfaced as `StaleNullifierRoot`. **I confirmed this by execution** (`zeroed_nullifier_root_slot_is_rejected`): a spend naming an unwritten root-history slot fails with 7015 before proof verification.

**Forester offline, slow, or malicious.** All three are liveness problems, not safety problems:

- *Offline or slow.* The queue fills; when a batch is `Full` and the other is not yet cleared, `insert_into_current_queue_batch` returns `BatchNotReady` (`queue.rs:41-48`) and spends stop. Nothing is double-spendable.
- *Malicious.* The forester cannot choose what to append: the leaves are fixed by the hash chain stored in the account, and the proof's `old_root` must match the live tree root or the update is evicted (`merkle_tree_update.rs:203-215`). It cannot clear a filter early, because clearing is a state-driven side effect of appending, not a separate instruction. The worst it can do is refuse to work.
- A batch cannot be refilled until its filter is cleared (`queue.rs:33-40`, `BloomFilterNotZeroed`), which prevents the filter from being reused while it still holds live values.

**Bloom-filter false positives** (1e-12 at capacity) reject a legitimate spend. That is a liveness cost, not a safety hole: false negatives are what would matter, and bloom filters have none.

## Within one proof, one transaction, one slot

- **Two input slots of one proof.** `transact` blocks this twice over. The circuit asserts pairwise distinctness unconditionally across all slots (`inputs.go:132-138`, `api.AssertIsDifferent`). The program blocks it independently: the first insert sets the bloom bits, the second finds them all set and fails. **Confirmed by execution**: `duplicate_nullifier_in_two_slots_is_rejected_by_the_queue` returns `NullifierTreeUpdateFailed` (7002), and the control test with distinct nullifiers reaches proof verification (7008) instead, which proves the queue and not the verifier is what fired.
- **The merge circuit is weaker here and it does not matter.** `spp_merge/circuit.go:212-219` gates distinctness on `bothReal`, so two dummy slots may carry the same value. The program's bloom filter rejects the duplicate insert regardless, so such a transaction self-reverts.
- **Two instructions in one Solana transaction.** Instructions execute sequentially against the same account data, so the second sees the bits the first set. **Confirmed by execution**: `spending_twice_in_one_transaction_is_rejected` returns 7002.
- **Two transactions in the same slot or block.** Every spend takes the tree account as writable, so Solana's scheduler serialises them; the second observes the committed filter state. Concluded by reading, not tested.
- **A replay in a later transaction.** **Confirmed by execution**: `replaying_a_landed_spend_is_rejected` lands a real Groth16-proved spend and then resubmits the byte-identical instruction. The proof is still valid the second time, because `transact` never advances the nullifier root history (only the forester does), so the roots it commits to have not moved. The nullifier queue is the only thing that can stop it, and it does, with 7002. This is the single most direct test of the invariant.

## Withdrawal atomicity

`process_transact_core` (`transact/processor.rs:130-177`) runs in a fixed order: write the tree including all nullifier inserts (`:130-141`), recompute `external_data_hash` (`:145-160`), verify the proof (`:168`), then settle (`:170-176`), then emit the event (`:177`).

Settlement is strictly after nullification and after verification, and every step returns `ProgramResult`. A failure at any point aborts the instruction and the runtime reverts all account writes, including the tree. There is no path that pays the public leg without recording the nullifiers, and no partial application: the tree write and the lamport/token movement share one instruction's success.

The reverse ordering (settle first, nullify second) would be the dangerous one, and it is not what the code does.

One adjacent guard worth noting: both public amounts set is rejected up front (`:126-128`), because the parser settles only one branch and the other proven leg would never move.

## Roots and history

A spend names a root by index, and `get_nullifier_tree_root` accepts **any** non-zero entry in the 120-slot ring (`program-libs/tree/src/lib.rs:238-250`). So historical roots are accepted, deliberately.

That is safe only because of the zeroing argument above: the moment a nullifier stops being covered by a bloom filter, every root old enough to prove its absence has been zeroed out of the ring, and zeroed slots are rejected. The bound on accepted root history is therefore not a fixed age; it is exactly "roots no older than the last cleared batch", enforced on chain by the zero check.

Two details I checked because they are easy to get wrong:

- **At genesis, slot 0 holds the empty-tree root and slots 1..119 are zero** (`merkle_tree.rs:269-277`). Non-inclusion against the empty-tree root succeeds trivially for any value, so early in a tree's life the root history offers no protection at all, and the bloom filter is carrying the whole invariant. That is sound, because a nullifier cannot leave the filter until its batch has been appended and the predating roots zeroed. But it does mean the two mechanisms are not redundant early on; they are strictly sequential.
- **The UTXO tree's root history is a separate question and not a double-spend vector.** Spending against an old UTXO root only proves the note once existed, which stays true; the nullifier check is what prevents reuse.

## Secondary finding: a chosen padding nullifier can wedge the queue

**This is not a double spend.** It cannot un-nullify a note or move value. It is an availability and fund-freeze bug in the same subsystem, found while tracing the above, and I am reporting it because it is severe and because the spec's stated worst case for this construct is incorrect.

**The gap.** A *padding* dummy input (`IsDummy = 1`, `DataHash = 0`) has its nullifier pin gated off: `assertEqualWhen(api, spendOrAddress, nullifier, in.Nullifier)` at `inputs.go:112` does not apply, and `AssertStrictlyOrdered` remaps a dummy to the trivial `0 < 1 < 2` (`inputs.go:177-180`). The public nullifier column is therefore free for the prover to choose. The program nevertheless inserts every column unconditionally (`transact/processor.rs:219-221`).

**Why that is exploitable.** The bloom filter only rejects values still in a live filter. A value already in the *tree* whose batch filter has been cleared passes the filter check, enters the queue, and then has no satisfiable append proof, because an indexed Merkle tree cannot take a duplicate. `find_low_element_index_for_nonexistent` returns `ElementAlreadyExists` (`program-libs/indexed-array/src/array.rs:204-222`, check at `:211-213`), so the forester cannot even build the witness. The batch's leaves are fixed by the hash chain in the account and there is no eviction path for a queued value, so the queue stalls permanently, both filters eventually fill, and every spend fails with `BatchNotReady`. Shielded balances in that tree become unspendable.

**The cheapest instance needs no waiting at all.** The indexed nullifier tree is initialised with element `0` (`sdk-libs/merkle-tree/src/indexed.rs:74-92`, `IndexedArray::new(BigUint::zero(), ...)` at `:81`), so `0` is a leaf from genesis. An attacker submits one `transact` whose padding dummy carries nullifier `0`.

**Both halves confirmed by execution:**

- `zero_nullifier_lands_on_chain_with_a_valid_proof`: a real Groth16-proved `transact` with a padding dummy carrying `0` **succeeds** on chain.
- `zero_is_already_a_nullifier_tree_leaf`: element `0` is present from genesis and appending it again fails.

Note the attacker needs no funds and no victim: a transaction whose inputs are *all* padding dummies is valid and lands (the pre-existing `transact_sends_valid_proof` test demonstrates exactly that shape). Cost is one transaction fee.

**Where this differs from the spec.** `docs/spec.md:970` addresses this construct and concludes: *"A re-prover can at most swap one random dummy nullifier for another … the worst case is a self-reverting duplicate-nullifier insertion, which cannot change real state."* Two things in that sentence do not hold:

1. The insertion is only self-reverting when the chosen value collides with something in a **live bloom filter**. A value in the **tree** with a cleared filter does not self-revert; it lands and wedges the queue.
2. The threat model is "a re-prover" sitting between signing and proving. The argument that "the sender builds the whole proof witness; no untrusted party sits between signing and proving" does not constrain an attacker who *is* the sender.

The spec also states that a dummy input "derives its nullifier over a random `blinding` with `nullifier_secret = 0`". That describes honest builder behaviour; the circuit does not enforce it. I have not edited `docs/spec.md`; it is read-only for this task and a spec worker is mid-amendment there.

**Related observation, same class.** An *address slot* (`IsDummy = 1`, `DataHash != 0`) has its nullifier pinned but its non-inclusion proof skipped, because the root binding at `inputs.go:124` is gated on `notDummy`. Address-slot uniqueness therefore rests entirely on the bloom filter, which is epoch-limited: an address slot created in one filter epoch could be re-submitted in a later one by its owner. Same wedge consequence, narrower reach (it needs the owner's `nullifier_secret`), and subsumed as an attack vector by the padding path.

**Minimal fix, described not applied.** The clean fix is in the circuit, not the program: pin a padding slot's nullifier column the same way a real spend's is, so it becomes a Poseidon image over witness values rather than a free choice. The prover still controls `blinding` and `nullifier_secret`, but hitting a chosen target then requires a preimage search at roughly 2⁻²⁵⁴, which is what makes the value unforgeable. Arity hiding is preserved, because the column stays indistinguishable from a real nullifier and the program keeps inserting all N. This changes `spp_transaction`/`spp_merge` and the verifying keys.

A program-only mitigation cannot be complete, because the program cannot tell a padding slot from a real one. Rejecting `nullifier_hash == 0` in `apply_tree` would close the cheap genesis instance but leave the general case (any previously-nullified value whose filter has been cleared) open. It is worth considering as a stopgap precisely because it is one comparison, but it should not be mistaken for a fix.

Per the standing instruction that this port changes SDK code only, I have applied neither. Both need an explicit exception.

## Agreement with the parallel merge investigation

`registry-merge-verification.md` had not landed when I finished, but that investigation's tests did (commit `cbf197e7`). Its finding: `merge_transact` validates its `user_record` only by owner program and discriminator, not that the record is the canonical registry record of the owner whose UTXOs are merged.

**I agree the binding is under-validated, and I find it does not create a double-spend path.** Substituting a `user_record` lets a caller claim a different owner identity and bypass the `merging_enabled` opt-in, but the merge circuit derives `userOwnerHash` from `UserNullifierSecret` and requires every real input's `Utxo.Owner` to equal it (`spp_merge/inputs.go:41`), so an attacker still needs the victim's `nullifier_secret` to satisfy the proof. Independently, nullifier insertion in `merge` is unconditional (`merge/processor.rs:146-148`) and does not read the `user_record` at all, so nothing about the record affects whether inputs are nullified. Their finding is an authorization and output-tagging issue; it does not touch this invariant.

## What I did not cover

Stated so the residual risk is visible rather than implied to be zero:

- **The root-zeroing property was verified in isolation, not end to end.** `test_zero_out` drives batch state by hand rather than by running a real forester through 120 append proofs, and my litesvm tests never advance a batch to the point of clearing. So I have execution evidence that the clearing routine zeroes the right roots, and reading plus arithmetic that the routine is reached with the right arguments on the live path. Closing that last step would need a full batch cycled through the forester with real proofs, which I judged too slow to build here. It is the single most valuable follow-up test.
- **The forester append circuit itself.** I established that a duplicate value has no satisfiable witness via the Rust reference implementation (`indexed-array`), not by running the Go `batch_address_append` circuit. If that circuit diverges from the reference, my wedge conclusion would need revisiting, though the divergence would have to be a soundness bug allowing duplicate insertion, which would be worse.
- **Same-slot concurrency was reasoned about, not executed.** I did not build a test that races two spends into one block. The argument rests on Solana serialising writers of the tree account, which is a runtime guarantee rather than a property of this code.
- **Multi-tree isolation.** `create_tree` can be permissionless (`create_tree.rs:21-27`) and `TransactAccounts` validates the tree only by owner and discriminator, not as a canonical PDA (`transact/account.rs:24-27`). I convinced myself this is not a double-spend vector, because a note's inclusion proof binds it to one tree's UTXO root and both roots in a spend come from the same account, but I did not test whether a second tree sharing the program-wide SOL/SPL vaults creates a *fund-conservation* problem. That is a different question and I flag it as unexamined.
- **The P256 rail and the zone/zone-authority variants were read, not executed.** My tests exercise the eddsa confidential rail only. The nullification code is shared across all of them, which is why I am comfortable with the enumeration, but the proofs I generated were 2×3 confidential eddsa.
- **`merge` and `merge_zone` were not exercised end to end.** Their nullification loop was read closely and is structurally the same as `transact`'s; I did not build merge proofs.
- **Bloom-filter false-positive behaviour at capacity** was not measured; I took the documented 1e-12 at face value, and it is a liveness parameter either way.
