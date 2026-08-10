# Recursive proofs

A recursive circuit verifies another circuit's proof. Five of them exist here.
Four lift a width their inner circuit cannot reach. The fifth batches legs that
could each settle alone.

## Terms

| Term | Meaning |
|---|---|
| leg | one inner proof, and the statement it proves, inside an outer proof |
| rail | the ownership and signature path a transact takes, such as confidential, ring eddsa, ring authority, or P256 |
| shape | the input and output counts a circuit is compiled for, written `(inputs,outputs)` or `2x3` |
| fold | an outer circuit that proves a run of legs advances one state or describes one account |
| span | the run of consecutive forester zkp batches one fold settles |
| slot | one position in a batch, with the inner verifying key that position accepts |

## How it works

Recursion is BN254 in BN254, because the on-chain verifier is BN254. The inner
scalar field is emulated in the outer field. The emulation makes an inner
verification expressible as constraints, and makes it expensive.

Three properties hold for every outer circuit below.

#### The inner verifying key is a compile-time constant

It is not a witness, so the outer verifying key alone names which inner circuit
a proof verified. A selector can therefore bind an outer proof to one rail,
shape, or tree without carrying the inner key in instruction data, and a proof
under another key is rejected rather than merely unexpected. A constant cannot
name a key this repository does not own, and
[alt-designs/recursion_proof_design.md](alt-designs/recursion_proof_design.md)
holds the unbuilt design for that case.

#### Legs are taken unchanged

A leg keeps the form the on-chain rail produced. A leg whose own circuit carries
a BSB22 commitment needs `stdgroth16.WithNativeHashToField`, which derives the
commitment challenge with RFC 9380 `expand_message_xmd` over SHA-256, the way
the native prover does. gnark's default is MiMC, which no proof sent on chain
uses. `spp_aggregate` and both squads folds pass it. `nullifier_fold` and
`spp_merge_chain` do not, because the append and merge circuits declare no
commitment. This is most of the gap between the uncommitted and committed
per-leg costs in the catalogue below.

#### The emulated public input is read through `ToBitsCanonical`

The read asserts the decomposition is below the modulus. A plain limb
recomposition would admit a second representation and let a leg claim a public
input it did not prove.

### Opening a public input

An outer circuit sees each leg's public input as one emulated field element. It
can chain those elements, but it cannot say anything about what is inside them.

`gadget.OpenPublicInput` closes that gap. It takes the leg's public-input
preimage as a witness, recomputes `gadget.HashChain` over it, and asserts the
result equals the opened emulated value. After that the outer circuit can
constrain the preimage fields directly.

Every outer circuit below except `spp_aggregate` uses it. `spp_aggregate` calls
only the `OpenEmulatedInput` half, which does the canonical read without binding
a preimage, because order is its whole statement.

The gadget's security surface is that a leg whose claimed preimage does not hash
to its public input is rejected, tested by
`TestOpenPublicInputRejectsAWrongPreimage` and
`TestOpenPublicInputRejectsAReorderedPreimage`.

### Three continuity shapes

What holds a run together differs by case, and the shape decides what the outer
circuit must assert.

| Shape | Predicate | Circuit |
|---|---|---|
| independent legs | none, only order | `spp_aggregate` |
| produced then consumed | an earlier leg produces a later leg's input | `nullifier_fold`, `spp_merge_chain` |
| equality across legs | every leg agrees on the fields the account holds once | `squads_zone_fold`, `squads_key_encryption_fold` |

Independent legs need no preimage: order alone is the statement, so chaining the
opaque public inputs is enough. The other two need it, because their predicate is
about values inside a leg's public input. `nullifier_fold` runs the dependency as
a line, one root and index step per leg. `spp_merge_chain` runs it as a tree,
where a leg's chained slot holds an output no tree ever saw.

## What recursion buys

Every circuit here has a fixed input width, and widening one costs a trusted
setup per width. Recursion buys the width with one ceremony instead of one per
width.

| Cap | Consequence above it | What lifts it |
|---|---|---|
| `merge` 8 to 1, fixed | consolidation takes several sequential rounds | `merge_chain_transact` |
| forester append batch, 10 or 250 at height 40 | one transaction per zkp batch | `batch_update_nullifier_tree_folded` |
| Squads key encryption, 1 to 3 keys | an account with more keys cannot be proved at all | `squads/key_encryption_fold` |
| Squads zone transfer, (1,1) and (2,2) | three UTXOs cannot be spent together | `squads/zone_fold` |

Recursion is not a throughput mechanism. `transact` already spans 5 inputs and 8
outputs, so one party rarely needs a second proof, and the outer proof costs one
to two orders of magnitude more prover time than the legs it replaces. It trades
prover time for transactions and on-chain compute.

#### UTXO fragmentation

Every received payment mints a UTXO, and `merge` collapses 8 at a time. The
rounds are sequential, because round two needs round one's outputs in the tree
under an advanced root. `merge_chain_transact` feeds an intermediate output
straight into the next level instead, so the rounds collapse into one
transaction and the ceiling becomes the transaction size.

#### Forester nullifier appends

Address appends are strictly sequential on chain. Each checks its old root
against the tree's current root, so the forester submits one transaction per zkp
batch. A fold proves the whole span advanced the root correctly and settles it
in one.

#### Recipient keys on a Squads account

The key-encryption circuit is keyed by count and supports 1, 2, or 3, counting
recovery keys plus auditors, while `ViewingKeyAccount` is sized for more than
that. Folding legs that must agree on the shared viewing key, its commitment,
and the shared ephemeral key reaches 6 and 9.

#### Three UTXOs in one zone spend

Zone transfer has keys for (1,1) and (2,2) only. Folding two legs spends 4 and
three legs spends 6, padded down with the dummy-input flag.

## What is built

Each settles through its own instruction and verifies with `verify_groth16`
unchanged: an outer proof is an ordinary BSB22 Groth16 proof with one public
input, so no new syscall is involved.

| Circuit | Instruction | Predicate | End-to-end test |
|---|---|---|---|
| `spp_aggregate` | `aggregate_transact`, tag 18 | order only | `aggregate_reports_compute` (`shielded-pool-tests`) |
| `nullifier_fold` | `batch_update_nullifier_tree_folded`, tag 19 | root and index continuity | `nullifier_tree_folded_run_matches_sequential_appends` |
| `spp_merge_chain` | `merge_chain_transact`, tag 20 | chained slot equality | `merge_chain_collapses_fifteen_utxos_in_one_transaction` |
| `squads/zone_fold` | `fold_transact`, tag 17 (zone) | shared account fields | `three_utxos_spend_together_under_one_fold` |
| `squads/key_encryption_fold` | zone account creation | shared viewing key | `a_wider_key_set_than_any_leg_proves_is_provable` |

### Forester nullifier fold

`batch_update_nullifier_tree_folded`, tag 19, advances an address tree by a run
of consecutive zkp batches against one proof. `forester/src/run.rs` submits one
transaction per run instead of one per batch. `--fold-run N` selects the width,
and `fold_span` falls back to single appends when fewer than N batches are
ready, tested by `fold_span_folds_only_at_the_configured_width` and
`a_run_of_five_folds_into_two_spans_and_a_single`.

#### Statement

`BatchAddressTreeAppendCircuit` binds
`PublicInputHash = HashChain(OldRoot, NewRoot, HashchainHash, StartIndex)`. The
fold opens that preimage per leg and asserts, for every adjacent pair, that
`OldRoot_{i+1} == NewRoot_i` and `StartIndex_{i+1} == StartIndex_i + BatchSize`.
Its own public input is
`HashChain(OldRoot_0, NewRoot_N, HashChain(hashchain hashes), StartIndex_0)`.

`BatchSize` is a compile-time constant taken from the inner key, so the index
step is fixed rather than witnessed.

#### Root history

A fold appends one root for the whole run. What that changes for a client is
stated in [spec.md](spec.md#batch_update_nullifier_tree_folded).

Photon reads the root from the instruction payload, and the folded payload is
`(run, inputs)` rather than the plain one, so it decodes the two shapes
separately. `parses_folded_batch_update_instruction` pins that, and
`folded_payload_is_not_read_as_an_unfolded_one` pins that neither is read at the
other's offsets.

The instruction applies only at the head. The run must be finalized and start at
the pending zkp batch, so `StartIndex_0` is the tree's current next index rather
than a caller-supplied offset. `old_root` is checked against
the account root before verifying, so a span from another tree state costs no
pairing.

#### Security invariants

One rejection test per guard, in `prover/server/circuits/nullifier_fold`:

| Invariant | Test |
|---|---|
| Adjacent legs must share a root | `TestFoldRejectsARootGap` |
| The index must advance by exactly one batch | `TestFoldRejectsAnIndexGap` |
| A leg cannot claim a span its proof did not commit to | `TestFoldRejectsAPreimageTheProofDidNotCommitTo` |
| A claimed span the fold did not prove is rejected | `TestFoldRejectsAWrongFoldHash` |
| A proof under another key is rejected | `TestFoldRejectsAProofForAnotherKey` |
| A run of one does not amortize and is rejected | `TestNewCircuitRejectsAnUnamortizedRun` |

`TestFoldVerifyingKeyMatchesTheOnChainVerifier` pins the generated key against
the committed constant, and `TestFoldConstraintCost` pins the circuit size.

| run | constraints |
|---:|---:|
| 2 | 1,472,103 |
| 3 | 2,175,073 |

### Merge chain

`merge_chain_transact`, tag 20, collapses more than eight UTXOs by feeding an
intermediate merge output straight into the next level. Only the top leg's
output is appended, and every level below stays inside the proof, so the rounds
that a plain merge runs sequentially collapse into one transaction.

#### Shape

A level shape names the tree: legs per level, bottom level first, top level
one. Level 0 legs spend only tree-backed UTXOs, and every later level consumes
the level below in order, up to eight per leg, with its remaining slots filled
from the tree. Chained slots take the high slots of a leg, so the tree-backed
inputs keep a contiguous low range.

Every leg but the top one fills exactly one slot above it, so a chain of L legs
spends 7L+1 UTXOs out of the state tree. Arity is eight because the merge public
input exposes eight per-slot input UTXO hashes. Opening its private tx hash
reaches all eight, and a chained slot is bound by that hash alone.

Constraint counts are pinned by `TestChainConstraintCost`. The packet column is
the whole transaction, not the instruction data alone.

| levels | legs | tree inputs | constraints | packet fits 1232 |
|---|---:|---:|---:|:---:|
| 1 1 | 2 | 15 | 1,499,221 | yes |
| 2 1 | 3 | 22 | 2,215,367 | no |

#### Statement

The outer proof has one public input, and its preimage is a single merge's
widened: the per-slot nullifiers, UTXO roots, and nullifier roots run over every
tree-backed slot of every leg in leg then slot order, the private tx hashes of
the legs are chained where a merge carries one, and the output is the top leg's.

A chained slot spends a UTXO no tree holds, so its inclusion witness is against
a root the prover picks. That root never leaves the outer proof, and nothing but
the chained equality says the UTXO existed.

Every leg folds the same external data hash, which names this instruction, the
expiry, and the output the pool inserts. A leg whose own output stays inside the
proof is still bound to the transaction that settles it.

#### Security invariants

In the circuit, tested in `prover/server/circuits/spp_merge_chain`:

| Invariant | Test |
|---|---|
| A chained slot must spend the output the level below produced | `TestChainRejectsASlotTheLevelBelowDidNotProduce` |
| A leg cannot restate the statement its proof committed to | `TestChainRejectsAPreimageTheProofDidNotCommitTo` |
| A per-slot vector must match the fold the proof committed to | `TestChainRejectsATamperedSlotVector` |
| Legs must agree on the external data hash, dummy policy, and signing key | `TestChainRejectsALegThatDisagreesOnTheSharedIdentity` |
| A UTXO cannot be spent by two legs | `TestChainRejectsANullifierSpentTwice` |
| A claimed statement the chain did not prove is rejected | `TestChainRejectsAWrongChainHash` |
| A proof under another key is rejected | `TestChainRejectsAProofForAnotherKey` |
| A level shape that does not close is rejected | `TestNewShapeRejectsATreeThatDoesNotClose` |

End to end, `merge_chain_collapses_fifteen_utxos_in_one_transaction` deposits
fifteen UTXOs, collapses them with two legs and one recursive proof, and asserts
that fifteen nullifiers queue, one output appends, and the packet fits 1232
bytes.

### Aggregate transact

`aggregate_transact`, tag 18, settles a batch of `transact` legs against one
recursive proof. It is the only case here that lifts no width cap: it batches
legs that could each settle alone. Its caller is a program that already produces
several proofs per transaction, which today is the swap example below.

A selector variant that carries the batch inside `transact` was considered and
not built, compared in
[alt-designs/recursive_selector.md](alt-designs/recursive_selector.md).

A batch needs the 4096-byte transaction SIMD-0296 introduces. No batch fits the
1232-byte limit that precedes it, and address lookup tables do not help, because
the instruction data alone is already over.

Two crates ship a test target named `aggregate_cu`, and they measure different
things. `aggregate_reports_compute`, in the `shielded-pool-tests` target, runs
under litesvm, which runs the real SVM and the real `alt_bn128` syscalls without
enforcing the packet size, so it reports the compute of a batch that no
validator would accept today. `aggregate_ring_eddsa_reports_cost` and
`aggregate_ring_p256_reports_cost`, in the `ring-test-program` target, run
against a validator and Photon, and report the sizes as well as the compute of
what fits.

The instruction compiles in unconditionally.

#### Statement

The outer proof has one public input: the Poseidon chain over the leg public
input hashes, in batch order. The chain is a left fold, so batch order is part
of the statement. The circuit builds it with `gadget.HashChain` and the program
with `create_hash_chain_from_slice`.

A leg keeps the instruction discriminator it would carry alone, so one proof is
valid both alone and inside a batch.

#### Instruction flow

Per leg, in order, the program runs the `transact` pipeline except the pairing
and keeps the public input hash. It then chains the hashes and verifies the
outer proof once.

Each leg declares how many accounts it consumes: payer, input tree, output
tree, the SPP and System Program accounts, the ring config on a ring rail, then
owner signers and settlement accounts. A declared count is needed because the
transact parser finds owner signers by scanning for the first non-signer, which
is ambiguous once leg runs are concatenated. The counts are
attacker-controlled, so the batch checks their total against the account list
before any leg settles.

A leg carries no proof and no BSB22 commitment. Neither is part of the
statement, so both are rejected when non-zero.

#### Outer circuit

`prover/server/circuits/spp_aggregate` verifies each batched proof against one
compile-time inner verifying key, then asserts the chain. It is the only outer
circuit that never binds a leg's public-input preimage, because batch order is
the whole statement.

#### Security invariants

Rejected before any pairing, tested in
`program-tests/shielded-pool/tests/aggregate/guard.rs`.

| Invariant | Test |
|---|---|
| A batch size with no key is rejected | `aggregate_rejects_a_batch_size_with_no_key` |
| Leg count must equal the selector's batch | `aggregate_rejects_a_leg_count_that_disagrees_with_the_selector` |
| A leg of another rail is rejected | `aggregate_rejects_a_leg_from_another_rail` |
| A leg of another shape is rejected | `aggregate_rejects_a_leg_of_another_shape` |
| A leg carrying a proof is rejected | `aggregate_rejects_a_leg_that_carries_a_proof` |
| A leg carrying a commitment is rejected | `aggregate_rejects_a_leg_that_carries_a_commitment` |
| An account list that does not split is rejected | `aggregate_rejects_an_account_list_that_does_not_split` |

In the circuit, tested in `prover/server/circuits/spp_aggregate`:

| Invariant | Test |
|---|---|
| A claimed chain the batch did not prove is rejected | `TestAggregateRejectsAWrongAggregateHash` |
| A reordered batch is rejected | `TestAggregateRejectsAReorderedBatch` |
| A proof under another key is rejected | `TestAggregateRejectsAProofForAnotherKey` |

Selector to key resolution is fail closed in both directions, tested by
`support_and_keys_agree` in `program-libs/interface/tests/aggregate_circuit.rs`.

### Squads folds

`squads/key_encryption_fold` and `squads/zone_fold` lift the two Squads width
caps. They differ from the folds above in their predicate. The legs are
parallel statements about one account rather than a state chain, so what holds
a run together is equality on the fields that account holds once.

Each fold's public input carries those shared fields once and every leg's own
fields after them. Reading the shared half from the first leg is sound only
because of the equality assertions. Without them a later leg could encrypt a
different viewing secret, or spend another account, and the chain the program
recomputes would still match.

For key encryption the resulting chain is exactly what a single circuit of the
summed width would expose, so `select_key_encryption_vk` resolves a folded
count to a fold key and nothing else in the program changes. Six and nine keys
have a key.

For the zone, `private_tx_hash` binds a leg's whole input and output set, so no
leg continues another. Each keeps its own SPP proof and settles through its own
`ring_transact`. `fold_transact` (tag 17) verifies the fold once and forwards
one CPI per leg. A leg carries no proposal, because a proposal commits to one
recipient amount and a folded run would settle it once per leg.

Constraint counts are pinned by the `size_test.go` of each fold package.

| fold | leg | legs | constraints |
|---|---|---:|---:|
| key encryption | 3 keys | 2 | 2,583,619 |
| key encryption | 3 keys | 3 | 3,776,084 |
| zone | 2x2 transfer | 2 | 2,576,895 |
| zone | 2x2 transfer | 3 | 3,766,715 |

Both track the committed aggregate family, because both leg circuits expose one
public input and one BSB22 commitment from their emulated P-256 arithmetic.

A fold covers leg width times leg count and nothing between, so the reachable
recipient counts are 6 and 9 and the reachable UTXO counts are 4 and 6, padded
down with the dummy-input flag. A count between them needs another leg width.
Adding 2 to `keyEncryptionFoldSupportedKeys` and its two mirrors reaches 4, at
the cost of one more setup per leg count.

#### Security invariants

One rejection test per equality the fold asserts, in
`prover/server/circuits/squads/key_encryption_fold`:

| Invariant | Test |
|---|---|
| Legs must agree on the account state they extend | `TestFoldRejectsADisagreeingOldStateHash` |
| Legs must agree on the shared viewing key | `TestFoldRejectsADisagreeingSharedViewingKey` |
| Legs must agree on its commitment | `TestFoldRejectsADisagreeingCommitment` |
| Legs must agree on the shared ephemeral key | `TestFoldRejectsADisagreeingEphemeralKey` |
| Legs must agree on the nullifier pair | `TestFoldRejectsADisagreeingNullifierPair` |

and in `prover/server/circuits/squads/zone_fold`:

| Invariant | Test |
|---|---|
| Legs must agree on the sender | `TestFoldRejectsADisagreeingSender` |
| Legs must agree on the recipient | `TestFoldRejectsADisagreeingRecipient` |
| No leg may carry a proposal | `TestFoldRejectsALegCarryingAProposal`, `TestFoldRejectsAProposalOnTheFirstLeg` |

Both folds share the four guards every opening fold needs:
`TestFoldRejectsAPreimageTheProofDidNotCommitTo`,
`TestFoldRejectsReorderedLegs`, `TestFoldRejectsAWrongFoldHash`, and
`TestFoldRejectsAProofForAnotherKey`.

## Keys

Every outer key is local. None is published, none is in the lockfile, and none
has a CI job. Groth16 setup is not deterministic, so two machines that run the
same setup get different verifying keys.

That has two consequences the scripts exist to handle.

#### The inner key must be the pinned one

A regenerated inner key carries a different verifying key, and an outer key
compiled against it would embed one that no on-chain constant matches.
`setup-aggregate`, `setup-nullifier-fold`, and `setup-merge-chain` each check
the inner key against the lockfile before they run. The squads leg keys are
local too, so `generate_keys_squads.sh` makes the leg keys and the folds
compiled against them in one pass.

#### A key rewrites its own committed constant every time

Each script skips a key already on disk but still re-exports its constant. A
script that rewrote only the keys it generated would leave a machine that
already holds keys pinned to constants from an earlier generation. The programs
must be rebuilt before they verify that key's proofs.

| Circuit | Script | Recipe |
|---|---|---|
| `spp_aggregate`, `spp_merge_chain` | `generate_keys_aggregate.sh` | `just test-aggregate` |
| `nullifier_fold` | `generate_keys_nullifier_fold.sh` | `just test-nullifier-fold` |
| squads legs and folds | `generate_keys_squads.sh` | squads SDK tests |

Each recipe regenerates, rewrites, and rebuilds in that order, so a machine
holding no keys reproduces the catalogue. Run them in the order the standing gates list them.
`verifying_key_fingerprint_is_pinned` covers these local keys, so a regeneration
invalidates it until the constants are committed.

### Outer key catalogue

One outer key per rail, shape, and batch size. Outer cost follows the inner
public input and commitment counts, not the inner circuit size, so two families
cover the catalogue. Uncommitted inner circuits are confidential, ring, ring
authority, and swap take. The committed inner circuit is P256.

Every `AssertProof` runs with `stdgroth16.WithFixedVerifyingKey` from the gnark
fork. The public-input MSM goes through fixed-base combs over the constant K
points, and the final exponentiation folds the precomputed `ML(-alpha, beta)`
into a residue witness check. The inner keys were already compile-time
constants, so the statement is unchanged and the outer verifying key keeps the
one-input, one-commitment shape the shielded pool parses.

Compiled against the pinned inner keys and pinned by `TestAggregateCompileCost`:

| family | batch | constraints | levels | domain |
|---|---:|---:|---:|---:|
| uncommitted | 2 | 1,059,358 | 405 | 2^21 |
| uncommitted | 3 | 1,556,316 | 405 | 2^21 |
| uncommitted | 4 | 2,053,274 | 588 | 2^21 |
| uncommitted | 5 | 2,550,232 | 783 | 2^22 |
| committed | 2 | 2,021,698 | 2,677 | 2^21 |
| committed | 3 | 2,934,159 | 2,677 | 2^22 |
| committed | 4 | 3,846,620 | 2,677 | 2^22 |
| committed | 5 | 4,759,082 | 2,677 | 2^23 |

The per-leg cost is the difference between adjacent batch rows, which
`TestAggregateCompileCost` pins with them. The level count is the solver depth,
which bounds witness-generation parallelism on the device route.

### Mixed batches

A batch is an ordered slot list, one fixed inner verifying key per slot, with
the same Poseidon chain over the leg hashes in slot order. A uniform list is the
degenerate case and keeps its key names and file format. Slot order is part of
the statement twice over. The chain is a left fold, and slot i accepts only
proofs under key i, tested by `TestAggregateRejectsMixedLegsInSwappedSlots`.

Every slot key must expose one public input. The swap take circuit fits
(`TestTakeKeyFitsAnAggregateSlot`), so a fill and the legs that settle it share
one outer proof, which `take_batch` needs.

The catalogue holds two mixed shapes rather than the cross product:

| key | slots |
|---|---|
| `aggregate_mix_swap_take-transfer_confidential_2_2_b2` | take fill, confidential settlement |
| `aggregate_mix_transfer_confidential_2_2-transfer_ring_2_3_b2` | confidential, ring pair |

Both are uncommitted-family shapes and match the uniform batch-of-two row.
Mixed keys use `aggregate_mix_<slot>-<slot>_b<n>.key` with slots in batch order
and a key file header that lists them. `setup-aggregate-mix` runs the setup and
takes one `--slot` per leg, either an inner key file for a transfer rail or
`swap-take:<raw-vk-file>` for the take circuit.

The outer circuit keeps exactly one BSB22 commitment for every shape, uniform or
mixed, committed or not. That commitment comes from the emulated range checker,
not from the batched proofs.

### Device route

Two device-witness properties are checked per shape at compile time, by
`TestAggregateCompileCost` and `TestMixedAggregateCompileCost`.

- No compiled shape contains a `BlueprintLookupHint`, the committed family
  included. The in-circuit SHA-256 of the native hash-to-field lowers to plain
  R1CS, so the tape exporter's lookup refusal reaches none of the catalogue.
- Every shape keeps exactly one BSB22 commitment, so the single-commitment
  device path holds.

The tape carries one host-fallback hint family,
`millerLoopAndCheckFinalExpHint`, one call per leg.
