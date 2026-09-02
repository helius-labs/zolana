# Batched Merkle Tree

This crate maintains a height-40 indexed Merkle tree parametrized by its
input queue of `N` batches (`N` = 2 in the current layout). This document specifies nullifier queue insertion, batch append, and
nullifier-PDA cleanup. Initialization is out of scope.

## State

Let:

| Symbol | Meaning |
| --- | --- |
| `B` | values per queue batch (`batch_size`) |
| `Z` | values per ZKP batch (`zkp_batch_size`) |
| `K` | ZKP batches per queue batch: `B / Z` |
| `c` | batch currently receiving values |
| `p` | batch currently being appended to the tree |
| `N` | queue batch count (`2` in the current layout) |
| `RH` | root-history capacity, derived as `B / Z` |
| `q` | next zero-based input-queue sequence number |
| `w` | exclusive queue-sequence PDA-close watermark (`close_before_index`) |

The tree is a program-derived account. It holds the queue, root history, and
lamports used as working capital for nullifier PDAs.

The account header also holds the fee schedule and the fee balance:

| Offset | Field | Meaning |
| --- | --- | --- |
| 0 | `discriminator: u8` | account type |
| 1 | `state: u8` | `UNINITIALIZED`, `INITIALIZED`, or `PAUSED` |
| 2 | `tree_id: u16` | id assigned at creation |
| 4 | padding | 4 bytes |
| 8 | `fees.fee_per_nullifier: u64` | lamports charged per queued nullifier |
| 16 | `fees.append_reimbursement: u64` | lamports paid per applied ZKP batch |
| 24 | `fees.close_reimbursement: u64` | lamports paid per closed PDA |
| 32 | `fee_balance: u64` | collected fees not yet paid out |
| 40 | reserved | 32 bytes |
| 72 | UTXO tree | `UtxoTreeLayout` |
| 7544 | nullifier tree | `NullifierTreeLayout` |

The schedule is runtime state: `create_tree` writes it and `set_tree_fees`
overwrites it; neither checks the values. `TreeFeeSchedule::at_cost` derives
the smallest `fee_per_nullifier` satisfying

```text
fees.fee_per_nullifier * Z >= fees.append_reimbursement + Z * fees.close_reimbursement
```

so one ZKP batch of insertions collects at least what its append and its `Z`
PDA closes pay out, but the fee authority may store any schedule.
`fee_balance` is the lamport amount owed to future reimbursements; both
payouts are capped by it (`min(owed, fee_balance)`), so the balance never goes
negative and an insolvent schedule never fails an update.
The lamport invariant

```text
tree.lamports >= rent_minimum + fee_balance
```

separates the fee pool from the working capital: PDA creation floors the tree
at `rent_minimum + fee_balance` and never borrows from collected fees.

The queue holds `N` batches. Each batch stores `K` hash-chain
commitments, `K` cached tree updates, and:

```rust
struct Batch {
    state: Fill | Full | Inserted,
    start_index: u64,
    num_inserted: u64,              // queued values in the open ZKP batch
    num_full_zkp_batches: u64,      // finalized hash chains
    num_inserted_zkp_batches: u64,  // finalized ZKP batches applied to the tree
    sequence_number: u64,           // reserved for account-layout compatibility
    root_index: u32,                // reserved for account-layout compatibility
}
```

```text
0 <= num_inserted_zkp_batches <= num_full_zkp_batches <= K

RH = K

unapplied_values =
    (num_full_zkp_batches - num_inserted_zkp_batches) * Z
    + num_inserted

inserted_elements = num_full_zkp_batches * Z + num_inserted

first_sequence(batch) = batch.start_index - 1

reclaimable(batch) = w >= first_sequence(batch) + B

batches[p].state != Inserted =>
    tree.next_index =
        batches[p].start_index + batches[p].num_inserted_zkp_batches * Z

next_queued_leaf_index = q + 1

tree.next_index <= next_queued_leaf_index <= tree.capacity

accepted_root(i) = i < RH and root_history[i] != 0
```

Initialization fills leaf zero and sets `q = 0`, `tree.next_index = 1`, and
`batches[i].start_index = 1 + i * B` for `0 <= i < N`. Queue sequence `x`
reserves leaf `x + 1`. Leaves in `[tree.next_index, q + 1)` are queued but not
yet appended to the tree.

`RH = K` keeps exactly one queue batch's worth of update roots. Fully applying
the successor batch therefore overwrites every root that predates it.

`Fill --B queue insertions--> Full --final ZKP append--> Inserted --reuse--> Fill`.
A finalized ZKP batch may be appended while its queue batch is still `Fill`.
Reclaimability governs PDA cleanup independently of this storage-reuse state
machine.

Each queued nullifier has an exact PDA account:

```text
PDA = canonical_pda(
    program_id,
    ["nullifier", tree_pubkey, nullifier],
)
```

```rust
// Borsh-serialized length: 10 bytes.
struct NullifierPda {
    queue_index: u64,
    tree_id: u16,
}
```

The queued nullifier and the PDA seed use the same canonical 32-byte field
encoding. Values outside the field are rejected, not reduced modulo the field.

## Insert into queue

**Description.** Creates an exact nullifier PDA and adds the nullifier to the
current batch's open hash chain. The PDA prevents the same pending nullifier
from being queued twice; the hash chain commits queue order for the later batch
proof.

**Input**

```rust
nullifier: [u8; 32]
```

The instruction also receives the writable PDA.

**Checks and state changes**

1. Require the nullifier-tree type and canonical nullifier encoding.
2. Require `batches[c].state == Fill`. If it is `Inserted`, reuse it first;
   reuse resets its counters and advances `start_index` by `N * B` without
   waiting for the batch's PDAs to become reclaimable. `Full` is not
   reusable.
3. Require
   `q + 1 = batches[c].start_index + batches[c].inserted_elements` and
   `q + 1 < tree.capacity`.
4. Derive the canonical PDA and bump. Require the supplied address to
   match. An initialized PDA fails with
   `ShieldedPoolError::NullifierAlreadyQueued` (7048).
5. Accept an unused PDA that is System-owned, empty, and optionally
   prefunded. Transfer only its missing rent-exempt balance from the tree, then
   allocate ten bytes, assign it to the program, and store `{ q, tree_id }`
   with the tree header's `tree_id`.
6. Let `j = batches[c].num_full_zkp_batches`. Update the open commitment:

   ```text
   hash_chains[c][j] = nullifier                              if num_inserted == 0
   hash_chains[c][j] = Poseidon(hash_chains[c][j], nullifier) otherwise
   ```

7. Increment `num_inserted`. When `num_inserted == Z`, finalize the commitment,
   increment
   `num_full_zkp_batches`, and reset `num_inserted` to zero. When
   `num_full_zkp_batches == K`, set the batch to `Full` and advance `c` modulo
   `N`.
8. Increment `q` once.
9. Charge `fees.fee_per_nullifier` from the transaction payer to the tree
   (System transfer) and add the same amount to `fee_balance`. The inserting
   instruction charges once per input, before it funds the PDAs, so the PDA
   rent check in step 5 sees the tree floored at `rent_minimum + fee_balance`.

PDA creation, fee collection, and queue mutation are atomic. Failure changes
none of them.

**Property — pending non-inclusion.** A successful insertion makes every later
queue insertion of the same nullifier fail while its PDA exists. The check
has no false positives. Non-inclusion against nullifiers already in the Merkle
tree is proved by the transaction proof.

**Property — ordered commitment.** Every finalized hash chain commits exactly
`Z` values in queue order.

## Batch append

**Description.** Verifies an indexed-append proof for one finalized hash chain,
caches proofs submitted out of order, and applies the longest contiguous cached
prefix. Each applied proof dequeues `Z` values: the tree root becomes
`new_root` and `tree.next_index` advances by `Z`.

**Instruction data**

```rust
struct BatchAppendInputs {
    new_root: [u8; 32],
    old_root: [u8; 32],
    zkp_batch_index: u16,
    compressed_proof: CompressedProof, // a[32] || b[64] || c[32]
}
```

**Proof statement**

For pending batch `p`, requested ZKP batch `i`, and
`a = batches[p].num_inserted_zkp_batches`:

```text
start_index = tree.next_index + (i - a) * Z
leaves_hash = hash_chains[p][i]

public_input = HashChain(
    old_root,
    new_root,
    leaves_hash,
    u256_be(start_index),
)

HashChain(x0, ..., xn) = Poseidon(...Poseidon(Poseidon(x0, x1), x2)..., xn)
```

The Groth16 proof establishes the height-40 indexed append from `old_root` to
`new_root` for the ordered values committed by `leaves_hash`, starting at
`start_index`. Supported `Z` values are `10` and `250`.

**Checks and state changes**

1. Require `i` to fit the cache and `i < num_full_zkp_batches`.
2. If `i < a`, the update is already applied and the call is a no-op.
3. Derive `start_index` and `public_input`, verify the proof, then cache
   `{ old_root, new_root }` at `[p][i]`, replacing any occupied value.
4. Repeatedly select the next required slot
   `i = batches[p].num_inserted_zkp_batches`. Stop when the slot is empty.
5. Require the cached `old_root` to equal the current tree root. On mismatch,
   evict that slot and stop without applying it; a correct proof may be
   resubmitted.
6. Require capacity for `Z` leaves, then apply the update:

   ```text
   tree.next_index     += Z
   tree.sequence_number += 1
   root_history.push(new_root)
   num_inserted_zkp_batches += 1
   ```

7. Clear the applied cache slot. Continue from step 4 so one call may apply
   several previously cached proofs.
8. When all `K` ZKP batches are applied, set the queue batch to `Inserted` and
   advance `p` modulo `N`.
9. On that final applied update, let `current_index` be the `p` used for the
   update (before step 8 advances it) and let:

   ```text
   current = batches[current_index]
   ```

   At this point `current.state == Inserted` and its `K = RH` applied updates
   have naturally overwritten every root that predates `current`. Set
   `w = max(w, first_sequence(current))`. This makes PDAs from every earlier
   batch reclaimable regardless of whether that batch has already been reused
   and returned to `Fill`. No root-history slots are explicitly zeroed. These
   changes are atomic.
10. When the call applied `num_update >= 1` updates, pay
    `min(fees.append_reimbursement * num_update, fee_balance)` from the tree
    to the writable `reimbursement_recipient` account and subtract the paid
    amount from `fee_balance`. The recipient must not be program-owned
    (`ShieldedPoolError::InvalidReimbursementRecipient`, 7055), checked before
    any state change. A short fee balance pays what it holds and never fails
    the update, so a fee increase cannot stall the queue. A call that only
    caches or evicts pays nothing.

**Property — queue draining.** One applied update reduces
`unapplied_values` by exactly `Z`. After all `K` updates, the batch has
`unapplied_values == 0`, is `Inserted`, and is no longer pending. Its
hash-chain bytes remain until overwritten on reuse. Its PDAs remain until
separate cleanup transactions close them.

**Property — reclaim liveness.** When the current batch's final ZKP update is
applied, `w` reaches `first_sequence(current)`, so every PDA from the
previous batch is reclaimable even if that batch has already been reused.
Reclaimability never gates batch storage reuse.

**Property — ordered application.** Proofs may arrive in any order, but roots
are applied only in increasing ZKP-batch order and only when each `old_root`
equals the live root.

**Property — public input.** The single Groth16 public input is the hash of
`old_root`, `new_root`, `leaves_hash`, and `start_index`; changing any of them
changes the public input.

**Property — replay.** A proof for an already applied ZKP batch (`i < a`) is
not verified and changes no state. A proof for an occupied slot is verified
and, if valid, replaces the cached update. The apply pass runs after every
cache, so slot `a` is empty between calls and an occupied slot is ahead of `a`;
its replacement changes neither the tree nor the queue in that call. A later
apply pass applies the replacement if its `old_root` matches and evicts it
otherwise.

The overwrite rule is a recovery mechanism: if a forester caches a verified
update built from the wrong starting state, a corrected update for the same
committed hash chain and start index can replace it before application. The
trade-off is a liveness-only griefing surface: a valid proof from the wrong
starting state can also replace an honest future update, but each overwrite can
only stop one later cascade at that slot and require resubmission; it cannot
change the tree, although repeated overwrites can repeat the delay.

**Event**

The call returns no event when it only caches or evicts an update. Otherwise it
returns one event for the applied cascade:

```rust
struct BatchAddressAppendEvent {
    merkle_tree_pubkey: [u8; 32],
    zkp_batch_size: u16,
    old_next_index: u64,
    start_sequence_number: u64,
    first_root_index: u32,
    num_update: u32,
    first_zkp_batch_index: u32,
    new_root: [u8; 32], // final root of the cascade
}
```

For applied update offset `n`, where `0 <= n < num_update`:

```text
old_next_index(n)  = old_next_index + n * Z
new_next_index(n)  = old_next_index + (n + 1) * Z
sequence_number(n) = start_sequence_number + n
root_index(n)      = (first_root_index + n) mod RH
```

Intermediate roots are stored in `root_history`; the event reports only the
final `new_root`.

## Close nullifier PDAs

**Description.** Closes any number of closable nullifier PDAs and reimburses
the forester from the tree's fee balance. The instruction is gated to
`protocol_config.forester_authority`, the same signer as the batch update: an
open close would let anyone race the forester's cleanup transaction, collect
the reimbursement, and leave the forester paying the fee of a failed
transaction.

**Input**

The instruction has no data. It receives the signing `authority`, the
`protocol_config`, the writable tree, a writable `reimbursement_recipient`,
and then one writable PDA per nullifier to close. The shielded-pool index
supplies the nullifiers to the forester, which derives the PDA addresses from
them.

**Checks and state changes**

1. Require `authority` to sign and to equal
   `protocol_config.forester_authority`
   (`ShieldedPoolError::UnauthorizedCaller`, 7003).
2. Require the recipient not to be program-owned
   (`ShieldedPoolError::InvalidReimbursementRecipient`, 7055). This rejects
   the tree itself, open nullifier PDAs, and the protocol config as
   recipients.
3. Require at least one PDA account.

For every PDA account:

4. Require program ownership and an exact ten-byte Borsh payload.
5. Require `PDA.tree_id` to equal the tree header's `tree_id`
   (`ShieldedPoolError::NullifierPdaTreeMismatch`, 7053).
6. Require `PDA.queue_index < w`.
7. Transfer every PDA lamport to the tree and close the PDA.

After closing `n` PDAs:

8. Pay `min(fees.close_reimbursement * n, fee_balance)` from the tree to the
   recipient and subtract the paid amount from `fee_balance`. A zero schedule
   or an empty fee balance pays nothing and still closes the PDAs.

The call is atomic. A cleanup call may contain PDAs from different reclaimable
batches of the same tree. The PDA rent always returns to the tree; only the
reimbursement leaves it.

**Property — safe PDA lifetime.** For every queued nullifier `n`:

```text
PDA(n) exists
OR
every accepted nullifier-tree root contains n
```

Fully applying the successor batch writes `RH` newer roots, which establishes
the right-hand condition before advancing `w`; cleanup may therefore remove
the PDA without enabling a stale non-inclusion proof. The transact verifier
accepts only roots for which `accepted_root` holds. Delayed cleanup locks
working capital.

## Cost

Let `A` be the number of append proofs that fit in one transaction, `C` the
number of PDA accounts that fit in one cleanup transaction, and `L` the
number of live PDAs.

For one full queue batch:

```text
K = B / Z
A = min(A_size, A_compute)
append_transactions  = ceil(K / A)
cleanup_transactions = ceil(B / C)
maintenance_transactions = ceil(K / A) + ceil(B / C)

compute_units = K * CU_append + ceil(B / C) * CU_cleanup(C)
network_fee = maintenance_transactions * base_fee
locked_nullifier_pda_rent = L * Rent::minimum_balance(10)
```

With `B = 25_000` and `Z = 250`, a full batch contains 100 append proofs. A
4,096-byte transaction fits approximately 19 append instructions by size;
`A_compute` may be lower and must be benchmarked. Each cleanup entry adds a
32-byte nullifier and one writable PDA. For compressed account references
and a 128-account limit:

```text
PDAs_per_cleanup_transaction ~= 115
cleanup_transactions = ceil(25_000 / 115) = 218

if A = 14: append_transactions = 8, maintenance_transactions = 226
if A = 19: append_transactions = 6, maintenance_transactions = 224
```

`A`, `C`, `CU_append`, and `CU_cleanup(C)` must be measured from the final
instruction and serialized transaction layouts. The counts are for the
successful path: proof replacements, retries, and duplicate cleanup attempts
are additional. At a 5,000-lamport signature fee and one signature per
transaction, 268 to 270 maintenance transactions cost 0.00134 to 0.00135 SOL in
base fees.

At the current default rent rate, one ten-byte PDA requires 960,480
lamports. One full batch locks 28.8144 SOL, all returned to the tree when its
PDAs are closed.

### Working capital

The tree funds every PDA, so at creation it must hold, above its own rent
exemption:

```text
working_capital = 3 * B * Rent::minimum_balance(10)
```

A PDA cannot be closed before its batch is reclaimable, and reclaimability
requires the successor batch's final applied update. Immediate reuse therefore
allows up to three batches of live PDAs at once: the old batch's PDAs,
the successor batch's PDAs, and the PDAs being created in the reused
batch. With prompt cleanup, this is the working capital required for continuous
insertion. Closed PDAs return their rent to the tree; delayed cleanup can
lock capital beyond this amount and eventually stop insertion. With
`B = 25_000` this is 72.036 SOL; with `B = 630_000` it is 1,815.3072 SOL.

### Cost per nullifier

At a 5,000-lamport transaction fee, `C ~= 115`, and `A` between 14 and 19:

```text
fee_per_nullifier = maintenance_transactions * 5_000 / B

if B = 25_000:  44.80 to 45.20 lamports
if B = 120_000: 44.58 to 44.96 lamports
```

Rounding up, successful maintenance costs **46 lamports per nullifier**. At
100 USD/SOL, this is 0.0000046 USD per nullifier. This excludes priority fees,
retries, failed transactions, and the opportunity cost of locked PDA rent.

### Fee schedule

The arithmetic above is the motivating estimate. What actually applies is the
schedule stored in the tree header (see [State](#state)): every insertion
charges `fees.fee_per_nullifier` into `fee_balance`, every applied ZKP batch
pays `fees.append_reimbursement`, and every closed PDA pays
`fees.close_reimbursement`, each payout capped by the fee balance. A schedule
satisfying the solvency inequality

```text
fee_per_nullifier * Z >= append_reimbursement + Z * close_reimbursement
```

collects over the `Z` insertions of one ZKP batch at least what that batch's
append and its `Z` closes pay out, so a tree that starts with `fee_balance =
0` never runs short on its own schedule. The program does not enforce the
inequality; `TreeFeeSchedule::at_cost` derives the smallest fee that satisfies
it. A schedule change applies to insertions and payouts from that point on:
raising the payouts ahead of the collected balance only reduces payouts to
`min(owed, fee_balance)`, it never blocks an append or a close.

The default schedule prices one 5,000-lamport append transaction per ZKP batch
and 170 lamports per PDA close, and sets the insertion fee to exactly cover
them:

```text
append_reimbursement = 5_000
close_reimbursement  = 170
fee_per_nullifier    = ceil((5_000 + Z * 170) / Z)

Z = 250: 190 lamports per nullifier
Z = 10:  670 lamports per nullifier
```

With these values nothing accumulates in the fee balance beyond rounding. The
fee authority retunes the schedule with `set_tree_fees` when Solana's limits or
priority fees move.
