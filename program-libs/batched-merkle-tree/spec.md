# Batched Merkle Tree

This crate maintains a height-40 indexed Merkle tree and a two-batch input
queue. This document specifies nullifier queue insertion, batch append, and
nullifier-marker cleanup. Initialization is out of scope.

## State

Let:

| Symbol | Meaning |
| --- | --- |
| `B` | values per queue batch (`batch_size`) |
| `Z` | values per ZKP batch (`zkp_batch_size`) |
| `K` | ZKP batches per queue batch: `B / Z` |
| `c` | batch currently receiving values |
| `p` | batch currently being appended to the tree |
| `RH` | root-history capacity |
| `q` | next zero-based input-queue sequence number |
| `w` | exclusive queue-sequence marker-close watermark (`close_before_index`) |

The tree is a program-derived account. It holds the queue, root history, and
lamports used as working capital for nullifier markers.

The queue has exactly two batches. Each batch stores `K` hash-chain
commitments, `K` cached tree updates, and:

```rust
struct Batch {
    state: Fill | Full | Inserted,
    start_index: u64,
    num_inserted: u64,              // queued values in the open ZKP batch
    num_full_zkp_batches: u64,      // finalized hash chains
    num_inserted_zkp_batches: u64,  // finalized ZKP batches applied to the tree
    sequence_number: u64,           // final append sequence + RH
    root_index: u32,                // final root's history slot
}
```

```text
0 <= num_inserted_zkp_batches <= num_full_zkp_batches <= K

RH >= K

unapplied_values =
    (num_full_zkp_batches - num_inserted_zkp_batches) * Z
    + num_inserted

inserted_elements = num_full_zkp_batches * Z + num_inserted

first_sequence(batch) = batch.start_index - 1

retired(batch) = w >= first_sequence(batch) + B

batches[p].state != Inserted =>
    tree.next_index =
        batches[p].start_index + batches[p].num_inserted_zkp_batches * Z

next_queued_leaf_index = q + 1

tree.next_index <= next_queued_leaf_index <= tree.capacity

accepted_root(i) = i < RH and root_history[i] != 0
```

Leaf zero is initialized, so initialization establishes `q = 0`,
`tree.next_index = 1`, and
`batches[i].start_index = 1 + i * B` for `i` in `{0, 1}`. Queue sequence `x`
reserves leaf `x + 1`. Leaves in `[tree.next_index, q + 1)` are queued but not
yet appended to the tree.

`RH >= K` ensures all roots produced by a maximum `K`-update cascade occupy
distinct history slots when the call returns. This is a root-availability
constraint, not a marker-cleanup safety requirement.

`Fill --B queue insertions--> Full --final ZKP append--> Inserted --retire--> reusable --reuse--> Fill`.
A finalized ZKP batch may be appended while its queue batch is still `Fill`.
Retirement keeps the state `Inserted` and does not wait for marker cleanup.

Each queued nullifier has an exact marker account:

```text
marker = canonical_pda(
    program_id,
    ["nullifier", tree_pubkey, nullifier],
)
```

```rust
// Borsh-serialized length: 9 bytes.
struct NullifierMarker {
    queue_index: u64,
    bump: u8,
}
```

The queued nullifier and the PDA seed use the same canonical 32-byte field
encoding. Values outside the field are rejected, not reduced modulo the field.

## Insert into queue

**Description.** Creates an exact nullifier marker and adds the nullifier to the
current batch's open hash chain. The marker prevents the same pending nullifier
from being queued twice; the hash chain commits queue order for the later batch
proof.

**Input**

```rust
nullifier: [u8; 32]
```

The instruction also receives the writable marker PDA.

**Checks and state changes**

1. Require the nullifier-tree type and canonical nullifier encoding.
2. Require `batches[c].state == Fill`. If it is `Inserted`, reuse it first;
   reuse requires the batch to have been retired (batch append, step 9), resets
   its counters, `sequence_number`, and `root_index`, and advances `start_index`
   by `2 * B`. `Full` is not reusable.
3. Require
   `q + 1 = batches[c].start_index + batches[c].inserted_elements` and
   `q + 1 < tree.capacity`.
4. Derive the canonical marker PDA and bump. Require the supplied address to
   match. An initialized marker returns `NonInclusionCheckFailed`.
5. Accept an unused marker that is System-owned, empty, and optionally
   prefunded. Transfer only its missing rent-exempt balance from the tree, then
   allocate nine bytes, assign it to the program, and store `{ q, bump }`.
6. Let `j = batches[c].num_full_zkp_batches`. Update the open commitment:

   ```text
   hash_chains[c][j] = nullifier                              if num_inserted == 0
   hash_chains[c][j] = Poseidon(hash_chains[c][j], nullifier) otherwise
   ```

7. Increment `num_inserted`. When `num_inserted == Z`, finalize the commitment,
   increment
   `num_full_zkp_batches`, and reset `num_inserted` to zero. When
   `num_full_zkp_batches == K`, set the batch to `Full` and advance `c` modulo
   two.
8. Increment `q` once.

Marker creation and queue mutation are atomic. Failure changes neither.

**Property — pending non-inclusion.** A successful insertion makes every later
queue insertion of the same nullifier fail while its marker exists. The check
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
8. When all `K` ZKP batches are applied, set the queue batch to `Inserted`, set
   its `sequence_number = tree.sequence_number + RH`, record the final root's
   history slot in `root_index`, and advance `p` modulo two.
9. After each applied update, let `current_index` be the `p` used for that
   update, before any advancement in step 8, and let:

   ```text
   current  = batches[current_index]
   previous = batches[(current_index + 1) mod 2]
   ```

   If `current.inserted_elements >= B / 2`, `previous.state == Inserted`, and
   `previous` is not retired, retire `previous`. If
   `previous.sequence_number > tree.sequence_number`, let:

   ```text
   final_sequence = previous.sequence_number - RH
   keep = tree.sequence_number - final_sequence + 1
   ```

   Preserve `keep` cyclic slots starting at `previous.root_index` and zero the
   other `RH - keep` slots. If
   `previous.sequence_number <= tree.sequence_number`, at least `RH` newer
   roots have already overwritten its final root and every older root, so zero
   nothing. Set
   `w = max(w, first_sequence(previous) + B)` and make `previous` reusable.
   These changes are atomic. Half full measures queued values, not applied ZKP
   batches.

**Property — queue draining.** One applied update reduces
`unapplied_values` by exactly `Z`. After all `K` updates, the batch has
`unapplied_values == 0`, is `Inserted`, and is no longer pending. Its
hash-chain bytes remain until overwritten on reuse. Its markers remain until
separate cleanup transactions close them.

**Property — retirement liveness.** Crossing `B / 2` queued values does not
itself retire the previous batch. The next successful append of that batch
does. Without that append, the previous batch cannot be reused when queue
insertion cycles back to it.

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

## Close nullifier markers

**Description.** Permissionlessly closes any number of retired nullifier
markers.

**Input**

```rust
nullifiers: Vec<[u8; 32]>
```

The instruction also receives the writable tree and one writable marker per
nullifier. The shielded-pool index supplies the nullifiers to the cleaner.

**Checks and state changes**

For every `(nullifier, marker)` pair:

1. Require program ownership and an exact nine-byte Borsh payload.
2. Recreate `PDA(["nullifier", tree_pubkey, nullifier, marker.bump])` and
   require it to equal the marker address.
3. Require `marker.queue_index < w`.
4. Transfer every marker lamport to the tree and close the marker.

The call is atomic. A cleanup call may contain markers from different retired
batches of the same tree.

**Property — safe marker lifetime.** For every queued nullifier `n`:

```text
marker(n) exists
OR
every accepted nullifier-tree root contains n
```

Retirement establishes the right-hand condition before advancing `w`; cleanup
may therefore remove the marker without enabling a stale non-inclusion proof.
The transact verifier accepts only in-bounds, nonzero root-history entries.
Delayed cleanup locks working capital.

## Cost

Let `A` be the number of append proofs that fit in one transaction, `C` the
number of marker accounts that fit in one cleanup transaction, and `L` the
number of live markers.

For one full queue batch:

```text
K = B / Z
A = min(A_size, A_compute)
append_transactions  = ceil(K / A)
cleanup_transactions = ceil(B / C)
maintenance_transactions = ceil(K / A) + ceil(B / C)

compute_units = K * CU_append + ceil(B / C) * CU_cleanup(C)
network_fee = maintenance_transactions * base_fee
locked_marker_rent = L * Rent::minimum_balance(9)
```

With `B = 30_000` and `Z = 250`, a full batch contains 120 append proofs. A
4,096-byte transaction fits approximately 19 append instructions by size;
`A_compute` may be lower and must be benchmarked. Each cleanup entry adds a
32-byte nullifier and one writable marker. For compressed account references
and a 128-account limit:

```text
markers_per_cleanup_transaction ~= 115
cleanup_transactions = ceil(30_000 / 115) = 261

if A = 14: append_transactions = 9, maintenance_transactions = 270
if A = 19: append_transactions = 7, maintenance_transactions = 268
```

`A`, `C`, `CU_append`, and `CU_cleanup(C)` must be measured from the final
instruction and serialized transaction layouts. The counts are for the
successful path: proof replacements, retries, and duplicate cleanup attempts
are additional. At a 5,000-lamport signature fee and one signature per
transaction, 268 to 270 maintenance transactions cost 0.00134 to 0.00135 SOL in
base fees.

At the current default rent rate, one nine-byte marker requires 953,520
lamports. One full batch locks 28.6056 SOL, all returned to the tree when its
markers are closed.
