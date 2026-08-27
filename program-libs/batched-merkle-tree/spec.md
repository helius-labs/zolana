# Batched Merkle Tree

This crate maintains a height-40 indexed Merkle tree and a two-batch input
queue. Address and nullifier trees use the same flows; they differ only in the
sentinel root selected at initialization.

This document specifies the two write flows: insert a value into the queue, and
append queued values to the tree with a batch proof.

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

The queue has exactly two batches. Each batch stores one bloom filter, `K`
hash-chain commitments, `K` cached tree updates, and:

```rust
struct Batch {
    state: Fill | Full | Inserted,
    start_index: u64,
    num_inserted: u64,              // values in the open ZKP batch
    num_full_zkp_batches: u64,      // finalized hash chains
    num_inserted_zkp_batches: u64,  // hash chains appended to the tree
}
```

```text
0 <= num_inserted_zkp_batches <= num_full_zkp_batches <= K

unapplied_values =
    (num_full_zkp_batches - num_inserted_zkp_batches) * Z
    + num_inserted

inserted_elements = num_full_zkp_batches * Z + num_inserted
```

`Fill --B queue insertions--> Full --final ZKP append--> Inserted --reuse--> Fill`.
A finalized ZKP batch may be appended while its queue batch is still `Fill`.

## Insert into queue

**Description.** Adds one value to the current batch's bloom filter and open
hash chain. The bloom filters prevent the same pending value from being queued
twice; the hash chain commits the value order for the later batch proof.

**Input**

```rust
value: [u8; 32]
```

The value is used unchanged as both the bloom-filter key and hash-chain value.

**Checks and state changes**

1. Require the indexed-tree type and a free leaf at
   `batches[c].start_index + batches[c].inserted_elements`.
2. Require `batches[c].state == Fill`. If it is `Inserted`, reuse it first;
   reuse requires its bloom filter to have been zeroed (batch append, step 9),
   resets its counters, and advances `start_index` by `2 * B`. `Full` is not
   reusable.
3. Require `value` to be absent from both bloom filters. A bloom-filter hit,
   including a false positive, returns `NonInclusionCheckFailed`.
4. Let `j = batches[c].num_full_zkp_batches`. Update the open commitment:

   ```text
   hash_chains[c][j] = value                              if num_inserted == 0
   hash_chains[c][j] = Poseidon(hash_chains[c][j], value) otherwise
   ```

5. Insert `value` into bloom filter `c` and increment `num_inserted`.
6. When `num_inserted == Z`, finalize the commitment, increment
   `num_full_zkp_batches`, and reset `num_inserted` to zero. When
   `num_full_zkp_batches == K`, set the batch to `Full` and advance `c` modulo
   two.
7. Increment `queue.next_index` once.

**Property — pending non-inclusion.** A successful insertion makes every later
queue insertion of the same value fail while either bloom filter retains it.
Bloom filters admit false positives but not false negatives. Non-inclusion
against values already in the Merkle tree is proved by the transaction/batch
proofs, not by this queue check.

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
    old_root: [u8; 32],
    new_root: [u8; 32],
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
2. If `i < a`, the update is already applied and the call is a no-op. If cache
   slot `[p][i]` is occupied, the update is already submitted and the call is a
   no-op.
3. Derive `start_index` and `public_input`, verify the proof, then cache
   `{ old_root, new_root }` at `[p][i]`.
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
8. When all `K` ZKP batches are applied, set the queue batch to `Inserted`,
   record its final root, and advance `p` modulo two.
9. During an append, if the next pending batch is at least half full, zero the
   previous inserted batch's bloom filter. Root-history entries older than that
   batch's recorded final root are zeroed at the same time. The retired batch
   may then be reused.

**Property — queue draining.** One applied update reduces
`unapplied_values` by exactly `Z`. After all `K` updates, the batch has
`unapplied_values == 0`, is `Inserted`, and is no longer pending. Its
bloom-filter bytes remain until step 9 zeroes them, and its hash-chain bytes
remain until overwritten on reuse.

**Property — ordered application.** Proofs may arrive in any order, but roots
are applied only in increasing ZKP-batch order and only when each `old_root`
equals the live root.

**Property — public input.** The single Groth16 public input is the hash of
`old_root`, `new_root`, `leaves_hash`, and `start_index`; changing any of them
changes the public input.

**Property — idempotence.** Replaying an already applied or already cached
update changes neither the tree nor the queue.

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
