# zolana-batched-merkle-tree

Batched indexed Merkle tree implementation for the trees that the shielded pool
maintains off the hot path: **address trees** (address registration) and
**nullifier trees** (spent-note non-membership). Both are indexed Merkle trees
of height 40 living in a single Solana account with an integrated input queue.
Instead of updating the tree one leaf at a time, insertions are batched into
the queue and applied to the tree with a zero-knowledge proof (ZKP). Trees keep
a cyclic root history for validity proofs. Pending non-inclusion of a queued
nullifier is guaranteed by an exact per-nullifier marker account, not by a
probabilistic filter. [`spec.md`](spec.md) is the normative description of
queue insertion, batch append, and marker cleanup.

| Module | Description |
|--------|-------------|
| `batch` | `Batch` state machine, retirement predicate, hash-chain insertion |
| `merkle_tree` | `BatchedMerkleTreeAccount` and queue/tree operations |
| `queue` | Queue batch insertion helper (batch reuse gated on retirement) |
| `queue_batch_metadata` | Metadata for queue batches |
| `nullifier_marker` | Marker payload, PDA seeds, test-only host emulation of the marker set |
| `initialize_address_tree` | Initialize a batched address or nullifier tree |
| `merkle_tree_metadata` | Tree and queue metadata structs |
| `merkle_tree_update` | Apply queued batches to the tree |
| `verify` | Groth16 verification and verifying keys |
| `errors` | Error types for batch operations |

## Account

There is a single account type, `BatchedMerkleTreeAccount`, a zero-copy view
of `TreeAccountLayout<RH, ZKP>`:

- 8-byte discriminator (`BatchMta`)
- `BatchedMerkleTreeMetadata` (240 bytes): tree type, sequence number, next
  index, height, root-history capacity, capacity, the two queue batches, and
  `close_before_index`
- cyclic root history of `RH` roots
- two bounded hash-chain regions of `ZKP` commitments each
- two cached-tree-update regions of `ZKP` slots each

Address and nullifier trees use the same `AddressV2` layout and differ only in
the sentinel root they are seeded with (`ADDRESS_TREE_INIT_ROOT_40` vs.
`NULLIFIER_TREE_INIT_ROOT_40`).

## Operations

### Queue insertion

`BatchedMerkleTreeAccount::insert_nullifier_into_queue` rejects values that
are not canonical BN254 scalar field elements, requires the queue sequence and
the current batch position to agree (`QueueIndexMismatch`), adds the value to
the current batch's open Poseidon hash chain, and returns the queue index `q`
the value reserved. The program stores `NullifierMarker { queue_index: q, bump }`
(9 Borsh bytes) in the PDA derived from `nullifier_marker_seeds(tree,
nullifier)` = `["nullifier", tree_pubkey, nullifier]`; an existing marker is
what rejects a second insertion of a pending nullifier
(`NonInclusionCheckFailed`).

With the `test-only` feature, `nullifier_marker::host` keeps a global set of
`(tree, nullifier) -> queue_index` reservations so lifecycle tests can mirror
the on-chain close rule. Normal host builds do not carry process-global marker
state.

### Tree update

`update_tree_from_address_queue` verifies one address-append proof, caches the
update, and applies every contiguous cached update whose `old_root` matches the
live root. Each applied update advances `next_index` and `sequence_number`,
appends the new root, and marks the ZKP batch inserted.

### Retirement and `close_before_index`

After each applied update, with `current` the batch that was just updated and
`previous` the other batch: if `current` holds at least `batch_size / 2`
values, `previous` is `Inserted`, and `previous` is not yet retired, then the
root-history slots that could still prove non-inclusion of `previous`'s values
are zeroed and the tree's watermark advances to
`close_before_index = max(close_before_index, first_sequence(previous) +
batch_size)` where `first_sequence(batch) = batch.start_index - 1`.

- `Batch::is_retired(close_before_index)` is
  `close_before_index >= first_sequence + batch_size`.
- Queue insertion reuses an `Inserted` batch only once it is retired; otherwise
  it fails with `BatchNotRetired`.
- A nullifier marker may be closed only once `marker.queue_index <
  close_before_index` (`NullifierMarkerNotClosable` otherwise), which is when
  every accepted root already contains the nullifier.

## Error codes

All errors are defined in `src/errors.rs` and map to u32 error codes:

- `BatchNotReady` (14301) - Batch is not ready to be inserted
- `BatchAlreadyInserted` (14302) - Batch is already inserted
- `TreeIsFull` (14310) - Batched Merkle tree reached capacity
- `NonInclusionCheckFailed` (14311) - Nullifier is already queued
- `BatchNotRetired` (14312) - Batch must be retired before reuse
- `NonCanonicalFieldElement` (14317) - Value is not below the BN254 scalar modulus
- `QueueIndexMismatch` (14318) - Queue index and batch position disagree
- `NullifierMarkerNotClosable` (14319) - Marker queue index is not below `close_before_index`
- `NullifierMarkerMissing` (14320) - No marker exists for the nullifier
- Additional errors from underlying libraries (hasher, zero-copy, verifier, etc.)

## Testing

- `cargo test -p zolana-batched-merkle-tree` runs the marker, canonical-field,
  and layout tests.
- `cargo test -p zolana-batched-merkle-tree --features test-only` adds the
  retirement tests (they drive the cached-update apply pass without a proof)
  and the prover-backed `tests/nullifier_tree.rs`, which needs a running
  prover (`ZOLANA_PROVER_URL`).
- `tests/init_roots.rs` verifies the sentinel roots against
  `zolana-merkle-tree`.
