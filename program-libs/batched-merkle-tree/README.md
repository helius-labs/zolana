# zolana-batched-merkle-tree

Batched indexed Merkle tree implementation for the trees that the shielded pool
maintains off the hot path: **address trees** (address registration) and
**nullifier trees** (spent-note non-membership). Both are indexed Merkle trees
of height 40 living in a single Solana account with an integrated input queue.
Instead of updating the tree one leaf at a time, insertions are batched into
the queue and applied to the tree with a zero-knowledge proof (ZKP). Trees keep
a cyclic root history for validity proofs. Pending non-inclusion of a queued
nullifier is guaranteed by an exact per-nullifier PDA account, not by a
probabilistic filter. [`spec.md`](spec.md) is the normative description of
queue insertion, batch append, and PDA cleanup.

| Module | Description |
|--------|-------------|
| `layout` | Account layout: tree, root history, queue batches, metadata |
| `init` | Configure and initialize a batched nullifier tree |
| `queue_insert` | Insert a nullifier into the input queue |
| `merkle_tree_update` | Apply queued batches to the tree |
| `access` | Read accessors, layout validation, and account size |
| `batch` | `Batch` state machine, reclaimability predicate, hash-chain insertion |
| `verify` | Groth16 verification and verifying keys |
| `errors` | `NullifierTreeError`, the crate's single error type |

## Account

There is a single state type, `NullifierTreeLayout<ZKP>`, cast in place from
the account bytes, where `ZKP = batch_size / zkp_batch_size`:

- `BatchedMerkleTreeMetadata` (240 bytes): tree type, sequence number, next
  index, height, root-history capacity, capacity, the two queue batches, and
  `close_before_index`
- cyclic root history of `ZKP` roots
- two bounded hash-chain regions of `ZKP` commitments each
- two cached-tree-update regions of `ZKP` slots each

Address and nullifier trees use the same `AddressV2` layout and differ only in
the sentinel root they are seeded with (`ADDRESS_TREE_INIT_ROOT_40` vs.
`NULLIFIER_TREE_INIT_ROOT_40`).

## Operations

### Queue insertion

`NullifierTreeLayout::insert_nullifier_into_queue` rejects values that
are not canonical BN254 scalar field elements, requires the queue sequence and
the current batch position to agree (`QueueIndexMismatch`), adds the value to
the current batch's open Poseidon hash chain, and returns the queue index `q`
the value reserved. The program stores `NullifierPda { queue_index: q, bump }`
(9 Borsh bytes, defined in `zolana_interface::state`) in the PDA derived from
`["nullifier", tree_pubkey, nullifier]`; an existing PDA is
what rejects a second insertion of a pending nullifier
(`ShieldedPoolError::NullifierAlreadyQueued`).

### Tree update

`update_tree_from_address_queue` verifies one address-append proof, caches the
update, and applies every contiguous cached update whose `old_root` matches the
live root. Each applied update advances `next_index` and `sequence_number`,
appends the new root, and marks the ZKP batch inserted.

### Reclaimable batches and `close_before_index`

Root history contains exactly one queue batch's worth of ZKP update roots:
its capacity is derived as `batch_size / zkp_batch_size`. When `current`, the
batch just updated, becomes fully applied (`Inserted`), it has naturally
overwritten every root that predates it. The tree's watermark therefore
advances to
`close_before_index = max(close_before_index, current.start_index - 1)`.
This makes the preceding batch reclaimable even if its storage has already
been reused and returned to `Fill`.

- `Batch::is_reclaimable(close_before_index)` is
  `close_before_index >= reclaimable_sequence()`.
- Queue insertion reuses an `Inserted` batch immediately; reclaimability gates
  PDA cleanup, not storage reuse.
- A nullifier PDA may be closed only once `PDA.queue_index <
  close_before_index` (`ShieldedPoolError::NullifierPdaNotClosable`
  otherwise), which is when every accepted root already contains the nullifier.

## Error codes

Every failure is a variant of the single `NullifierTreeError` in
`src/errors.rs`, which maps to a u32 error code in the 14000 space:

- `BatchNotReady` (14001) - Batch is not ready to be inserted
- `BatchAlreadyInserted` (14002) - Batch is already inserted
- `InvalidBatchConfiguration` (14007) - Queue-level and per-batch metadata disagree
- `TreeIsFull` (14008) - Batched Merkle tree reached capacity
- `QueueIndexMismatch` (14009) - Queue index and batch position disagree
- `NonCanonicalFieldElement` (14010) - Value is not below the BN254 scalar modulus
- `InvalidRootHistoryCapacity` (14017) - Root history must contain exactly one
  queue batch of ZKP update roots
- `ProofVerificationFailed` (14024) - Groth16 verification rejected the proof
- Errors from underlying libraries (hasher, account checks) are wrapped and keep
  their own codes

## Testing

- `cargo test -p zolana-batched-merkle-tree` runs the queue-insertion, layout,
  and reclaimable-batch tests (the latter drive the cached-update apply pass
  without a proof).
- `cargo test -p zolana-batched-merkle-tree --features test-only` adds the
  in-crate unit tests and the prover-backed `tests/nullifier_tree.rs`, which
  needs a running prover (`ZOLANA_PROVER_URL`).
- `tests/init_roots.rs` verifies the sentinel roots against
  `zolana-merkle-tree`.
