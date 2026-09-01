//! # Nullifier tree
//!
//! Batched indexed Merkle tree implementation for the trees that the shielded
//! pool maintains off the hot path: **address trees** (address registration)
//! and **nullifier trees** (spent-note non-membership). Both are indexed Merkle
//! trees of height 40 living in a single Solana account with an integrated input
//! queue. Instead of updating the tree one leaf at a time, insertions are
//! batched into the queue and applied to the tree with a zero-knowledge proof
//! (ZKP), enabling efficient on-chain verification. Trees keep a cyclic root
//! history for validity proofs; pending non-inclusion of a queued nullifier is
//! guaranteed by a per-nullifier PDA account. See `nullifier_tree_spec.md`.
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`layout`] | Account layout: tree metadata, queue metadata, root history, batches |
//! | [`init`] | Configure and initialize a batched nullifier tree |
//! | [`queue_insert`] | Insert a nullifier into the input queue |
//! | [`merkle_tree_update`] | Apply queued batches to the tree |
//! | [`access`] | Read accessors, layout validation, and account size |
//! | [`batch`] | `Batch` state machine, hash chains, and cached tree updates |
//! | [`proof`] | `CompressedProof`, the batch-update proof encoding |
//! | `verify` | Groth16 verification and verifying keys (feature `verify`) |
//! | [`error`] | `NullifierTreeError`, the module's single error type |
//!
//! ## Account
//!
//! There is a single state type, [`layout::NullifierTreeLayout`], cast in
//! place from the account bytes: it stores the tree metadata, the cyclic root
//! history, and the input queue's two batches, each carrying its own hash
//! chains and cached tree updates.
//! Address and nullifier trees use the same `AddressV2` layout and differ only
//! in the sentinel root they are seeded with.
//!
//! ## Operations
//!
//! ### Initialization
//! The shielded pool initializes its nullifier tree with
//! [`layout::NullifierTreeLayout::init`], seeding it with the BN254 `p-1`
//! sentinel root ([`constants::NULLIFIER_TREE_INIT_ROOT_40`]) and the
//! configuration in [`init`].
//!
//! ### Queue insertion
//! - [`layout::NullifierTreeLayout::insert_nullifier_into_queue`]
//!   rejects non-canonical field elements, adds the value to the current
//!   input-queue batch's open hash chain via the [`queue_insert`] module, and returns
//!   the queue index `q` the value reserved. The program stores `{ q, bump }` in
//!   the nullifier PDA (`zolana_interface::state::NullifierPda`); the
//!   nullifier PDA is what rejects a second insertion of a pending nullifier.
//!
//! ### Tree update
//! - The queued batch is applied to the tree with a ZKP that proves
//!   `old root + queue values -> new root` (see [`merkle_tree_update`]).
//!
//! ## Key concepts
//!
//! **Batching system:** Each tree uses 2 alternating batches. While one batch is
//! being filled, the previous batch can be applied to the tree with a ZKP.
//!
//! **ZKP batches:** Each batch is divided into smaller ZKP batches
//! (`batch_size / zkp_batch_size`); the tree is updated incrementally one ZKP
//! batch at a time.
//!
//! **Reclaimable batches and `close_before_index`:** Root history contains exactly
//! one queue batch's worth of ZKP update roots. Once the successor batch is fully
//! applied (`Inserted`), those updates have naturally overwritten every older
//! root and the tree's `close_before_index` watermark `w` advances to
//! `current.start_index - 1`. An `Inserted` batch can be reused immediately;
//! reclaimability gates nullifier PDA cleanup rather than batch storage reuse. A
//! nullifier PDA may be closed only once `nullifier PDA.queue_index < w`.
//!
//! **Hash chains:** Each ZKP batch keeps a hash chain storing the Poseidon hash
//! of all values in that ZKP batch, used as a public input to the ZKP.
//!
//! **ZKP verification:** Public inputs are the old root, new root, the hash
//! chain committing to the queue elements, and `next_index` for the append.
//!
//! **Root history:** A cyclic buffer with
//! `batch_size / zkp_batch_size` entries keeps exactly one queue batch's worth
//! of update roots. Its capacity is the region length, so the only word the
//! account stores for it is the write cursor.
//!
//! ## Dependencies
//!
//! - **`zolana-hasher`** - Poseidon hash for hash chains and tree operations
//! - **`groth16-solana`** - Groth16 proof verification for batch updates (see the `verify` module)
//! - **`zolana-account-checks`** - `AccountError` variants reused by [`error`]
//!
//! ## Testing and reference implementations
//!
//! - **`zolana-merkle-tree`** - Reference indexed Merkle tree implementation
//!   (dev dependency), used to generate the constants
//!   [`constants::ADDRESS_TREE_INIT_ROOT_40`] and
//!   [`constants::NULLIFIER_TREE_INIT_ROOT_40`] (see `tests/init_roots.rs`).
//!   Address trees are seeded as `H(0, HIGHEST_ADDRESS_PLUS_ONE)` and nullifier
//!   trees as `H(0, BN254 p-1)`.
//!
//! ## Error codes
//!
//! Every failure is a variant of the single [`error::NullifierTreeError`],
//! which maps to a u32 error code in the 14000 space:
//! - `BatchNotReady` (14001) - Batch is not ready to be inserted
//! - `BatchAlreadyInserted` (14002) - Batch is already inserted
//! - `TreeIsFull` (14008) - Batched Merkle tree reached capacity
//! - `NonCanonicalFieldElement` (14010) - Value is not below the BN254 scalar modulus
//! - `InvalidRootHistoryCapacity` (14017) - Root history must contain exactly one
//!   queue batch of ZKP update roots
//! - `ProofVerificationFailed` (14024) - Groth16 verification rejected the proof
//! - Errors from underlying libraries (hasher, account checks) keep their own codes

pub mod access;
pub mod batch;
pub mod constants;
pub mod error;
pub mod init;
pub mod layout;
pub mod merkle_tree_update;
pub mod proof;
pub mod queue_insert;
#[cfg(feature = "verify")]
pub mod verify;
