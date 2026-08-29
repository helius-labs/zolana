//! # zolana-batched-merkle-tree
//!
//! Batched indexed Merkle tree implementation for the trees that the shielded
//! pool maintains off the hot path: **address trees** (address registration)
//! and **nullifier trees** (spent-note non-membership). Both are indexed Merkle
//! trees of height 40 living in a single Solana account with an integrated input
//! queue. Instead of updating the tree one leaf at a time, insertions are
//! batched into the queue and applied to the tree with a zero-knowledge proof
//! (ZKP), enabling efficient on-chain verification. Trees keep a cyclic root
//! history for validity proofs; pending non-inclusion of a queued nullifier is
//! guaranteed by a per-nullifier PDA account. See `spec.md`.
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`batch`] | `Batch` state machine and per-batch insertion |
//! | [`merkle_tree`] | `BatchedMerkleTreeAccount` and queue/tree operations |
//! | [`queue`] | Queue batch insertion helper |
//! | [`queue_batch_metadata`] | Metadata for queue batches |
//! | [`initialize_address_tree`] | Configure and initialize a batched nullifier tree |
//! | [`merkle_tree_metadata`] | Tree and queue metadata structs |
//! | [`merkle_tree_update`] | Apply queued batches to the tree |
//! | [`verify`] | Groth16 verification and verifying keys |
//! | [`errors`] | Error types for batch operations |
//!
//! ## Account
//!
//! There is a single account type, [`merkle_tree::BatchedMerkleTreeAccount`]: it
//! stores the tree roots, the cyclic root history, and an integrated input queue
//! (hash chains + cached tree updates). Address and nullifier trees use the same
//! `AddressV2` layout and differ only in the sentinel root they are seeded with.
//!
//! ## Operations
//!
//! ### Initialization
//! The shielded pool initializes its nullifier tree through
//! [`initialize_address_tree`], seeding it with the BN254 `p-1` sentinel root
//! ([`constants::NULLIFIER_TREE_INIT_ROOT_40`]).
//!
//! ### Queue insertion
//! - [`merkle_tree::BatchedMerkleTreeAccount::insert_nullifier_into_queue`]
//!   rejects non-canonical field elements, adds the value to the current
//!   input-queue batch's open hash chain via the [`queue`] module, and returns
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
//! - **`groth16-solana`** - Groth16 proof verification for batch updates (see [`verify`])
//! - **`zolana-account-checks`** - Account validation and discriminator checks
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
//! All errors are defined in [`errors`] and map to u32 error codes:
//! - `BatchNotReady` (14301) - Batch is not ready to be inserted
//! - `BatchAlreadyInserted` (14302) - Batch is already inserted
//! - `TreeIsFull` (14310) - Batched Merkle tree reached capacity
//! - `NonCanonicalFieldElement` (14317) - Value is not below the BN254 scalar modulus
//! - `QueueIndexMismatch` (14318) - Queue index and batch position disagree
//! - `InvalidBatchConfiguration` (14319) - Queue-level and per-batch metadata disagree
//! - `InvalidRootHistoryCapacity` (14010) - Root history must contain exactly one
//!   queue batch of ZKP update roots
//! - Additional errors from underlying libraries (hasher, zero-copy, verifier, etc.)

#![allow(unexpected_cfgs)]
pub mod batch;
pub mod constants;
pub mod errors;
pub mod initialize_address_tree;
pub mod merkle_tree;
pub mod merkle_tree_metadata;
pub mod merkle_tree_update;
pub mod queue;
pub mod queue_batch_metadata;
pub mod verify;
pub mod zero_copy;

use borsh::{BorshDeserialize, BorshSerialize};
