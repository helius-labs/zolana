//! # zolana-batched-merkle-tree
//!
//! Batched indexed Merkle tree implementation for the trees that the shielded
//! pool maintains off the hot path: **address trees** (address registration)
//! and **nullifier trees** (spent-note non-membership). Both are indexed Merkle
//! trees of height 40 living in a single Solana account with an integrated input
//! queue. Instead of updating the tree one leaf at a time, insertions are
//! batched into the queue and applied to the tree with a zero-knowledge proof
//! (ZKP), enabling efficient on-chain verification. Trees keep a cyclic root
//! history for validity proofs and use bloom filters for non-inclusion proofs
//! while a batch is being filled.
//!
//! | Module | Description |
//! |--------|-------------|
//! | [`batch`] | `Batch` state machine and per-batch insertion |
//! | [`merkle_tree`] | `BatchedMerkleTreeAccount` and queue/tree operations |
//! | [`queue`] | Queue batch insertion helper |
//! | [`queue_batch_metadata`] | Metadata for queue batches |
//! | [`initialize_address_tree`] | Initialize a batched address or nullifier tree |
//! | [`merkle_tree_metadata`] | Tree and queue metadata structs |
//! | [`merkle_tree_update`] | Apply queued batches to the tree |
//! | [`events`] | Batch update events |
//! | [`verify`] | Groth16 verification and verifying keys |
//! | [`errors`] | Error types for batch operations |
//!
//! ## Account
//!
//! There is a single account type, [`merkle_tree::BatchedMerkleTreeAccount`]: it
//! stores the tree roots, the cyclic root history, and an integrated input queue
//! (bloom filters + hash chains). Address and nullifier trees use the same
//! `AddressV2` layout and differ only in the sentinel root they are seeded with.
//!
//! ## Operations
//!
//! ### Initialization
//! Address and nullifier trees are created with a single Solana account. See
//! [`initialize_address_tree`]:
//! - `init_batched_address_merkle_tree_account` seeds the address sentinel root
//!   ([`constants::ADDRESS_TREE_INIT_ROOT_40`]).
//! - `init_batched_nullifier_merkle_tree_from_account_info` seeds the BN254
//!   `p-1` sentinel root ([`constants::NULLIFIER_TREE_INIT_ROOT_40`]).
//!
//! ### Queue insertion
//! - [`merkle_tree::BatchedMerkleTreeAccount::insert_address_into_queue`] inserts
//!   a value into the current input-queue batch (bloom filter + hash chain) via
//!   the [`queue`] module's insertion helper.
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
//! **Bloom filters:** The input queue uses a bloom filter for non-inclusion
//! proofs. While a batch is filling, values are inserted into the bloom filter.
//! After the batch is fully inserted into the tree and the next batch is 50%
//! full, the bloom filter is zeroed by a forester to prevent false positives; a
//! batch whose bloom filter is not yet zeroed cannot be reused.
//!
//! **Hash chains:** Each ZKP batch keeps a hash chain storing the Poseidon hash
//! of all values in that ZKP batch, used as a public input to the ZKP.
//!
//! **ZKP verification:** Public inputs are the old root, new root, the hash
//! chain committing to the queue elements, and `next_index` for the append.
//!
//! **Root history:** A cyclic buffer of recent roots (default: 200) keeps
//! validity proofs valid as the tree continues to update.
//!
//! ## Dependencies
//!
//! - **`zolana-bloom-filter`** - Bloom filter for non-inclusion proofs
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
//! - `NonInclusionCheckFailed` (14311) - Value exists in bloom filter
//! - `BloomFilterNotZeroed` (14312) - Bloom filter must be zeroed before reuse
//! - Additional errors from underlying libraries (hasher, zero-copy, verifier, etc.)

#![allow(unexpected_cfgs)]
pub mod batch;
pub mod constants;
pub mod errors;
pub mod events;
pub mod initialize_address_tree;
pub mod merkle_tree;
pub mod merkle_tree_metadata;
pub mod merkle_tree_update;
pub mod queue;
pub mod queue_batch_metadata;
pub(crate) mod rent;
pub mod verify;
pub mod zero_copy;

// Use the appropriate BorshDeserialize and BorshSerialize based on feature
use borsh::{BorshDeserialize, BorshSerialize};
