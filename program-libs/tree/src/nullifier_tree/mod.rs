//! # Nullifier tree
//!
//! Batched indexed Merkle tree of height 40 for spent-UTXO non-membership,
//! with an integrated input queue. Insertions are queued, then applied to the
//! tree one ZKP batch at a time with a Groth16 proof. A per-nullifier PDA
//! rejects a second insertion of a nullifier while it is queued. See
//! `nullifier_tree_spec.md`.
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
//! | [`event`] | [`event::NullifierTreeUpdateEvent`], the emitted batch-update event |
//! | [`error`] | `NullifierTreeError`, the module's single error type |
//!
//! ## Operations
//!
//! ### Initialization
//! [`layout::NullifierTreeLayout::init`] seeds the tree with a single leaf
//! `H(0, p-1)`, where `p-1` is the BN254 sentinel; its root is
//! [`constants::NULLIFIER_TREE_INIT_ROOT_40`].
//!
//! ### Queue insertion
//! [`layout::NullifierTreeLayout::insert_nullifier_into_queue`] rejects
//! non-canonical field elements, adds the value to the current batch's
//! current hash chain, and returns the queue index `q` the value reserved. The program
//! stores `q` and the tree id in the nullifier PDA
//! (`zolana_interface::state::NullifierPda`).
//!
//! ### Tree update
//! A queued ZKP batch is applied with a proof of `old root + queue values ->
//! new root` (see [`merkle_tree_update`]).
//!
//! ## Key concepts
//!
//! **Batching:** The queue has two alternating batches. While one fills, the
//! other is applied to the tree.
//!
//! **ZKP batches:** Each batch is divided into `batch_size / zkp_batch_size`
//! ZKP batches; the tree is updated one ZKP batch at a time.
//!
//! **Hash chains:** Each ZKP batch keeps a Poseidon hash chain over its
//! values. The proof's single public input is the hash of the old root, the
//! new root, this chain, and the leaf index the ZKP batch starts at.
//!
//! **Root history:** A cyclic buffer of `batch_size / zkp_batch_size` roots,
//! exactly one queue batch's worth of ZKP update roots.
//!
//! **Reclaimable batches and `close_before_index`:** Once a batch is fully
//! applied (`Inserted`), its roots have overwritten every older root in the
//! history, and the watermark `w` advances to that batch's `start_index`.
//! An `Inserted` batch is reused immediately; reclaimability gates nullifier
//! PDA cleanup, not batch storage reuse. A nullifier PDA may be closed only
//! once `NullifierPda.queue_index < w`. Queue indices equal the leaf index the
//! value takes and start at 1, so a zero `queue_index` never names a queued
//! nullifier.
//!
//! ## Testing
//!
//! `tests/nullifier_tree/init_roots.rs` derives
//! [`constants::NULLIFIER_TREE_INIT_ROOT_40`] from the `zolana-merkle-tree`
//! reference implementation.

pub mod access;
pub mod batch;
pub mod constants;
pub mod error;
pub mod event;
pub mod init;
pub mod layout;
pub mod merkle_tree_update;
pub mod proof;
pub mod queue_insert;
#[cfg(feature = "verify")]
pub mod verify;
