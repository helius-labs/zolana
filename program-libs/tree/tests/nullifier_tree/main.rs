mod init_roots;

// The rest of the suite builds small trees and uses the `test-only` accessors
// on `Batch`, so it does not exist without the feature.
#[cfg(feature = "test-only")]
mod access;
#[cfg(feature = "test-only")]
mod batch;
#[cfg(feature = "test-only")]
mod batch_reclaimable;
#[cfg(feature = "test-only")]
mod common;
#[cfg(feature = "test-only")]
mod layout;
#[cfg(feature = "test-only")]
mod merkle_tree_update;
#[cfg(feature = "test-only")]
mod nullifier_pda;
#[cfg(feature = "test-only")]
mod prover_e2e;
#[cfg(feature = "test-only")]
mod queue_insert;
