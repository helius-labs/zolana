//! End-to-end BDD tests for the merge proof at shape (8,1). Each scenario
//! consolidates 1..8 P256-owned inputs (rest dummy) into one output, proves it on
//! the prover server, and verifies against the committed merge verifying key.
//!
//! Requires a reachable prover server (started via `spawn_prover`) with the
//! `merge_8_1.key` proving key available.
//!
//! Run with: `cargo test -p zolana-client --test merge_proving`

mod steps;
mod world;

// Shared with the transfer runner; included by path since it lives at tests/.
#[path = "../test_indexer.rs"]
mod test_indexer;

use cucumber::World as _;

fn main() {
    futures::executor::block_on(
        world::MergeWorld::cucumber()
            .fail_on_skipped()
            .run_and_exit("tests/merge/features"),
    );
}
