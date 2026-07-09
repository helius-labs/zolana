//! End-to-end BDD tests for the policy-zone merge proof at shape (8,1). Each
//! scenario consolidates 1..8 zone-owned inputs (rest dummy) sharing one owner into
//! one zone-owned output, proves it on the prover server, and verifies against the
//! committed merge-zone verifying key.
//!
//! Requires a reachable prover server (started via `spawn_prover`) with the
//! `merge_zone_8_1.key` proving key available.
//!
//! Run with: `cargo test -p rings-client --test merge_zone_proving`

mod steps;
mod world;

// Shared with the transfer/merge runners; included by path since it lives at tests/.
#[path = "../test_indexer.rs"]
mod test_indexer;

use cucumber::World as _;

fn main() {
    futures::executor::block_on(
        world::MergeZoneWorld::cucumber()
            .fail_on_skipped()
            .run_and_exit("tests/merge_zone/features"),
    );
}
