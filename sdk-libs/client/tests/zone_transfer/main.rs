//! End-to-end BDD tests for the zone-transfer circuit (`zone_transact`). Each
//! scenario builds a zone-owned state transition over a chosen shape, proves it on
//! the prover server, and verifies against the committed `transfer_zone_<shape>`
//! verifying key (ed25519 rail, vanilla Groth16; the P256 rail is removed).
//!
//! Requires a reachable prover server (started via `spawn_prover`) with the
//! `transfer_zone_<shape>.key` proving keys available.
//!
//! Run with: `cargo test -p zolana-client --test zone_transfer_proving`

mod steps;
mod world;

// Shared with the transfer/merge/zone-authority runners; included by path since it
// lives at tests/.
#[path = "../test_indexer.rs"]
mod test_indexer;

use cucumber::World as _;

fn main() {
    futures::executor::block_on(
        world::ZoneTransferWorld::cucumber()
            .fail_on_skipped()
            .run_and_exit("tests/zone_transfer/features"),
    );
}
