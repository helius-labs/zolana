//! End-to-end BDD tests for the `Transaction` builder at shape (2,3), one feature
//! file per ownership rail (`eddsa_transaction`, `p256_transaction`,
//! `eddsa_p256_transaction`). Each scenario declares inputs / sends / withdrawals,
//! then the `the proof verifies` step builds the transfer, proves it on the prover
//! server, and verifies against the committed vk for the selected rail.
//!
//! Requires a reachable prover server (started via `spawn_prover`) with the
//! `transfer_2_3.key` and `transfer_p256_2_3.key` proving keys available.
//!
//! Run with: `cargo test -p zolana-client --test transaction_proving`

mod prover;
mod steps;
mod test_indexer;
mod world;

use cucumber::World as _;

fn main() {
    futures::executor::block_on(
        world::TransferWorld::cucumber()
            .fail_on_skipped()
            .run_and_exit("tests/features"),
    );
}
