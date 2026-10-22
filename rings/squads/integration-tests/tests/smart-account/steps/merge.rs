//! Crank consolidation: the backend crank merges an account's fragmented UTXOs
//! of one asset into a single output.

use cucumber::then;
use squads_ring_tests::localnet::SOL_ASSET_ID;

use crate::{fixture::viewing_key_account_address, world::SquadsLifecycleWorld};

#[then(expr = "{word} consolidates into a {int} lamport SOL UTXO")]
fn consolidates_sol(world: &mut SquadsLifecycleWorld, name: String, amount: u64) {
    world
        .net
        .wait_for_consolidated(viewing_key_account_address(&name), SOL_ASSET_ID, amount)
        .expect("consolidate SOL UTXO");
}
