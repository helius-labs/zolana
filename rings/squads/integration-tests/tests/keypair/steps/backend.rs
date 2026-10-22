//! Backend `getBalances` steps: the backend decrypts an account's balance from
//! on-chain data and its auditor secret alone.

use cucumber::then;
use squads_ring_tests::localnet::{SOL_ASSET_ID, SPL_ASSET_ID};

use crate::{fixture::viewing_key_account_address, world::SquadsLifecycleWorld};

#[then(expr = "the backend auditor decrypts {word}'s SOL balance as {int} lamports")]
fn backend_sol_balance(world: &mut SquadsLifecycleWorld, name: String, amount: u64) {
    world
        .net
        .wait_for_balance(viewing_key_account_address(&name), SOL_ASSET_ID, amount)
        .expect("backend SOL balance");
}

#[then(expr = "the backend auditor decrypts {word}'s SPL balance as {int} tokens")]
fn backend_spl_balance(world: &mut SquadsLifecycleWorld, name: String, amount: u64) {
    world
        .net
        .wait_for_balance(viewing_key_account_address(&name), SPL_ASSET_ID, amount)
        .expect("backend SPL balance");
}
