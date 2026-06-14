//! End-to-end BDD tests for the `Transaction` builder at shape (2,3): each
//! scenario declares inputs / sends / withdrawals, then the `Then` step builds
//! the transfer, proves it on the prover server, and verifies against the
//! committed verifying key for the selected rail (P256 `transfer_p256_2_3` or
//! Solana-only `transfer_2_3`).
//!
//! Requires a reachable prover server (started via `spawn_prover`) with the
//! `transfer_p256_2_3.key` and `transfer-eddsa_2_3.key` proving keys available.
//!
//! Run with: `cargo test -p zolana-client --test transfer_p256_2_3`

mod common;

use common::{Asset, InputSpec, Owner, SendSpec, TransferPlan, WithdrawSpec};
use cucumber::{given, then, when, World};

#[derive(Debug, Default, World)]
struct TransferWorld {
    plan: TransferPlan,
}

fn owner(word: &str) -> Owner {
    match word {
        "P256" => Owner::P256,
        "Solana" => Owner::Solana,
        other => panic!("unknown owner type: {other}"),
    }
}

fn asset(word: &str) -> Asset {
    match word {
        "SOL" => Asset::Sol,
        "SPL" => Asset::Spl,
        other => panic!("unknown asset: {other}"),
    }
}

#[given(expr = "a {word} {word} input worth {int}")]
fn given_input(world: &mut TransferWorld, owner_word: String, asset_word: String, amount: u64) {
    world.plan.inputs.push(InputSpec {
        owner: owner(&owner_word),
        asset: asset(&asset_word),
        amount,
    });
}

#[given("the (2,3) shape is declared")]
fn given_declared_shape(world: &mut TransferWorld) {
    world.plan.declared_shape = true;
}

#[when(expr = "the sender sends {int} {word} to a fresh recipient")]
fn when_sends(world: &mut TransferWorld, amount: u64, asset_word: String) {
    world.plan.sends.push(SendSpec {
        asset: asset(&asset_word),
        amount,
    });
}

#[when(expr = "the sender withdraws {int} {word} to an external account")]
fn when_withdraws(world: &mut TransferWorld, amount: u64, asset_word: String) {
    world.plan.withdraw = Some(WithdrawSpec {
        asset: asset(&asset_word),
        amount,
    });
}

#[then("the proof verifies")]
fn then_proof_verifies(world: &mut TransferWorld) {
    common::run(&world.plan);
}

fn main() {
    futures::executor::block_on(
        TransferWorld::cucumber()
            .fail_on_skipped()
            .run_and_exit("tests/features"),
    );
}
