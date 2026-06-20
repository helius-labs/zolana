//! Shield / transfer / spend / recover steps for the SOL lifecycle.

use cucumber::{given, then, when};

use crate::LifecycleWorld;

#[given(expr = "{word} shields {int} lamports of SOL")]
fn shields(world: &mut LifecycleWorld, name: String, amount: u64) {
    world.shield_sol(&name, amount).expect("shield");
}

#[when(expr = "{word} transfers {int} lamports of SOL to {word}")]
fn transfers(world: &mut LifecycleWorld, from: String, amount: u64, to: String) {
    world.transfer_sol(&from, &to, amount).expect("transfer");
}

#[when(expr = "{word} spends {int} lamports of SOL to {word}")]
fn spends(world: &mut LifecycleWorld, from: String, amount: u64, to: String) {
    world.transfer_sol(&from, &to, amount).expect("spend");
}

#[then(expr = "{word} recovers its notes by sync")]
fn recovers(world: &mut LifecycleWorld, name: String) {
    world.recover_and_assert(&name).expect("recover");
}
