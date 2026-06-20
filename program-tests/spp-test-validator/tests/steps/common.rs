//! Shared setup and isolation steps.

use cucumber::{given, then};

use crate::LifecycleWorld;

#[given(expr = "a fresh shielded pool")]
fn fresh_pool(_world: &mut LifecycleWorld) {
    // `LifecycleWorld::new` already restarted the validator + Photon, started the
    // (persistent) prover, and created the protocol config and a tree. This step
    // exists so features can name the precondition.
}

#[then(expr = "{word} recovers nothing by sync")]
fn recovers_nothing(world: &mut LifecycleWorld, name: String) {
    world.recover_nothing(&name).expect("sync");
}
