//! Background setup step: names the precondition the World already established.

use cucumber::given;

use crate::SquadsLifecycleWorld;

#[given(expr = "a fresh squads shielded pool")]
fn fresh_pool(_world: &mut SquadsLifecycleWorld) {
    // `SquadsLifecycleWorld::new` already restarted the validator + Photon and
    // created the protocol config, a tree, the squads zone config, and registered
    // it with SPP. This step exists so features can name the precondition.
}
