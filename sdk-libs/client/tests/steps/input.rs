//! Given steps: declare the inputs and shape of the transfer under test.

use cucumber::given;

use crate::world::{asset_kind, owner, InputSpec, TransferWorld};

#[given(expr = "a {word} {word} input worth {int}")]
fn given_input(world: &mut TransferWorld, owner_word: String, asset_word: String, amount: u64) {
    world.plan.inputs.push(InputSpec {
        owner: owner(&owner_word),
        asset: asset_kind(&asset_word),
        amount,
    });
}

#[given("the (2,3) shape is declared")]
fn given_declared_shape(world: &mut TransferWorld) {
    world.plan.declared_shape = true;
}
