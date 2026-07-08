//! `create_spl_interface` step: register the scenario's SPL asset.

use cucumber::given;

use crate::SquadsLifecycleWorld;

#[given(expr = "an SPL asset exists")]
fn spl_asset_exists(world: &mut SquadsLifecycleWorld) {
    world.ensure_spl_asset().expect("create SPL asset");
}
