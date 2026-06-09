use cucumber::given;
use zolana_global_shared_viewkey::GlobalSharedViewKey;

use crate::GsvkWorld;

#[given("a global shared view key authority")]
fn a_global_shared_view_key_authority(world: &mut GsvkWorld) {
    world.authority = Some(GlobalSharedViewKey::new());
}
