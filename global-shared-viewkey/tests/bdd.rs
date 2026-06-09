mod steps;

use cucumber::World;
use zolana_global_shared_viewkey::{EncryptedKeyShare, GlobalSharedViewKey, SharedViewKeySetup};

#[derive(Default, World)]
pub struct GsvkWorld {
    pub authority: Option<GlobalSharedViewKey>,
    pub setup: Option<SharedViewKeySetup>,
    pub returned: Vec<Vec<EncryptedKeyShare>>,
}

impl std::fmt::Debug for GsvkWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GsvkWorld")
    }
}

#[tokio::main]
async fn main() {
    GsvkWorld::cucumber()
        .fail_on_skipped()
        .run_and_exit("tests/features")
        .await;
}
