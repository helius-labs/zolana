mod steps;

use cucumber::World;
use steps::UserRegistryWorld;

#[tokio::main]
async fn main() {
    UserRegistryWorld::run("tests/features/user_registry.feature").await;
}
