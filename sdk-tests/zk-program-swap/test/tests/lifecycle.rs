mod actor;
mod localnet;
mod steps;
mod world;

use cucumber::World as _;
pub use world::SwapWorld;

fn main() {
    futures::executor::block_on(
        SwapWorld::cucumber()
            .max_concurrent_scenarios(1)
            .fail_on_skipped()
            .run_and_exit("tests/features"),
    );
}
