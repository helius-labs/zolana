use zolana_interface::state;
use zolana_program_test::ZolanaProgramTest;

pub fn tree_account_size() -> u64 {
    state::tree_account_size() as u64
}

pub fn program_test() -> ZolanaProgramTest {
    ZolanaProgramTest::new().expect(
        "boot shielded-pool program test; run `cargo build-sbf -p shielded-pool-program` first",
    )
}
