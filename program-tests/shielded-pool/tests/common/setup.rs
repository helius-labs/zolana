use zolana_interface::state;
use zolana_program_test::{ProgramTestError, ZolanaProgramTest};

pub fn tree_account_size() -> u64 {
    state::tree_account_size() as u64
}

pub fn program_test() -> Option<ZolanaProgramTest> {
    match ZolanaProgramTest::new() {
        Ok(r) => Some(r),
        Err(ProgramTestError::MissingProgram(_)) => {
            eprintln!(
                "skipping program test: shielded_pool_program.so missing - \
                 run `cargo build-sbf -p shielded-pool-program`"
            );
            None
        }
        Err(e) => panic!("program test boot failed: {e}"),
    }
}
