use zolana_interface::state;
use zolana_program_test::{ProgramTestError, ZolanaProgramTest};

pub fn tree_account_size() -> u64 {
    state::tree_account_size() as u64
}

pub fn program_test() -> ZolanaProgramTest {
    match ZolanaProgramTest::new() {
        Ok(test) => test,
        Err(ProgramTestError::MissingProgram(path)) => panic!(
            "shielded-pool .so is missing at {path:?}: run `cargo build-sbf -p shielded-pool-program`"
        ),
        Err(error) => panic!(
            "shielded-pool .so failed to load (stale or incompatible build?): {error}; \
             rebuild with `cargo build-sbf -p shielded-pool-program`"
        ),
    }
}
