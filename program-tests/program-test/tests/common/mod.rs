//! Shared harness for shielded-pool program tests: rig boot (skipping when
//! the .so is missing), the standard protocol-config + tree setup, and
//! shared error assertions.

use solana_keypair::Keypair;
use zolana_program_test::{PoolTestRig, RigError};

/// 1.16 MB — big enough for the combined account; the program ignores any
/// caller-supplied size and uses `tree_account_size()` internally.
pub const TREE_ACCOUNT_SIZE: u64 = 1_200_000;

pub fn rig() -> Option<PoolTestRig> {
    match PoolTestRig::new() {
        Ok(r) => Some(r),
        Err(RigError::MissingProgram(_)) => {
            eprintln!(
                "skipping program test: shielded_pool_program.so missing — \
                 run `cargo build-sbf -p shielded-pool-program`"
            );
            None
        }
        Err(e) => panic!("rig boot failed: {e}"),
    }
}

/// Boot a rig with the canonical protocol config and one tree, returning
/// (rig, authority, tree).
pub fn rig_with_tree() -> Option<(PoolTestRig, Keypair, Keypair)> {
    let mut rig = rig()?;
    let authority = Keypair::new();
    rig.create_protocol_config(&authority)
        .expect("create_protocol_config");
    let tree = rig
        .create_tree(TREE_ACCOUNT_SIZE, &authority)
        .expect("create_tree");
    Some((rig, authority, tree))
}

/// Assert a rig error is the program's `Custom(code)`. The discriminants are
/// the stable on-chain error codes (`error.rs`).
#[allow(dead_code)] // each test binary compiles this module; not all use it
#[track_caller]
pub fn assert_custom(err: RigError, code: u32) {
    let msg = format!("{err}");
    let needle = format!("Custom({code})");
    assert!(msg.contains(&needle), "expected {needle}, got: {msg}");
}

/// Assert a rig error is a built-in Solana instruction error (by name as it
/// appears in litesvm's debug output, e.g. "NotEnoughAccountKeys").
#[allow(dead_code)] // each test binary compiles this module; not all use it
#[track_caller]
pub fn assert_instruction_error(err: RigError, name: &str) {
    let msg = format!("{err}");
    assert!(msg.contains(name), "expected {name}, got: {msg}");
}
