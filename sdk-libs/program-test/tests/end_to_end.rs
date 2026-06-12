//! End-to-end happy-path coverage of the shielded-pool program against a
//! real .so loaded by litesvm: create_pool_tree plus the
//! batch_update_address_tree authorization guard. Tree appends and queue
//! insertions happen only inside value-moving instructions
//! (proofless_shield, transact), which carry their own tests.
//!
//! Requires `cargo build-sbf -p shielded-pool-program` to have produced
//! `target/deploy/shielded_pool_program.so`. The PoolTestRig returns
//! `RigError::MissingProgram` if not.
//!
//! `batch_update_address_tree` needs a real Groth16 proof and lives in
//! `registry_cpi.rs` once the prover wiring lands.

use light_program_test::{PoolTestRig, RigError};
use solana_signer::Signer;

/// 1.16 MB — big enough for the combined account; the program ignores any
/// caller-supplied size and uses `pool_tree_account_size()` internally.
const TREE_ACCOUNT_SIZE: u64 = 1_200_000;

fn rig() -> Option<PoolTestRig> {
    match PoolTestRig::new() {
        Ok(r) => Some(r),
        Err(RigError::MissingProgram(_)) => {
            eprintln!(
                "skipping end-to-end test: shielded_pool_program.so missing — \
                 run `cargo build-sbf -p shielded-pool-program`"
            );
            None
        }
        Err(e) => panic!("rig boot failed: {e}"),
    }
}

#[test]
fn create_pool_tree_succeeds() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(TREE_ACCOUNT_SIZE)
        .expect("create_pool_tree");

    // The on-chain program allocated the account and wrote the combined
    // discriminator (1) into the first 8 bytes.
    let data = rig.account_data(&tree.pubkey()).expect("account data");
    assert!(data.len() >= 8);
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&data[..8]);
    assert_eq!(u64::from_le_bytes(disc), 1, "combined discriminator");
}

#[test]
fn batch_update_address_tree_rejects_non_registry_signer() {
    use zolana_interface::instruction::BatchUpdateAddressTreeData;

    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(TREE_ACCOUNT_SIZE)
        .expect("create_pool_tree");

    // Payer is just a random keypair, not the registry's CPI authority PDA.
    // Shielded-pool's verify() must reject this — UnauthorizedCaller.
    let data = BatchUpdateAddressTreeData {
        new_root: [9u8; 32],
        compressed_proof_a: [0u8; 32],
        compressed_proof_b: [0u8; 64],
        compressed_proof_c: [0u8; 32],
    };
    let err = rig
        .batch_update_address_tree(&tree, data)
        .expect_err("non-registry signer must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("Custom(5)") || msg.contains("UnauthorizedCaller"),
        "expected UnauthorizedCaller (Custom(5)), got: {msg}"
    );
}
