//! Shared proof-backed environment and tree inspection helpers for
//! shielded-pool `transact` tests.

use solana_account::Account;
use solana_pubkey::Pubkey;
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::prover::spawn_workspace_prover;
use zolana_tree::TreeAccount;

pub use super::fixtures::Pool;

/// Start the workspace prover and return an initialized pool backend.
pub fn proof_env() -> Pool {
    spawn_workspace_prover();
    Pool::initialized()
}

/// Read the on-chain roots used by a `transact` input.
pub fn tree_roots(rpc: &ZolanaProgramTest, tree: &Pubkey, utxo_index: u16) -> ([u8; 32], [u8; 32]) {
    let mut data = rpc.account_data(tree).expect("tree account");
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    (
        account.get_utxo_tree_root(utxo_index).expect("utxo root"),
        account.get_nullifier_tree_root(0).expect("nullifier root"),
    )
}

/// Read the two counters advanced by a successful `transact`.
pub fn tree_progress(rpc: &ZolanaProgramTest, tree: &Pubkey) -> (u64, u64) {
    let mut data = rpc.account_data(tree).expect("tree account");
    let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    (
        account.utxo_tree().next_index(),
        account.nullifer_tree().queue_batches.next_index,
    )
}

/// Write caller-constructed zone-config bytes at an arbitrary address.
///
/// Callers retain control over the payload and owner so malformed-account
/// tests keep their defect visible at the call site.
pub fn write_zone_config_account(
    rpc: &mut ZolanaProgramTest,
    address: Pubkey,
    owner: Pubkey,
    data: Vec<u8>,
) {
    rpc.svm
        .set_account(
            address,
            Account {
                lamports: 1_000_000_000,
                data,
                owner,
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("write fabricated zone config");
}
