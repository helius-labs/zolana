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
        account.nullifier_tree().queue_next_index,
    )
}

/// Advance a fresh tree's nullifier progress metadata to `sequence_number`
/// while preserving every loader-validated invariant. Test fixtures use this
/// to model otherwise impractically distant states without changing roots.
pub fn set_synthetic_nullifier_sequence(tree: &mut TreeAccount<'_>, sequence_number: u64) {
    let nullifier = tree.nullifier_tree();
    let next_index = sequence_number
        .checked_mul(nullifier.zkp_batch_size)
        .and_then(|index| index.checked_add(1))
        .expect("synthetic nullifier progress fits in u64");
    assert!(
        next_index <= nullifier.capacity,
        "synthetic sequence fits tree"
    );
    let root_history_capacity =
        u64::try_from(nullifier.root_history.roots.len()).expect("root history fits in u64");
    let completed_batches = sequence_number / root_history_capacity;

    nullifier.sequence_number = sequence_number;
    nullifier.next_index = next_index;
    nullifier.queue_next_index = next_index;
    nullifier.close_before_index = if completed_batches == 0 {
        0
    } else {
        completed_batches
            .checked_sub(1)
            .and_then(|completed| completed.checked_mul(nullifier.batch_size))
            .and_then(|index| index.checked_add(1))
            .expect("synthetic close watermark fits in u64")
    };
    nullifier.root_history.current_index =
        (sequence_number % root_history_capacity + 1) % root_history_capacity;
    nullifier.currently_processing_batch_index = 0;
    nullifier.pending_batch_index = 0;
    nullifier.batches[0].start_index = next_index;
    nullifier.batches[1].start_index = next_index
        .checked_add(nullifier.batch_size)
        .expect("synthetic successor batch fits in u64");
}

/// Move a fresh tree's nullifier queue just beyond the point where dummy
/// inputs remain safe. The roots stay unchanged so proof tests isolate the
/// `allow_dummy_inputs` public input.
pub fn advance_nullifier_queue_past_dummy_threshold(tree: &mut TreeAccount<'_>) {
    let state_remaining = {
        let utxo = tree.utxo_tree();
        utxo.capacity() - utxo.next_index()
    };
    let nullifier = tree.nullifier_tree();
    let threshold = nullifier
        .capacity
        .checked_sub(state_remaining)
        .expect("nullifier capacity exceeds state capacity");
    let sequence_number = threshold.div_ceil(nullifier.zkp_batch_size);
    set_synthetic_nullifier_sequence(tree, sequence_number);
}

/// Write caller-constructed ring-config bytes at an arbitrary address.
///
/// Callers retain control over the payload and owner so malformed-account
/// tests keep their defect visible at the call site.
pub fn write_ring_config_account(
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
        .expect("write fabricated ring config");
}
