#![cfg(feature = "tree")]

use solana_rent::Rent;
use zolana_interface::{
    state::tree::{
        default_tree_fees, nullifier_tree_params, read_tree_id, tree_account_size,
        tree_creation_step_count, tree_id_offset, tree_liquid_working_capital_lamports,
        tree_working_capital_lamports, AT_COST_APPEND_REIMBURSEMENT_LAMPORTS,
        AT_COST_CLOSE_REIMBURSEMENT_LAMPORTS, NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
        STATE_HEIGHT, STATE_ROOT_HISTORY_CAPACITY, TREE_ALLOCATION_STEP,
    },
    tree_slot::tree_id_field,
    NULLIFIER_PDA_SIZE,
};
use zolana_tree::{TreeAccount, TreeFeeSchedule};

/// The sponsored default charges nothing, so nothing accrues to reimburse
/// from either: a schedule that paid a forester out of an empty fee balance
/// would advertise a rate `take_reimbursement` can never honour.
#[test]
fn default_tree_fees_are_sponsored_for_every_batch_size() {
    for zkp_batch_size in [nullifier_tree_params().input_queue_zkp_batch_size, 10, 1] {
        assert_eq!(
            default_tree_fees(zkp_batch_size),
            Some(TreeFeeSchedule::default()),
            "zkp_batch_size {zkp_batch_size}"
        );
    }
    assert_eq!(default_tree_fees(0), None);
}

/// The documented at-cost figures: the close rate is
/// `ceil(append / closes_per_transaction)` at the count
/// `forester/tests/close_nullifier_pdas.rs` pins, and the pair prices the
/// canonical zkp batch at the 90 lamports per nullifier `xtask::tree_fees`
/// pins.
#[test]
fn at_cost_reimbursements_match_the_pinned_closes_per_transaction() {
    const CLOSES_PER_TRANSACTION: u64 = 57;
    assert_eq!(
        AT_COST_CLOSE_REIMBURSEMENT_LAMPORTS,
        AT_COST_APPEND_REIMBURSEMENT_LAMPORTS.div_ceil(CLOSES_PER_TRANSACTION)
    );

    let zkp_batch_size = nullifier_tree_params().input_queue_zkp_batch_size;
    assert_eq!(
        TreeFeeSchedule::at_cost(
            zkp_batch_size,
            AT_COST_APPEND_REIMBURSEMENT_LAMPORTS,
            AT_COST_CLOSE_REIMBURSEMENT_LAMPORTS,
        )
        .expect("at-cost schedule")
        .fee_per_nullifier,
        90
    );
}

#[test]
fn working_capital_funds_three_batches_of_live_nullifier_pdas() {
    let nullifier_pda_rent = Rent::default().minimum_balance(NULLIFIER_PDA_SIZE);
    assert_eq!(nullifier_pda_rent, 967_440);

    let canonical = nullifier_tree_params().input_queue_batch_size;
    assert_eq!(
        tree_working_capital_lamports(canonical, nullifier_pda_rent),
        Some(3 * 24_995 * 967_440)
    );
    assert_eq!(
        tree_working_capital_lamports(canonical / 2, nullifier_pda_rent),
        Some(3 * 12_497 * 967_440)
    );
    assert_eq!(tree_working_capital_lamports(canonical, u64::MAX), None);
}

#[test]
fn liquid_working_capital_excludes_rent_held_by_open_nullifier_pdas() {
    let canonical = nullifier_tree_params().input_queue_batch_size;
    assert_eq!(
        tree_liquid_working_capital_lamports(canonical, 0, 9),
        tree_working_capital_lamports(canonical, 9)
    );
    assert_eq!(
        tree_liquid_working_capital_lamports(canonical, canonical, 9),
        Some(2 * canonical * 9)
    );
    assert_eq!(
        tree_liquid_working_capital_lamports(canonical, 4 * canonical, 9),
        Some(0)
    );
}

#[test]
fn read_tree_id_reads_the_initialized_id_at_offset_two() {
    assert_eq!(tree_id_offset(), 2);
    let mut bytes = vec![0u8; tree_account_size()];
    // The `TreeAccount` borrows `bytes` mutably; read the id field off the
    // temporary so the borrow ends before the raw-byte reads below.
    let tree_id_array = TreeAccount::init(
        &mut bytes,
        1,
        STATE_HEIGHT as u8,
        [7u8; 32],
        0x1234,
        nullifier_tree_params(),
        default_tree_fees(NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE).expect("default tree fees"),
    )
    .expect("init tree")
    .tree_id_array();
    // The tree crate cannot depend on the interface, so it spells out the
    // field encoding itself; both must agree byte for byte.
    assert_eq!(tree_id_array, tree_id_field(0x1234));
    assert_eq!(read_tree_id(&bytes), Some(0x1234));
    assert_eq!(bytes.get(2..4), Some(&0x1234u16.to_le_bytes()[..]));
    assert_eq!(read_tree_id(bytes.get(..3).expect("three bytes")), None);
}

#[test]
fn tree_creation_takes_two_allocation_steps() {
    assert_eq!(STATE_ROOT_HISTORY_CAPACITY, 500);
    assert_eq!(tree_account_size(), 18_608);
    assert_eq!(tree_creation_step_count(), 2);
    assert!(tree_account_size() > TREE_ALLOCATION_STEP);
    assert!(tree_account_size() <= 2 * TREE_ALLOCATION_STEP);
}
