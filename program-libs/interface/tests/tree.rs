#![cfg(feature = "tree")]

use solana_rent::Rent;
use spr_interface::{
    state::tree::{
        default_tree_fees, nullifier_tree_params, read_tree_id, tree_account_size,
        tree_creation_step_count, tree_id_offset, tree_liquid_working_capital_lamports,
        tree_working_capital_lamports, AT_COST_APPEND_REIMBURSEMENT_LAMPORTS,
        AT_COST_CLOSE_REIMBURSEMENT_LAMPORTS, DEFAULT_FEE_PER_TREE_LAMPORTS,
        NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE, NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
        NULLIFIER_TREE_ROOT_HISTORY_CAPACITY, STATE_HEIGHT, STATE_ROOT_HISTORY_CAPACITY,
        TREE_ALLOCATION_STEP,
    },
    tree_slot::tree_id_field,
    NULLIFIER_PDA_SIZE,
};
use spr_tree::{TreeAccount, TreeFeeSchedule};

/// The default schedule charges the flat per-tree fee and reimburses
/// foresters at cost. The fee one transaction pays a tree covers the
/// reimbursements of every nullifier it can queue there: one close each, plus
/// its share of a zkp batch append. 52 is the widest input set (merge).
#[test]
fn default_tree_fees_cover_the_widest_transaction() {
    let fees = default_tree_fees();
    assert_eq!(
        fees,
        TreeFeeSchedule {
            fee_per_tree: DEFAULT_FEE_PER_TREE_LAMPORTS,
            append_reimbursement: AT_COST_APPEND_REIMBURSEMENT_LAMPORTS,
            close_reimbursement: AT_COST_CLOSE_REIMBURSEMENT_LAMPORTS,
        }
    );
    const WIDEST_INPUTS: u64 = 52;
    let zkp_batch_size = NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE;
    assert!(
        WIDEST_INPUTS * (fees.append_reimbursement + zkp_batch_size * fees.close_reimbursement)
            <= fees.fee_per_tree * zkp_batch_size
    );
}

/// The documented at-cost close rate is `ceil(append / closes_per_transaction)`
/// at the count `protocol-ops/forester/tests/close_nullifier_pdas.rs` pins.
#[test]
fn at_cost_reimbursements_match_the_pinned_closes_per_transaction() {
    const CLOSES_PER_TRANSACTION: u64 = 57;
    assert_eq!(
        AT_COST_CLOSE_REIMBURSEMENT_LAMPORTS,
        AT_COST_APPEND_REIMBURSEMENT_LAMPORTS.div_ceil(CLOSES_PER_TRANSACTION)
    );
}

#[test]
fn working_capital_funds_three_batches_of_live_nullifier_pdas() {
    let nullifier_pda_rent = Rent::default().minimum_balance(NULLIFIER_PDA_SIZE);
    assert_eq!(nullifier_pda_rent, 967_440);

    let canonical = nullifier_tree_params().input_queue_batch_size;
    assert_eq!(
        tree_working_capital_lamports(canonical, nullifier_pda_rent),
        Some(3 * 499_900 * 967_440)
    );
    assert_eq!(
        tree_working_capital_lamports(canonical / 2, nullifier_pda_rent),
        Some(3 * 249_950 * 967_440)
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
        default_tree_fees(),
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
fn tree_creation_takes_four_allocation_steps() {
    assert_eq!(STATE_ROOT_HISTORY_CAPACITY, 500);
    assert_eq!(NULLIFIER_TREE_ROOT_HISTORY_CAPACITY, 100);
    assert_eq!(NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE, 4999);
    assert_eq!(NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE, 499_900);
    nullifier_tree_params()
        .validate()
        .expect("valid production parameters");
    assert_eq!(tree_account_size(), 40_080);
    assert_eq!(tree_creation_step_count(), 4);
    assert!(tree_account_size() > 3 * TREE_ALLOCATION_STEP);
    assert!(tree_account_size() <= 4 * TREE_ALLOCATION_STEP);
}
