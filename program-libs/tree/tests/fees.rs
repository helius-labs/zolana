use zolana_tree::{error::TreeError, NullifierTreeInitParams, TreeAccount, TreeFeeSchedule};

const HEIGHT: u8 = 32;
const DISCRIMINATOR: u8 = 7;
const TREE_ID: u16 = 11;
const ZKP_BATCH_SIZE: u64 = 250;

const EXACT: TreeFeeSchedule = TreeFeeSchedule {
    fee_per_nullifier: 190,
    append_reimbursement: 5_000,
    close_reimbursement: 170,
};

fn init_tree(bytes: &mut [u8], fees: TreeFeeSchedule) -> Result<TreeAccount<'_>, TreeError> {
    TreeAccount::init(
        bytes,
        DISCRIMINATOR,
        HEIGHT,
        [2u8; 32],
        TREE_ID,
        NullifierTreeInitParams::default(),
        fees,
    )
}

#[test]
fn at_cost_derives_the_smallest_solvent_fee() {
    assert_eq!(TreeFeeSchedule::at_cost(250, 5_000, 170), Some(EXACT));
    let small = TreeFeeSchedule::at_cost(10, 5_000, 170).unwrap();
    assert_eq!(small.fee_per_nullifier, 670);
    let rounded = TreeFeeSchedule::at_cost(3, 10, 0).unwrap();
    assert_eq!(rounded.fee_per_nullifier, 4);
    assert_eq!(TreeFeeSchedule::at_cost(0, 5_000, 170), None);
    assert_eq!(TreeFeeSchedule::at_cost(250, u64::MAX, 170), None);
}

#[test]
fn init_writes_a_valid_schedule_with_an_empty_balance() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let tree = init_tree(&mut bytes, EXACT).unwrap();
    assert_eq!(tree.fees(), EXACT);
    assert_eq!(tree.fee_balance(), 0);
}

#[test]
fn init_stores_an_insolvent_schedule() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let insolvent = TreeFeeSchedule {
        fee_per_nullifier: 0,
        append_reimbursement: 1,
        close_reimbursement: 0,
    };
    let tree = init_tree(&mut bytes, insolvent).unwrap();
    assert_eq!(tree.fees(), insolvent);
    assert_eq!(tree.fee_balance(), 0);
}

#[test]
fn set_fee_schedule_keeps_the_balance() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = init_tree(&mut bytes, EXACT).unwrap();
    assert_eq!(tree.credit_insertion_fee(3), Ok(570));
    let doubled = TreeFeeSchedule {
        fee_per_nullifier: 380,
        append_reimbursement: 10_000,
        close_reimbursement: 340,
    };
    tree.set_fee_schedule(doubled);
    assert_eq!(tree.fees(), doubled);
    assert_eq!(tree.fee_balance(), 570);
    assert_eq!(tree.credit_insertion_fee(1), Ok(380));
    assert_eq!(tree.fee_balance(), 950);
}

#[test]
fn credit_insertion_fee_overflow_is_reported() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = init_tree(&mut bytes, EXACT).unwrap();
    assert_eq!(
        tree.credit_insertion_fee(u64::MAX),
        Err(TreeError::FeeOverflow)
    );
    assert_eq!(tree.fee_balance(), 0);
}

#[test]
fn take_append_reimbursement_pays_up_to_the_balance() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = init_tree(&mut bytes, EXACT).unwrap();
    assert_eq!(tree.take_append_reimbursement(1), 0);

    tree.credit_insertion_fee(ZKP_BATCH_SIZE).unwrap();
    assert_eq!(tree.fee_balance(), 47_500);
    assert_eq!(tree.take_append_reimbursement(1), 5_000);
    assert_eq!(tree.fee_balance(), 42_500);

    assert_eq!(tree.take_append_reimbursement(9), 42_500);
    assert_eq!(tree.fee_balance(), 0);
    assert_eq!(tree.take_append_reimbursement(1), 0);
}

#[test]
fn take_close_reimbursement_pays_up_to_the_balance() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = init_tree(&mut bytes, EXACT).unwrap();
    tree.credit_insertion_fee(2).unwrap();
    assert_eq!(tree.fee_balance(), 380);

    assert_eq!(tree.take_close_reimbursement(1), 170);
    assert_eq!(tree.fee_balance(), 210);
    assert_eq!(tree.take_close_reimbursement(2), 210);
    assert_eq!(tree.fee_balance(), 0);
    assert_eq!(tree.take_close_reimbursement(1), 0);
}

#[test]
fn take_reimbursement_saturates_to_the_balance() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = init_tree(&mut bytes, EXACT).unwrap();
    tree.credit_insertion_fee(1).unwrap();
    assert_eq!(tree.take_close_reimbursement(u64::MAX), 190);
    assert_eq!(tree.fee_balance(), 0);
}

#[test]
fn zero_schedule_charges_and_pays_nothing() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = init_tree(&mut bytes, TreeFeeSchedule::default()).unwrap();
    assert_eq!(tree.credit_insertion_fee(8), Ok(0));
    assert_eq!(tree.take_append_reimbursement(3), 0);
    assert_eq!(tree.take_close_reimbursement(8), 0);
    assert_eq!(tree.fee_balance(), 0);
}
