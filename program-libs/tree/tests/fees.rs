use zolana_tree::{
    error::TreeError, NullifierTreeInitParams, TreeAccount, TreeFeeSchedule, MAX_FEE_PER_NULLIFIER,
};

const HEIGHT: u8 = 32;
const DISCRIMINATOR: u8 = 7;
const TREE_ID: u16 = 11;
const ZKP_BATCH_SIZE: u64 = 250;

const EXACT: TreeFeeSchedule = TreeFeeSchedule {
    fee_per_nullifier: 66,
    append_reimbursement: 5_000,
    close_reimbursement: 46,
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
    assert_eq!(TreeFeeSchedule::at_cost(250, 5_000, 46), Some(EXACT));
    let small = TreeFeeSchedule::at_cost(10, 5_000, 46).unwrap();
    assert_eq!(small.fee_per_nullifier, 546);
    let rounded = TreeFeeSchedule::at_cost(3, 10, 0).unwrap();
    assert_eq!(rounded.fee_per_nullifier, 4);
    assert_eq!(TreeFeeSchedule::at_cost(0, 5_000, 46), None);
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
    assert_eq!(tree.credit_insertion_fee(3), Ok(198));
    let doubled = TreeFeeSchedule {
        fee_per_nullifier: 132,
        append_reimbursement: 10_000,
        close_reimbursement: 92,
    };
    tree.set_fee_schedule(doubled).unwrap();
    assert_eq!(tree.fees(), doubled);
    assert_eq!(tree.fee_balance(), 198);
    assert_eq!(tree.credit_insertion_fee(1), Ok(132));
    assert_eq!(tree.fee_balance(), 330);
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
    assert_eq!(tree.fee_balance(), 16_500);
    assert_eq!(tree.take_append_reimbursement(1), 5_000);
    assert_eq!(tree.fee_balance(), 11_500);

    assert_eq!(tree.take_append_reimbursement(9), 11_500);
    assert_eq!(tree.fee_balance(), 0);
    assert_eq!(tree.take_append_reimbursement(1), 0);
}

#[test]
fn take_close_reimbursement_pays_up_to_the_balance() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = init_tree(&mut bytes, EXACT).unwrap();
    tree.credit_insertion_fee(2).unwrap();
    assert_eq!(tree.fee_balance(), 132);

    assert_eq!(tree.take_close_reimbursement(1), 46);
    assert_eq!(tree.fee_balance(), 86);
    // Two closes cost 92, more than the 86 left, so the balance is paid out and
    // the shortfall is simply not covered.
    assert_eq!(tree.take_close_reimbursement(2), 86);
    assert_eq!(tree.fee_balance(), 0);
    assert_eq!(tree.take_close_reimbursement(1), 0);
}

#[test]
fn take_reimbursement_saturates_to_the_balance() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = init_tree(&mut bytes, EXACT).unwrap();
    tree.credit_insertion_fee(1).unwrap();
    assert_eq!(tree.take_close_reimbursement(u64::MAX), 66);
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

#[test]
fn fee_schedule_validation_caps_the_fee_per_nullifier() {
    let at_cap = TreeFeeSchedule {
        fee_per_nullifier: MAX_FEE_PER_NULLIFIER,
        ..TreeFeeSchedule::default()
    };
    assert_eq!(at_cap.validate(), Ok(()));
    let above_cap = TreeFeeSchedule {
        fee_per_nullifier: MAX_FEE_PER_NULLIFIER + 1,
        ..at_cap
    };
    assert_eq!(above_cap.validate(), Err(TreeError::FeeTooHigh));
}

#[test]
fn init_rejects_a_fee_above_the_cap() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let above_cap = TreeFeeSchedule {
        fee_per_nullifier: MAX_FEE_PER_NULLIFIER + 1,
        ..EXACT
    };
    assert_eq!(
        init_tree(&mut bytes, above_cap).err(),
        Some(TreeError::FeeTooHigh)
    );
}

#[test]
fn live_nullifier_pdas_track_creation_and_close() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = init_tree(&mut bytes, EXACT).unwrap();
    assert_eq!(tree.live_nullifier_pdas(), 0);
    tree.record_nullifier_pdas_created(5);
    tree.record_nullifier_pdas_closed(2);
    assert_eq!(tree.live_nullifier_pdas(), 3);
    tree.record_nullifier_pdas_closed(4);
    assert_eq!(tree.live_nullifier_pdas(), 0);
}
