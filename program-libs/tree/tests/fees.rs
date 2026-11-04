use spr_tree::{
    error::TreeError, NullifierTreeInitParams, TreeAccount, TreeFeeSchedule, MAX_FEE_PER_TREE,
};

const HEIGHT: u8 = 32;
const DISCRIMINATOR: u8 = 7;
const TREE_ID: u16 = 11;
const EXACT: TreeFeeSchedule = TreeFeeSchedule {
    fee_per_tree: 5_000,
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
        fee_per_tree: 0,
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
    assert_eq!(tree.credit_tree_fee(), Ok(5_000));
    let doubled = TreeFeeSchedule {
        fee_per_tree: 10_000,
        append_reimbursement: 10_000,
        close_reimbursement: 92,
    };
    tree.set_fee_schedule(doubled).unwrap();
    assert_eq!(tree.fees(), doubled);
    assert_eq!(tree.fee_balance(), 5_000);
    assert_eq!(tree.credit_tree_fee(), Ok(10_000));
    assert_eq!(tree.fee_balance(), 15_000);
}

#[test]
fn take_append_reimbursement_pays_up_to_the_balance() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = init_tree(&mut bytes, EXACT).unwrap();
    assert_eq!(tree.take_append_reimbursement(1), 0);

    for _ in 0..3 {
        tree.credit_tree_fee().unwrap();
    }
    assert_eq!(tree.fee_balance(), 15_000);
    assert_eq!(tree.take_append_reimbursement(1), 5_000);
    assert_eq!(tree.fee_balance(), 10_000);

    assert_eq!(tree.take_append_reimbursement(9), 10_000);
    assert_eq!(tree.fee_balance(), 0);
    assert_eq!(tree.take_append_reimbursement(1), 0);
}

#[test]
fn take_close_reimbursement_pays_up_to_the_balance() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = init_tree(&mut bytes, EXACT).unwrap();
    tree.credit_tree_fee().unwrap();
    assert_eq!(tree.fee_balance(), 5_000);

    assert_eq!(tree.take_close_reimbursement(100), 4_600);
    assert_eq!(tree.fee_balance(), 400);
    // Ten closes cost 460, more than the 400 left, so the balance is paid out
    // and the shortfall is simply not covered.
    assert_eq!(tree.take_close_reimbursement(10), 400);
    assert_eq!(tree.fee_balance(), 0);
    assert_eq!(tree.take_close_reimbursement(1), 0);
}

#[test]
fn take_reimbursement_saturates_to_the_balance() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = init_tree(&mut bytes, EXACT).unwrap();
    tree.credit_tree_fee().unwrap();
    assert_eq!(tree.take_close_reimbursement(u64::MAX), 5_000);
    assert_eq!(tree.fee_balance(), 0);
}

#[test]
fn zero_schedule_charges_and_pays_nothing() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = init_tree(&mut bytes, TreeFeeSchedule::default()).unwrap();
    assert_eq!(tree.credit_tree_fee(), Ok(0));
    assert_eq!(tree.take_append_reimbursement(3), 0);
    assert_eq!(tree.take_close_reimbursement(8), 0);
    assert_eq!(tree.fee_balance(), 0);
}

#[test]
fn fee_schedule_validation_caps_the_fee_per_tree() {
    let at_cap = TreeFeeSchedule {
        fee_per_tree: MAX_FEE_PER_TREE,
        ..TreeFeeSchedule::default()
    };
    assert_eq!(at_cap.validate(), Ok(()));
    let above_cap = TreeFeeSchedule {
        fee_per_tree: MAX_FEE_PER_TREE + 1,
        ..at_cap
    };
    assert_eq!(above_cap.validate(), Err(TreeError::FeeTooHigh));
}

#[test]
fn init_rejects_a_fee_above_the_cap() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let above_cap = TreeFeeSchedule {
        fee_per_tree: MAX_FEE_PER_TREE + 1,
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

#[test]
fn fee_balance_reserve_counts_closes_and_started_batches() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = init_tree(&mut bytes, EXACT).unwrap();
    let zkp_batch_size = NullifierTreeInitParams::default().input_queue_zkp_batch_size;
    let close = EXACT.close_reimbursement;
    let append = EXACT.append_reimbursement;
    assert_eq!(tree.fee_balance_reserve(), 0);
    let mut live = 0;
    for (target, appends) in [
        (1, 1),
        (zkp_batch_size, 1),
        (zkp_batch_size + 1, 2),
        (2 * zkp_batch_size, 2),
    ] {
        tree.record_nullifier_pdas_created(target - live);
        live = target;
        assert_eq!(
            tree.fee_balance_reserve(),
            live * close + appends * append,
            "{live} live nullifier PDAs"
        );
    }
}

#[test]
fn release_fee_surplus_lowers_the_balance_to_the_reserve() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = init_tree(&mut bytes, EXACT).unwrap();
    for _ in 0..3 {
        tree.credit_tree_fee().unwrap();
    }
    // No open PDA: nothing is owed, so the whole balance is released.
    assert_eq!(tree.release_fee_surplus(), 15_000);
    assert_eq!(tree.fee_balance(), 0);

    for _ in 0..3 {
        tree.credit_tree_fee().unwrap();
    }
    tree.record_nullifier_pdas_created(1);
    let reserve = EXACT.close_reimbursement + EXACT.append_reimbursement;
    assert_eq!(tree.fee_balance_reserve(), reserve);
    assert_eq!(tree.release_fee_surplus(), 15_000 - reserve);
    assert_eq!(tree.fee_balance(), reserve);
    assert_eq!(tree.release_fee_surplus(), 0, "a second release is a no-op");
    assert_eq!(tree.fee_balance(), reserve);
}

#[test]
fn release_fee_surplus_keeps_a_balance_below_the_reserve() {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    let mut tree = init_tree(&mut bytes, EXACT).unwrap();
    tree.credit_tree_fee().unwrap();
    tree.record_nullifier_pdas_created(
        NullifierTreeInitParams::default().input_queue_zkp_batch_size,
    );
    assert!(tree.fee_balance() < tree.fee_balance_reserve());
    assert_eq!(tree.release_fee_surplus(), 0);
    assert_eq!(tree.fee_balance(), EXACT.fee_per_tree);
}
