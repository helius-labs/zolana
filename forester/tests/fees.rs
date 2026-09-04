use forester::run::{
    append_reimbursement_below_base_cost, reimbursement_shortfall, LAMPORTS_PER_SIGNATURE,
};

#[test]
fn shortfall_is_zero_while_the_fee_balance_covers_the_pass() {
    assert_eq!(reimbursement_shortfall(5_000, 50_000, 10), 0);
    assert_eq!(reimbursement_shortfall(5_000, 50_001, 10), 0);
    assert_eq!(reimbursement_shortfall(0, 0, 10), 0);
}

#[test]
fn shortfall_is_the_uncovered_remainder() {
    assert_eq!(reimbursement_shortfall(5_000, 47_500, 10), 2_500);
    assert_eq!(reimbursement_shortfall(5_000, 0, 3), 15_000);
    assert_eq!(reimbursement_shortfall(u64::MAX, 1, 2), u64::MAX - 1);
}

#[test]
fn base_cost_check_compares_against_one_signature() {
    assert!(append_reimbursement_below_base_cost(
        LAMPORTS_PER_SIGNATURE - 1
    ));
    assert!(!append_reimbursement_below_base_cost(
        LAMPORTS_PER_SIGNATURE
    ));
    assert!(!append_reimbursement_below_base_cost(
        LAMPORTS_PER_SIGNATURE + 1
    ));
}
