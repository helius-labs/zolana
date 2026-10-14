use proptest::prelude::*;
use zolana_transaction::Mint;

use super::{
    fixtures::{
        balance, broken, pairs, sources, BALANCES, PAIRS, SOURCES, TOKEN, TRANSFER,
        TRANSFER_EXCEEDS, WITHDRAW, WITHDRAWAL_EXCEEDS,
    },
    vectors::Vector,
};
use crate::harness::fixture::{check_constraints, each, Native};

fn vector(deposit: u64, amount: u64, balances: [u64; 2]) -> Vector {
    Vector {
        name: "random",
        deposit,
        amount,
        balances,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn natively_a_transfer_holds_exactly_when_it_fits_the_balance(
        deposit in 1u64..,
        amount in any::<u64>(),
    ) {
        let expected = if amount <= deposit { Ok(()) } else { Err(broken(TRANSFER_EXCEEDS)) };
        let balances = [deposit.wrapping_sub(amount), amount];
        prop_assert_eq!(
            pairs::<TRANSFER, _>(&Native, &vector(deposit, amount, balances)),
            each(&PAIRS, expected)
        );
    }

    #[test]
    fn natively_a_withdrawal_holds_exactly_when_it_fits_the_balance(
        deposit in 1u64..,
        amount in 1u64..,
    ) {
        let expected = if amount <= deposit { Ok(()) } else { Err(broken(WITHDRAWAL_EXCEEDS)) };
        let balances = [deposit.wrapping_sub(amount), 0];
        prop_assert_eq!(
            sources::<WITHDRAW, _>(&Native, &vector(deposit, amount, balances)),
            each(&SOURCES, expected)
        );
    }

    #[test]
    fn natively_every_other_source_balance_breaks_the_balance_rule(
        deposit in 1u64..,
        amount in any::<u64>(),
        claimed in any::<u64>(),
    ) {
        let amount = amount % deposit;
        prop_assume!(claimed != deposit - amount);
        prop_assert_eq!(
            pairs::<TRANSFER, _>(&Native, &vector(deposit, amount, [claimed, amount])),
            each(&PAIRS, Err(broken(BALANCES)))
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn every_fitting_transfer_checks_exactly_the_pinned_count(
        deposit in 1u64..,
        amount in any::<u64>(),
    ) {
        let amount = amount % deposit;
        let fixture = balance::<TOKEN, TOKEN, TRANSFER, true>(
            Mint::SOL,
            &vector(deposit, amount, [deposit - amount, amount]),
        );
        prop_assert_eq!(check_constraints(&fixture), Ok(1642));
    }
}
