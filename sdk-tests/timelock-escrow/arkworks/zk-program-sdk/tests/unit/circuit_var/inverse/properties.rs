use ark_bn254::Fr;
use ark_ff::{Field as _, One};
use proptest::prelude::*;
use zk_program_sdk::circuit::Field;

use super::fixtures::{honest, Inverse, CLAIMED_WIRE, DIVISION_BY_ZERO, RULE, RULE_BROKEN};
use crate::harness::{
    field::random,
    fixture::{breaks_rule, check_constraints, check_tampered, exported, native},
};

fn arbitrary_field() -> impl Strategy<Value = Field> {
    any::<[u8; 32]>().prop_map(random)
}

fn nonzero_field() -> impl Strategy<Value = Field> {
    arbitrary_field().prop_filter("a nonzero x", |x| *x != Field::from(0u64))
}

proptest! {
    #[test]
    fn natively_the_inverse_holds_exactly_when_the_claim_times_x_is_one(
        x in nonzero_field(),
        claimed in arbitrary_field(),
        honest_claim in any::<bool>(),
    ) {
        let inverse = if honest_claim { honest(x).inverse } else { claimed };
        let expected = if x * inverse == Field::from(1u64) { Ok(()) } else { Err(RULE_BROKEN) };
        prop_assert_eq!(native(&Inverse { x, inverse }), expected);
    }

    #[test]
    fn every_honest_inverse_checks_two_constraints_and_a_wrong_claim_names_the_rule(
        x in nonzero_field(),
        offset in nonzero_field(),
    ) {
        let fixture = honest(x);
        prop_assert_eq!(
            (
                check_constraints(&fixture),
                check_tampered(&fixture, CLAIMED_WIRE, fixture.inverse + offset),
            ),
            (Ok(2), Err(breaks_rule(1, RULE)))
        );
    }

    #[test]
    fn a_zero_x_is_refused_natively_and_by_every_witness(
        claimed in arbitrary_field(),
        witness in arbitrary_field(),
    ) {
        let zero = Field::from(0u64);
        prop_assert_eq!(
            (
                native(&Inverse { x: zero, inverse: claimed }),
                exported::<Inverse>().first_unsatisfied(&[
                    Fr::one(),
                    zero.into(),
                    claimed.into(),
                    witness.into(),
                ]),
            ),
            (Err(DIVISION_BY_ZERO), Some(0))
        );
    }

    #[test]
    fn a_wrong_inverse_witness_breaks_the_inverse_row(
        x in nonzero_field(),
        witness in arbitrary_field(),
    ) {
        let inverse = Fr::from(x).inverse().expect("a nonzero x");
        prop_assume!(Fr::from(witness) != inverse);
        prop_assert_eq!(
            exported::<Inverse>().first_unsatisfied(&[
                Fr::one(),
                x.into(),
                witness.into(),
                witness.into(),
            ]),
            Some(0)
        );
    }
}
