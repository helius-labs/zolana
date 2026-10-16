use ark_bn254::Fr;
use ark_ff::One;
use proptest::prelude::*;
use zolana_program::{
    circuit::{value, Bool, CircuitVar, Field},
    CircuitError,
};

use super::{
    fixtures::{
        ArrayAssertEqual, ArrayAssertNotEqual, ArrayIsEqual, AssertEqual, AssertEqualIf,
        AssertNotEqual, IsEqual, CLAIM_RULE, NOT_EQUAL_BROKEN, RULE_BROKEN,
    },
    vectors::LENGTH,
};
use crate::harness::{
    field::random,
    fixture::{
        assignment, breaks_rule, check_constraints, check_tampered, exported, native,
        native_circuit, outcome, Fixture,
    },
};

fn arbitrary_field() -> impl Strategy<Value = Field> {
    any::<[u8; 32]>().prop_map(random)
}

fn pair() -> impl Strategy<Value = (Field, Field)> {
    (arbitrary_field(), arbitrary_field(), any::<bool>())
        .prop_map(|(left, right, same)| (left, if same { left } else { right }))
}

fn native_is_equal(left: Field, right: Field) -> Field {
    let fixture = IsEqual {
        left,
        right,
        claimed: left,
    };
    let circuit = native_circuit(&fixture).expect("native instantiation");
    let equal = <IsEqual as Fixture<Result<Bool, CircuitError>>>::computed(&circuit);
    value(&CircuitVar::from(equal.expect("native equality"))).expect("constant flag")
}

proptest! {
    #[test]
    fn natively_each_assertion_holds_exactly_when_its_relation_does(
        (left, right) in pair(),
        condition in any::<bool>(),
    ) {
        let equal = left == right;
        prop_assert_eq!(
            (
                native(&AssertEqual { left, right }),
                native(&AssertNotEqual { left, right }),
                native(&AssertEqualIf { left, right, condition }),
                native_is_equal(left, right),
            ),
            (
                if equal { Ok(()) } else { Err(RULE_BROKEN) },
                if equal { Err(NOT_EQUAL_BROKEN) } else { Ok(()) },
                if equal || !condition { Ok(()) } else { Err(RULE_BROKEN) },
                Field::from(u64::from(equal)),
            )
        );
    }

    #[test]
    fn the_inverse_hint_proves_every_different_pair_and_nothing_proves_an_equal_one(
        (left, right) in pair(),
        hint in arbitrary_field(),
    ) {
        let r1cs = exported::<AssertNotEqual>();
        let forged = [Fr::one(), left.into(), left.into(), hint.into()];
        let honest = (left != right).then(|| {
            let witness = assignment(&AssertNotEqual { left, right });
            (
                (witness[1] - witness[2]) * witness[3],
                r1cs.first_unsatisfied(&witness),
            )
        });
        prop_assert_eq!(
            (r1cs.first_unsatisfied(&forged), honest),
            (Some(0), (left != right).then_some((Fr::one(), None)))
        );
    }

    #[test]
    fn every_honest_equality_claim_checks_three_rows_and_the_other_claim_breaks_the_last(
        (left, right) in pair(),
    ) {
        let claimed = Field::from(u64::from(left == right));
        let fixture = IsEqual { left, right, claimed };
        let flipped = Field::from(u64::from(left != right));
        prop_assert_eq!(
            (check_constraints(&fixture), check_tampered(&fixture, 3, flipped)),
            (Ok(3), Err(breaks_rule(2, CLAIM_RULE)))
        );
    }

    #[test]
    fn natively_arrays_are_equal_exactly_when_every_element_is(
        left in proptest::array::uniform3(arbitrary_field()),
        other in proptest::array::uniform3(arbitrary_field()),
        same in proptest::array::uniform3(any::<bool>()),
    ) {
        let right: [Field; LENGTH] =
            core::array::from_fn(|index| if same[index] { left[index] } else { other[index] });
        let equal = left == right;
        let fixture = ArrayIsEqual::<LENGTH> { left, right, claimed: Field::from(0u64) };
        let circuit = native_circuit(&fixture).expect("native instantiation");
        let computed = <ArrayIsEqual<LENGTH> as Fixture<Result<Bool, CircuitError>>>::computed(&circuit);
        let flag = outcome(value(&CircuitVar::from(computed.expect("native equality"))));
        prop_assert_eq!(
            (
                flag,
                native(&ArrayAssertEqual::<LENGTH> { left, right }),
                native(&ArrayAssertNotEqual::<LENGTH> { left, right }),
            ),
            (
                Ok(Field::from(u64::from(equal))),
                if equal { Ok(()) } else { Err(RULE_BROKEN) },
                if equal { Err(NOT_EQUAL_BROKEN) } else { Ok(()) },
            )
        );
    }
}
