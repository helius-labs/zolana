use zk_program_sdk::{
    circuit::{value, Bool, CircuitVar, Field},
    CircuitError,
};

use super::{
    fixtures::{
        owner_tag, ArrayAssertEqual, ArrayAssertEqualIf, ArrayAssertNotEqual, ArrayIsEqual,
        AssertEqual, AssertEqualIf, AssertEqualIfConstant, AssertNotEqual, ConditionInCircuit,
        Constant, ConstantsIf, EqualConstantsIf, IsEqual, NOT_EQUAL_BROKEN, RULE_BROKEN, TAG_FILE,
        TAG_RULE,
    },
    vectors::{Arrays, Pair, ARRAYS, DIFFERENT, EQUAL, LENGTH},
};
use crate::harness::{
    field::field,
    fixture::{native, native_circuit, outcome, per_vector, Fixture, Refusal},
};

type Flag = (String, Result<Field, Refusal>);

fn flag<F: Fixture<Result<Bool, CircuitError>>>(fixture: &F) -> Flag {
    let circuit = native_circuit(fixture).expect("native instantiation");
    let equal = CircuitVar::from(F::computed(&circuit).expect("native equality"));
    (format!("{equal:?}"), outcome(value(&equal)))
}

fn constant_flag(equal: bool) -> Flag {
    let bit = u64::from(equal);
    (format!("CircuitVar::constant({bit})"), Ok(Field::from(bit)))
}

fn is_equal(pair: &Pair) -> Flag {
    let (left, right) = pair.fields();
    flag(&IsEqual {
        left,
        right,
        claimed: left,
    })
}

#[test]
fn is_equal_of_constants_is_the_constant_one_exactly_when_the_sides_are_equal() {
    assert_eq!(
        (
            per_vector(&EQUAL, is_equal),
            per_vector(&DIFFERENT, is_equal)
        ),
        (
            per_vector(&EQUAL, |_| constant_flag(true)),
            per_vector(&DIFFERENT, |_| constant_flag(false))
        )
    );
}

fn assert_equal(pair: &Pair) -> Result<(), Refusal> {
    let (left, right) = pair.fields();
    native(&AssertEqual { left, right })
}

fn assert_not_equal(pair: &Pair) -> Result<(), Refusal> {
    let (left, right) = pair.fields();
    native(&AssertNotEqual { left, right })
}

#[test]
fn assert_equal_holds_natively_exactly_for_equal_sides() {
    assert_eq!(
        (
            per_vector(&EQUAL, assert_equal),
            per_vector(&DIFFERENT, assert_equal)
        ),
        (
            per_vector(&EQUAL, |_| Ok(())),
            per_vector(&DIFFERENT, |_| Err(RULE_BROKEN))
        )
    );
}

#[test]
fn assert_not_equal_holds_natively_exactly_for_different_sides() {
    assert_eq!(
        (
            per_vector(&EQUAL, assert_not_equal),
            per_vector(&DIFFERENT, assert_not_equal)
        ),
        (
            per_vector(&EQUAL, |_| Err(NOT_EQUAL_BROKEN)),
            per_vector(&DIFFERENT, |_| Ok(()))
        )
    );
}

fn assert_equal_if(pair: &Pair) -> [Result<(), Refusal>; 6] {
    let (left, right) = pair.fields();
    [
        native(&AssertEqualIf {
            left,
            right,
            condition: false,
        }),
        native(&AssertEqualIfConstant::<false> { left, right }),
        native(&ConditionInCircuit {
            left,
            right,
            condition: Constant(false),
        }),
        native(&AssertEqualIf {
            left,
            right,
            condition: true,
        }),
        native(&AssertEqualIfConstant::<true> { left, right }),
        native(&ConditionInCircuit {
            left,
            right,
            condition: Constant(true),
        }),
    ]
}

#[test]
fn assert_equal_if_holds_natively_for_every_pair_under_false_and_for_equal_sides_under_true() {
    assert_eq!(
        (
            per_vector(&EQUAL, assert_equal_if),
            per_vector(&DIFFERENT, assert_equal_if)
        ),
        (
            per_vector(&EQUAL, |_| [Ok(()); 6]),
            per_vector(&DIFFERENT, |_| [
                Ok(()),
                Ok(()),
                Ok(()),
                Err(RULE_BROKEN),
                Err(RULE_BROKEN),
                Err(RULE_BROKEN)
            ])
        )
    );
}

#[test]
fn assert_equal_if_on_constant_sides_holds_natively_unless_they_differ_under_true() {
    assert_eq!(
        [false, true].map(|condition| (
            native(&EqualConstantsIf { condition }),
            native(&ConstantsIf { condition })
        )),
        [(Ok(()), Ok(())), (Ok(()), Err(RULE_BROKEN))]
    );
}

type ArrayOutcomes = (
    Result<(), Refusal>,
    Flag,
    Result<(), Refusal>,
    Result<(), Refusal>,
    Result<(), Refusal>,
);

fn arrays(vector: &Arrays) -> ArrayOutcomes {
    let (left, right) = vector.fields();
    (
        native(&ArrayAssertEqual::<LENGTH> { left, right }),
        flag(&ArrayIsEqual::<LENGTH> {
            left,
            right,
            claimed: field("0"),
        }),
        native(&ArrayAssertEqualIf::<LENGTH> {
            left,
            right,
            condition: false,
        }),
        native(&ArrayAssertEqualIf::<LENGTH> {
            left,
            right,
            condition: true,
        }),
        native(&ArrayAssertNotEqual::<LENGTH> { left, right }),
    )
}

#[test]
fn array_assertions_hold_natively_exactly_when_every_element_pair_is_equal() {
    assert_eq!(
        per_vector(&ARRAYS, arrays),
        per_vector(&ARRAYS, |vector| if vector.equal {
            (
                Ok(()),
                constant_flag(true),
                Ok(()),
                Ok(()),
                Err(NOT_EQUAL_BROKEN),
            )
        } else {
            (
                Err(RULE_BROKEN),
                constant_flag(false),
                Ok(()),
                Err(RULE_BROKEN),
                Ok(()),
            )
        })
    );
}

#[test]
fn empty_arrays_are_always_equal_natively() {
    let (left, right) = ([], []);
    assert_eq!(
        (
            native(&ArrayAssertEqual::<0> { left, right }),
            flag(&ArrayIsEqual::<0> {
                left,
                right,
                claimed: field("0"),
            }),
            [false, true].map(|condition| native(&ArrayAssertEqualIf::<0> {
                left,
                right,
                condition,
            })),
            native(&ArrayAssertNotEqual::<0> { left, right }),
        ),
        (
            Ok(()),
            constant_flag(true),
            [Ok(()), Ok(())],
            Err(NOT_EQUAL_BROKEN)
        )
    );
}

#[test]
fn a_one_element_array_is_equal_exactly_when_its_element_is() {
    let one = |pair: &Pair| {
        let (left, right) = pair.fields();
        flag(&ArrayIsEqual::<1> {
            left: [left],
            right: [right],
            claimed: left,
        })
    };
    assert_eq!(
        (per_vector(&EQUAL, one), per_vector(&DIFFERENT, one)),
        (
            per_vector(&EQUAL, is_equal),
            per_vector(&DIFFERENT, is_equal)
        )
    );
}

#[test]
fn assert_equal_unless_never_skipping_refuses_every_owner_tag_but_s_and_p_natively() {
    let tags = [b'S', b'P', 0, b'Q', b'T', u8::MAX];
    assert_eq!(
        tags.map(|tag| (tag, native(&owner_tag(tag)))),
        [
            (b'S', Ok(())),
            (b'P', Ok(())),
            (
                0,
                Err(("CircuitError.RuleBroken", Some(TAG_RULE), TAG_FILE))
            ),
            (
                b'Q',
                Err(("CircuitError.RuleBroken", Some(TAG_RULE), TAG_FILE))
            ),
            (
                b'T',
                Err(("CircuitError.RuleBroken", Some(TAG_RULE), TAG_FILE))
            ),
            (
                u8::MAX,
                Err(("CircuitError.RuleBroken", Some(TAG_RULE), TAG_FILE))
            ),
        ]
    );
}
