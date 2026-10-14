use zolana_program::circuit::{constant, is_in, value, CircuitVar, Field};

use super::{
    fixtures::{is_in_fixture, AssertIn, InConstants, FLAG_BROKEN, MEMBER_BROKEN},
    vectors::VECTORS,
};
use crate::harness::{
    field::field,
    fixture::{native, per_vector},
};

#[test]
fn every_value_is_in_exactly_the_sets_that_hold_it_natively() {
    assert_eq!(
        (
            per_vector(&VECTORS, |vector| native(&vector.is_in())),
            per_vector(&VECTORS, |vector| native(&vector.flipped())),
        ),
        (
            per_vector(&VECTORS, |_| Ok(())),
            per_vector(&VECTORS, |_| Err(FLAG_BROKEN)),
        )
    );
}

#[test]
fn assert_in_holds_natively_exactly_for_a_member() {
    assert_eq!(
        per_vector(&VECTORS, |vector| native(&vector.assert_in())),
        per_vector(&VECTORS, |vector| if vector.member {
            Ok(())
        } else {
            Err(MEMBER_BROKEN)
        })
    );
}

#[test]
fn nothing_is_in_the_empty_set() {
    assert_eq!(
        [
            native(&is_in_fixture::<0>(field("1"), [], false)),
            native(&is_in_fixture::<0>(field("0"), [], true)),
            native(&AssertIn::<0> {
                value: field("0"),
                set: []
            }),
        ],
        [Ok(()), Err(FLAG_BROKEN), Err(MEMBER_BROKEN)]
    );
}

#[test]
fn a_constant_value_and_set_give_a_constant_flag() {
    let set = [constant(3u64), constant(5u64)];
    let flag = |member: u64| -> Result<Field, String> {
        is_in(&constant(member), &set)
            .and_then(|flag| value(&CircuitVar::from(flag)))
            .map_err(|error| error.to_string())
    };
    assert_eq!(
        (
            flag(5),
            flag(4),
            native(&InConstants { value: field("3") }),
            native(&InConstants { value: field("4") }),
        ),
        (
            Ok(Field::from(1u64)),
            Ok(Field::from(0u64)),
            Ok(()),
            Err(MEMBER_BROKEN)
        )
    );
}
