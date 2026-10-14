#![cfg(feature = "external-tools")]

use super::{
    fixtures::{
        ArrayAssertEqual, ArrayAssertNotEqual, ArrayIsEqual, AssertEqual, AssertEqualIf,
        AssertEqualIfConstant, AssertNotEqual, IsEqual,
    },
    vectors::LENGTH,
};
use crate::{
    harness::{
        fixture::{export, picus_export},
        picus::Verdict,
        WorkDir,
    },
    ops::picus::{verdict_of, wire_order},
};

#[test]
fn the_picus_export_leads_with_the_gadget_witnesses_and_ends_with_the_inverse_hints() {
    assert_eq!(
        (
            picus_export::<AssertEqual>() == export::<AssertEqual>(),
            wire_order::<AssertNotEqual>(),
            wire_order::<IsEqual>(),
            wire_order::<ArrayIsEqual<2>>(),
        ),
        (
            true,
            (vec![0, 3, 1, 2], 1),
            (vec![0, 4, 1, 2, 3, 5], 1),
            (vec![0, 6, 8, 10, 1, 2, 3, 4, 5, 7, 9, 11], 3),
        )
    );
}

#[test]
fn picus_finds_every_binding_assertion_deterministic() {
    let work = WorkDir::new("picus-assert-binding");
    let right_elements: Vec<usize> = (0..LENGTH).map(|index| 1 + LENGTH + index).collect();
    assert_eq!(
        [
            verdict_of::<AssertEqual>(&work, "assert-equal-right", &[2]),
            verdict_of::<AssertNotEqual>(&work, "assert-not-equal", &[]),
            verdict_of::<IsEqual>(&work, "is-equal-claimed", &[3]),
            verdict_of::<AssertEqualIfConstant<true>>(&work, "if-true-right", &[2]),
            verdict_of::<ArrayAssertEqual<LENGTH>>(&work, "array-right", &right_elements),
            verdict_of::<ArrayIsEqual<2>>(&work, "array-claimed", &[5]),
            verdict_of::<ArrayAssertNotEqual<2>>(&work, "array-not-equal", &[]),
        ],
        [Verdict::Safe; 7]
    );
}

#[test]
fn picus_finds_the_right_side_free_whenever_the_condition_can_be_false() {
    let work = WorkDir::new("picus-assert-unbound");
    assert_eq!(
        [
            verdict_of::<AssertEqualIf>(&work, "if-variable-right", &[2]),
            verdict_of::<AssertEqualIfConstant<false>>(&work, "if-false-right", &[2]),
        ],
        [Verdict::Unsafe; 2]
    );
}
