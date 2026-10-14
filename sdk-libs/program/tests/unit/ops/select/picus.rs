#![cfg(feature = "external-tools")]

use super::{
    fixtures::{ArraySelected, SelectConstantCondition, Selected, Unasserted},
    vectors::LENGTH,
};
use crate::{
    harness::{picus::Verdict, WorkDir},
    ops::picus::{verdict_of, wire_order},
};

#[test]
fn the_picus_export_leads_with_every_product_variable() {
    assert_eq!(
        (
            wire_order::<Selected<0>>(),
            wire_order::<Unasserted>(),
            wire_order::<ArraySelected<LENGTH>>(),
        ),
        (
            (vec![0, 5, 1, 2, 3, 4], 1),
            (vec![0, 4, 1, 2, 3], 1),
            (vec![0, 11, 12, 13, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 3),
        )
    );
}

#[test]
fn picus_finds_the_selection_fixed_by_the_condition_and_the_branches() {
    let work = WorkDir::new("picus-select-fixed");
    let selected: Vec<usize> = (0..LENGTH).map(|index| 2 + 2 * LENGTH + index).collect();
    assert_eq!(
        [
            verdict_of::<Selected<0>>(&work, "selected", &[4]),
            verdict_of::<Selected<1>>(&work, "selected-method", &[4]),
            verdict_of::<Unasserted>(&work, "product", &[]),
            verdict_of::<ArraySelected<LENGTH>>(&work, "array-selected", &selected),
            verdict_of::<SelectConstantCondition<true>>(&work, "constant-selected", &[3]),
        ],
        [Verdict::Safe; 5]
    );
}

#[test]
fn picus_finds_a_branch_free_whenever_it_can_go_unchosen() {
    let work = WorkDir::new("picus-select-free");
    assert_eq!(
        [
            verdict_of::<Selected<0>>(&work, "if-true", &[2]),
            verdict_of::<Selected<0>>(&work, "if-false", &[3]),
            verdict_of::<SelectConstantCondition<true>>(&work, "constant-if-false", &[2]),
        ],
        [Verdict::Unsafe; 3]
    );
}
