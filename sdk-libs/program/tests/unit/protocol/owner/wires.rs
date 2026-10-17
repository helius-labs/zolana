//! Wires found by the labels the conversion layer puts on each allocation, so
//! the tests name a preimage field instead of a hand-counted index. A wire is
//! a private variable index plus the constant one.

use zolana_program::{
    circuit::{CircuitLabel, LabelKind},
    testing, ZkCircuit,
};

pub fn labels<F: ZkCircuit>(fixture: &F) -> Vec<CircuitLabel> {
    testing::constraint_labels(fixture).expect("constraint labels")
}

pub fn allocated<F: ZkCircuit>(fixture: &F, text: &str) -> Vec<usize> {
    labels(fixture)
        .into_iter()
        .filter(|label| matches!(label.kind, LabelKind::Allocation(_)) && label.text == text)
        .map(|label| label.private_variables.start + 1)
        .collect()
}

pub fn wire<F: ZkCircuit>(fixture: &F, text: &str) -> usize {
    *allocated(fixture, text)
        .first()
        .unwrap_or_else(|| panic!("no allocation labelled {text:?}"))
}

pub fn check<F: ZkCircuit>(fixture: &F, text: &str) -> CircuitLabel {
    labels(fixture)
        .into_iter()
        .find(|label| label.kind == LabelKind::Check && label.text == text)
        .unwrap_or_else(|| panic!("no check labelled {text:?}"))
}

/// The wire allocated last before the check labelled `text` opened: for the
/// owner tag check, the product `(tag - S) * (tag - P)` it compares with 0.
pub fn before_check<F: ZkCircuit>(fixture: &F, text: &str) -> usize {
    check(fixture, text).private_variables.start
}
