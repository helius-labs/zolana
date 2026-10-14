//! Rows and wires found through the circuit's labels, for circuits too large
//! to number by hand. Wire numbers index the exported assignment: a label's
//! private variable `v` is wire `v + 1`.

use std::ops::Range;

use ark_bn254::Fr;
use ark_ff::One;
use zolana_program::{
    circuit::{CircuitLabel, Field, LabelKind},
    testing, ZkCircuit,
};

use crate::harness::fixture::{assignment, check_tampered, ProverRefusal};

pub fn labels<F: ZkCircuit>(fixture: &F) -> Vec<CircuitLabel> {
    testing::constraint_labels(fixture).expect("constraint labels")
}

/// The row ranges of every check labelled `rule`, in row order.
pub fn checks<F: ZkCircuit>(fixture: &F, rule: &str) -> Vec<Range<usize>> {
    labels(fixture)
        .into_iter()
        .filter(|label| label.kind == LabelKind::Check && label.text == rule)
        .map(|label| label.rows)
        .collect()
}

/// The wire of every variable allocated with `text`, in allocation order.
pub fn allocated<F: ZkCircuit>(fixture: &F, text: &str) -> Vec<usize> {
    labels(fixture)
        .into_iter()
        .filter(|label| matches!(label.kind, LabelKind::Allocation(_)) && label.text == text)
        .flat_map(|label| label.private_variables)
        .map(|variable| variable + 1)
        .collect()
}

pub fn scoped<F: ZkCircuit>(fixture: &F, text: &str) -> Vec<usize> {
    labels(fixture)
        .into_iter()
        .filter(|label| label.kind == LabelKind::Scope && label.text == text)
        .flat_map(|label| label.private_variables)
        .map(|variable| variable + 1)
        .collect()
}

/// The first private wire a check labelled `rule` allocates.
pub fn first_wire_of<F: ZkCircuit>(fixture: &F, rule: &str) -> usize {
    labels(fixture)
        .into_iter()
        .find(|label| {
            label.kind == LabelKind::Check
                && label.text == rule
                && !label.private_variables.is_empty()
        })
        .map(|label| label.private_variables.start + 1)
        .expect("a check that allocates a variable")
}

/// What tampering `wire` with its honest value plus one breaks: the error, the
/// rule that names the row, and whether the row is one of that rule's rows.
pub type Broken = (&'static str, Option<&'static str>, bool);

pub fn tamper<F: ZkCircuit>(fixture: &F, wire: usize) -> Result<(), Broken> {
    let honest = assignment(fixture)[wire];
    let rows: Vec<(&'static str, Range<usize>)> = labels(fixture)
        .into_iter()
        .filter(|label| label.kind == LabelKind::Check)
        .map(|label| (label.text, label.rows))
        .collect();
    check_tampered(fixture, wire, Field::from(honest + Fr::one())).map_err(
        |(name, row, rule): ProverRefusal| {
            let inside = match (row, rule) {
                (Some(row), Some(rule)) => rows
                    .iter()
                    .any(|(text, range)| *text == rule && range.contains(&row)),
                _ => false,
            };
            (name, rule, inside)
        },
    )
}

pub const fn breaks(rule: &'static str) -> Broken {
    ("ProverError.ProofInputsBreakRule", Some(rule), true)
}
