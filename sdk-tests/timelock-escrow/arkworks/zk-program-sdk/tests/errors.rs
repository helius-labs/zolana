use std::error::Error;

use ark_relations::r1cs::SynthesisError;
use zk_program_sdk::{
    circuit::{CircuitLabel, FailedConstraint, LabelKind},
    CircuitError, CircuitErrorKind, ClientError, ProverError, ProverErrorKind,
};

fn divide_by_zero() -> Result<(), CircuitError> {
    Err(CircuitErrorKind::DivisionByZero)?
}
const DIVIDE_BY_ZERO_LINE: u32 = line!() - 2;

fn unassigned() -> Result<(), SynthesisError> {
    Err(SynthesisError::AssignmentMissing)
}

fn missing_assignment() -> Result<(), CircuitError> {
    Ok(unassigned().map_err(CircuitErrorKind::Internal)?)
}
const MISSING_ASSIGNMENT_LINE: u32 = line!() - 2;

fn foreign_error() -> Result<(), CircuitError> {
    Err(SynthesisError::Unsatisfiable)?
}
const FOREIGN_ERROR_LINE: u32 = line!() - 2;

#[track_caller]
fn broken(rule: &'static str) -> CircuitError {
    CircuitError::rule_broken(rule)
}

fn is_this_file(file: &str) -> bool {
    file.ends_with("tests/errors.rs")
}

#[test]
fn question_mark_records_its_line() {
    for (error, line) in [
        (divide_by_zero(), DIVIDE_BY_ZERO_LINE),
        (missing_assignment(), MISSING_ASSIGNMENT_LINE),
        (foreign_error(), FOREIGN_ERROR_LINE),
    ] {
        let location = error.expect_err("the helper fails").location();
        assert!(is_this_file(location.file()), "{location}");
        assert_eq!(location.line(), line);
    }
}

#[test]
fn a_tracked_helper_records_its_caller() {
    let (error, line) = (broken("the rule"), line!());
    assert!(is_this_file(error.location().file()));
    assert_eq!(error.location().line(), line);
    assert_eq!(error.broken_rule(), Some("the rule"));
    assert_eq!(error.name(), "CircuitError.RuleBroken");
}

#[test]
fn into_records_its_line() {
    let error: CircuitError = CircuitErrorKind::NotZeroOrOne.into();
    let line = line!() - 1;
    assert_eq!(error.location().line(), line);
    assert_eq!(error.to_string(), "a value is neither 0 nor 1");
}

#[test]
fn a_wrapped_circuit_error_keeps_its_message_name_and_origin() {
    let circuit = broken("the transfer exceeds the balance");
    let origin = circuit.location();
    let client = ClientError::from(circuit);
    assert_eq!(client.to_string(), "the transfer exceeds the balance");
    assert_eq!(client.name(), "CircuitError.RuleBroken");
    assert_eq!(client.location(), origin);
    assert_eq!(
        client.broken_rule(),
        Some("the transfer exceeds the balance")
    );
    assert!(client.circuit_error().is_some());

    let prover = ProverError::from(broken("the transfer exceeds the balance"));
    assert_eq!(prover.to_string(), "the transfer exceeds the balance");
    assert_eq!(prover.name(), "CircuitError.RuleBroken");
    assert_eq!(
        prover.broken_rule(),
        Some("the transfer exceeds the balance")
    );
}

#[test]
fn debug_prints_every_frame() {
    let circuit = broken("the rule");
    let origin = circuit.location();
    let client = ClientError::from(circuit);
    let crossing = line!() - 1;
    let debug = format!("{client:?}");
    assert!(
        debug.starts_with(&format!(
            "CircuitError: the rule\n  at {origin}\nClientError\n  at "
        )),
        "{debug}"
    );
    assert!(debug.ends_with(&format!(":{crossing}:18")), "{debug}");
}

#[test]
fn the_source_chain_repeats_no_message() {
    let client = ClientError::from(foreign_error().expect_err("the helper fails"));
    let mut messages = vec![client.to_string()];
    let mut source = client.source();
    while let Some(error) = source {
        messages.push(error.to_string());
        source = error.source();
    }
    let mut unique = messages.clone();
    unique.dedup();
    assert_eq!(messages, unique);
}

#[test]
fn a_broken_row_reports_the_rule_and_its_line() {
    let label = CircuitLabel {
        kind: LabelKind::Check,
        text: "the escrow locks nothing",
        file: "src/circuit/escrow.rs",
        line: 33,
        column: 24,
        rows: 4..6,
        private_variables: 0..0,
    };
    let error = ProverError::from(ProverErrorKind::ProofInputsBreakRule(Box::new(
        FailedConstraint {
            row: 5,
            label: Some(label.clone()),
        },
    )));
    assert_eq!(error.broken_rule(), Some("the escrow locks nothing"));
    assert_eq!(error.location().to_string(), "src/circuit/escrow.rs:33:24");
    assert_eq!(error.name(), "ProverError.ProofInputsBreakRule");

    let scope = ProverError::from(ProverErrorKind::ProofInputsBreakRule(Box::new(
        FailedConstraint {
            row: 5,
            label: Some(CircuitLabel {
                kind: LabelKind::Scope,
                ..label
            }),
        },
    )));
    assert_eq!(scope.broken_rule(), None);
}

#[test]
fn errors_stay_small() {
    assert!(size_of::<Result<(), CircuitError>>() <= 128);
    assert!(size_of::<Result<(), ClientError>>() <= 128);
    assert!(size_of::<Result<(), ProverError>>() <= 128);
}

#[test]
fn errors_cross_threads() {
    fn send_sync<T: Send + Sync + 'static>() {}
    send_sync::<CircuitError>();
    send_sync::<ClientError>();
    send_sync::<ProverError>();
}
