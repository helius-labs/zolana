//! The shape-independent layer every area's fixtures build on. A fixture is a
//! `ZkCircuit` (a `ProofInput` whose circuit implements `Constraints`); the
//! runners here take one by reference, so fixtures holding vectors or nested
//! protocol values need not be `Copy`.
//!
//! Wire numbers are indices into the exported assignment and the exported
//! `.r1cs`: wire 0 is the constant one, the only instance variable of a
//! constraint-only circuit, and the private variables follow in allocation
//! order, intermediate witnesses included.

use std::fmt::Debug;

use ark_bn254::Fr;
use zolana_program::{
    circuit::{Constraints, Field},
    conversion::Allocator,
    testing::{self, PrivateVariableReport, Tamper},
    CircuitError, ProverError, ProverErrorKind, ZkCircuit,
};

use super::iden3::{read_r1cs, read_wtns, R1cs};

const INSTANCE_VARIABLES: usize = 1;

pub type Refusal = (&'static str, Option<&'static str>, &'static str);

pub fn outcome<T>(result: Result<T, CircuitError>) -> Result<T, Refusal> {
    result.map_err(|error| (error.name(), error.broken_rule(), error.location().file()))
}

pub const fn rule_broken(rule: &'static str, file: &'static str) -> Refusal {
    ("CircuitError.RuleBroken", Some(rule), file)
}

pub type ProverRefusal = (&'static str, Option<usize>, Option<&'static str>);

pub fn prover_refusal(error: ProverError) -> ProverRefusal {
    match error.kind() {
        ProverErrorKind::ConstraintsDiffer(failed)
        | ProverErrorKind::ProofInputsBreakRule(failed) => (
            error.name(),
            Some(failed.row),
            failed.label.as_ref().map(|label| label.text),
        ),
        _ => (error.name(), None, None),
    }
}

pub const fn breaks_rule(row: usize, rule: &'static str) -> ProverRefusal {
    ("ProverError.ProofInputsBreakRule", Some(row), Some(rule))
}

pub const fn constraints_differ(row: usize, rule: &'static str) -> ProverRefusal {
    ("ProverError.ConstraintsDiffer", Some(row), Some(rule))
}

/// A fixture that exposes a value its circuit computes, for native semantics
/// checks. Every `ZkCircuit` is a `Fixture<()>`; an area implements
/// `Fixture<T>` for the fixtures whose computed value it inspects.
pub trait Fixture<Computed = ()>: ZkCircuit + Debug {
    fn computed(circuit: &Self::Circuit) -> Computed;
}

impl<T: ZkCircuit + Debug> Fixture for T {
    fn computed(_circuit: &T::Circuit) {}
}

pub trait Visit<Computed = ()> {
    type Output;

    fn visit<F: Fixture<Computed>>(&self, fixture: &F) -> Self::Output;
}

pub type Visited<T> = Vec<(&'static str, T)>;

pub trait Named {
    fn name(&self) -> &'static str;
}

pub fn per_vector<V: Named, T>(vectors: &[V], forms: impl Fn(&V) -> T) -> Visited<T> {
    vectors
        .iter()
        .map(|vector| (vector.name(), forms(vector)))
        .collect()
}

pub fn expected<V: Named, T>(
    vectors: &[V],
    forms: &[&'static str],
    value: impl Fn(&V, &'static str) -> T,
) -> Visited<Visited<T>> {
    per_vector(vectors, |vector| {
        forms
            .iter()
            .map(|form| (*form, value(vector, form)))
            .collect()
    })
}

pub fn each<T: Clone>(names: &[&'static str], value: T) -> Visited<T> {
    names.iter().map(|name| (*name, value.clone())).collect()
}

pub fn native_circuit<F: ZkCircuit>(fixture: &F) -> Result<F::Circuit, Refusal> {
    outcome(fixture.instantiate(&Allocator::native()))
}

pub fn native<F: ZkCircuit>(fixture: &F) -> Result<(), Refusal> {
    outcome(
        fixture
            .instantiate(&Allocator::native())
            .and_then(|circuit| circuit.constraints()),
    )
}

pub fn check_constraints<F: ZkCircuit>(fixture: &F) -> Result<usize, ProverRefusal> {
    fixture.check_constraints().map_err(prover_refusal)
}

pub fn export<F: ZkCircuit>() -> Vec<u8> {
    F::export_r1cs().expect("r1cs export")
}

pub fn picus_export<F: ZkCircuit>() -> Vec<u8> {
    F::export_picus_r1cs().expect("picus r1cs export")
}

pub fn exported<F: ZkCircuit>() -> R1cs {
    read_r1cs(&export::<F>())
}

pub fn assignment<F: ZkCircuit>(fixture: &F) -> Vec<Fr> {
    read_wtns(&fixture.export_assignment().expect("assignment"))
}

pub fn with_wires(mut witness: Vec<Fr>, wires: &[(usize, Fr)]) -> Vec<Fr> {
    for (wire, value) in wires {
        *witness.get_mut(*wire).expect("witness wire") = *value;
    }
    witness
}

pub fn first_unsatisfied<F: ZkCircuit>(witness: &[Fr]) -> Option<usize> {
    exported::<F>().first_unsatisfied(witness)
}

/// `check_tampered` on the proving rows, with `wire` numbered as in the
/// exported assignment.
pub fn check_tampered<F: ZkCircuit>(
    fixture: &F,
    wire: usize,
    value: Field,
) -> Result<(), ProverRefusal> {
    let index = wire
        .checked_sub(INSTANCE_VARIABLES)
        .expect("a private wire");
    testing::check_tampered(fixture, Tamper::PrivateVariable { index, value })
        .map_err(prover_refusal)
}

pub fn check_private_variables<F: ZkCircuit>(fixture: &F) -> PrivateVariableReport {
    testing::check_private_variables(fixture).expect("private variable report")
}

pub fn no_free_variable(constraints: usize, private_variables: usize) -> PrivateVariableReport {
    PrivateVariableReport {
        constraints,
        private_variables,
        free: vec![],
        tolerated: vec![],
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size {
    pub constraints: usize,
    pub variables: usize,
}

impl Size {
    pub fn of(r1cs: &R1cs) -> Self {
        Self {
            constraints: r1cs.header.constraints,
            variables: r1cs.header.variables,
        }
    }
}

pub fn size<F: ZkCircuit>() -> Size {
    Size::of(&exported::<F>())
}

pub struct Native;

impl<C> Visit<C> for Native {
    type Output = Result<(), Refusal>;

    fn visit<F: Fixture<C>>(&self, fixture: &F) -> Self::Output {
        native(fixture)
    }
}

pub struct CheckConstraints;

impl<C> Visit<C> for CheckConstraints {
    type Output = Result<usize, ProverRefusal>;

    fn visit<F: Fixture<C>>(&self, fixture: &F) -> Self::Output {
        check_constraints(fixture)
    }
}

pub struct Export;

impl<C> Visit<C> for Export {
    type Output = Vec<u8>;

    fn visit<F: Fixture<C>>(&self, _fixture: &F) -> Vec<u8> {
        export::<F>()
    }
}

pub struct PicusExport;

impl<C> Visit<C> for PicusExport {
    type Output = Vec<u8>;

    fn visit<F: Fixture<C>>(&self, _fixture: &F) -> Vec<u8> {
        picus_export::<F>()
    }
}

pub struct Assignment;

impl<C> Visit<C> for Assignment {
    type Output = Vec<Fr>;

    fn visit<F: Fixture<C>>(&self, fixture: &F) -> Vec<Fr> {
        assignment(fixture)
    }
}

pub struct FreeVariables;

impl<C> Visit<C> for FreeVariables {
    type Output = PrivateVariableReport;

    fn visit<F: Fixture<C>>(&self, fixture: &F) -> PrivateVariableReport {
        check_private_variables(fixture)
    }
}
