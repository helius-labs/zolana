use zk_program_sdk::{
    circuit::{value, CircuitVar, Constraints, Field, LabelKind, VariableRole},
    conversion::{Allocator, ProofInput},
    testing::{check_forged_hint, check_private_variables, constraint_labels, FreeVariable},
    CircuitError, ProverError, ProverErrorKind, ZkCircuit,
};

use crate::gadgets::{
    field_sqrt, forgetful, isqrt, isqrt_without_upper_bound, FORGOTTEN_HINT, ISQRT_HINT,
    ISQRT_RULE, NOT_A_SQUARE, SQRT_HINT, SQRT_RULE,
};

#[derive(Clone, Copy, Debug, ProofInput)]
struct Isqrt {
    value: u64,
}

impl Constraints for IsqrtCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        isqrt(&self.value).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
struct IsqrtWithoutUpperBound {
    value: u64,
}

impl Constraints for IsqrtWithoutUpperBoundCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        isqrt_without_upper_bound(&self.value).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
struct FieldSqrt {
    value: Field,
}

impl Constraints for FieldSqrtCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        field_sqrt(&self.value).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
struct Forgetful {
    value: Field,
}

impl Constraints for ForgetfulCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        forgetful(&self.value)
    }
}

type Refusal = (&'static str, Option<&'static str>);

fn refusal(error: ProverError) -> Refusal {
    (error.name(), error.broken_rule())
}

const BREAKS_ISQRT_RULE: Refusal = ("ProverError.ProofInputsBreakRule", Some(ISQRT_RULE));

fn native_isqrt(input: u64) -> Field {
    let circuit = Isqrt { value: input }
        .instantiate(&Allocator::native())
        .expect("native isqrt input");
    let root = isqrt(&circuit.value).expect("native isqrt");
    value(&CircuitVar::from(root)).expect("native root")
}

fn native_sqrt(input: Field) -> Result<Field, CircuitError> {
    let circuit = FieldSqrt { value: input }
        .instantiate(&Allocator::native())
        .expect("native sqrt input");
    value(&field_sqrt(&circuit.value)?)
}

#[test]
fn isqrt_matches_the_integer_square_root_natively_and_in_r1cs() {
    let values = [0, 1, 2, 15, 16, 17, u64::MAX];
    let constraints = Isqrt { value: 0 }
        .check_constraints()
        .expect("isqrt constraints");
    let checked: Vec<(Field, Result<usize, &str>)> = values
        .iter()
        .map(|&value| {
            (
                native_isqrt(value),
                Isqrt { value }
                    .check_constraints()
                    .map_err(|error| error.name()),
            )
        })
        .collect();
    let expected: Vec<(Field, Result<usize, &str>)> = values
        .iter()
        .map(|&value| (Field::from(value.isqrt()), Ok(constraints)))
        .collect();
    assert_eq!(checked, expected);
}

#[test]
fn isqrt_leaves_no_private_variable_free() {
    let report = check_private_variables(&Isqrt { value: 17 }).expect("private variable report");
    assert_eq!(report.free, Vec::<FreeVariable>::new());
}

#[test]
fn the_hint_is_labelled_where_the_program_calls_the_gadget() {
    let hints: Vec<_> = constraint_labels(&Isqrt { value: 17 })
        .expect("isqrt labels")
        .into_iter()
        .filter(|label| label.kind == LabelKind::Allocation(VariableRole::Hint))
        .map(|label| (label.text, label.file, label.private_variables.len()))
        .collect();
    assert_eq!(hints, vec![(ISQRT_HINT, file!(), 1)]);
}

#[test]
fn a_forged_integer_root_breaks_the_rule() {
    let forged = [3u64, 5].map(|root| {
        check_forged_hint(&Isqrt { value: 17 }, ISQRT_HINT, &[Field::from(root)]).map_err(refusal)
    });
    assert_eq!(forged, [Err(BREAKS_ISQRT_RULE), Err(BREAKS_ISQRT_RULE)]);
}

#[test]
fn a_missing_upper_bound_accepts_a_smaller_root() {
    let forged = [(3u64, 17u64), (5, 17)].map(|(root, value)| {
        check_forged_hint(
            &IsqrtWithoutUpperBound { value },
            ISQRT_HINT,
            &[Field::from(root)],
        )
        .map_err(refusal)
    });
    assert_eq!(forged, [Ok(()), Err(BREAKS_ISQRT_RULE)]);
}

#[test]
fn field_sqrt_accepts_either_root_and_nothing_else() {
    let nine = Field::from(9u64);
    let root = native_sqrt(nine).expect("nine is a square");
    let forged = [-root, root + Field::from(1u64)].map(|forged| {
        check_forged_hint(&FieldSqrt { value: nine }, SQRT_HINT, &[forged]).map_err(refusal)
    });
    assert_eq!(
        (
            root * root,
            FieldSqrt { value: nine }
                .check_constraints()
                .map(|_| ())
                .map_err(refusal),
            forged,
        ),
        (
            nine,
            Ok(()),
            [
                Ok(()),
                Err(("ProverError.ProofInputsBreakRule", Some(SQRT_RULE)))
            ],
        )
    );
}

#[test]
fn a_non_square_breaks_the_rule_in_its_hint() {
    let five = Field::from(5u64);
    assert_eq!(
        (
            native_sqrt(five).map_err(|error| (error.name(), error.broken_rule())),
            FieldSqrt { value: five }
                .check_constraints()
                .map_err(refusal),
        ),
        (
            Err(("CircuitError.RuleBroken", Some(NOT_A_SQUARE))),
            Err(("CircuitError.RuleBroken", Some(NOT_A_SQUARE))),
        )
    );
}

#[test]
fn synthesis_refuses_a_hint_no_constraint_reads() {
    let error = Forgetful {
        value: Field::from(7u64),
    }
    .check_constraints()
    .expect_err("an unused hint");
    let hint = match error.kind() {
        ProverErrorKind::UnusedHint(label) => Some(label.text),
        _ => None,
    };
    assert_eq!(
        (error.name(), error.location().file(), hint),
        ("ProverError.UnusedHint", file!(), Some(FORGOTTEN_HINT))
    );
}

#[test]
fn forging_a_hint_the_circuit_lacks_is_refused() {
    assert_eq!(
        check_forged_hint(&Isqrt { value: 17 }, "no such hint", &[Field::from(1u64)])
            .map_err(|error| error.name()),
        Err("ProverError.NoSuchHint")
    );
}
