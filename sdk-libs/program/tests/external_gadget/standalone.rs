use zolana_program::{
    circuit::{constant, Assert, ConstraintSystem, Constraints, Field, VariableRole},
    conversion::{Allocator, ProofInput},
    testing::{check_private_variables, FreeVariable},
    CircuitError, ProverError, ZkCircuit,
};

use crate::gadgets::{assert_field_sqrt, assert_isqrt, assert_isqrt_without_upper_bound};

const ISQRT_RULE: &str = "the root is the integer square root";
const SQRT_RULE: &str = "the root squares to the value";

#[derive(Clone, Copy, Debug, ProofInput)]
struct Isqrt {
    value: u64,
    root: u32,
}

impl Constraints for IsqrtCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        assert_isqrt(&self.value, &self.root, ISQRT_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
struct IsqrtWithoutUpperBound {
    value: u64,
    root: u32,
}

impl Constraints for IsqrtWithoutUpperBoundCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        assert_isqrt_without_upper_bound(&self.value, &self.root, ISQRT_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
struct FieldSqrt {
    value: Field,
    root: Field,
}

impl Constraints for FieldSqrtCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        assert_field_sqrt(&self.value, &self.root, SQRT_RULE)
    }
}

type Refusal = (&'static str, Option<&'static str>);

fn refusal(error: ProverError) -> Refusal {
    (error.name(), error.broken_rule())
}

/// Instantiate directly so native rejection cannot hide missing R1CS checks.
fn r1cs_accepts<P: ZkCircuit>(inputs: &P) -> bool {
    let cs = ConstraintSystem::new_ref();
    inputs
        .instantiate(&Allocator::R1cs(cs.clone()))
        .expect("circuit inputs")
        .constraints()
        .expect("generate constraints");
    cs.is_satisfied().expect("R1CS satisfaction")
}

#[test]
fn declared_integer_roots_check_natively_and_in_r1cs() {
    let values = [0u64, 1, 2, 15, 16, 17, u64::MAX];
    let constraints = Isqrt { value: 0, root: 0 }
        .check_constraints()
        .expect("isqrt constraints");
    let checked = values.map(|value| {
        // Witness values are computed by the caller and passed as inputs.
        Isqrt {
            value,
            root: u32::try_from(value.isqrt()).expect("32-bit root"),
        }
        .check_constraints()
        .map_err(refusal)
    });
    assert_eq!(checked, [Ok(constraints); 7]);
}

#[test]
fn isqrt_leaves_no_private_variable_free() {
    let report =
        check_private_variables(&Isqrt { value: 17, root: 4 }).expect("private variable report");
    assert_eq!(report.free, Vec::<FreeVariable>::new());
}

#[test]
fn smaller_and_larger_integer_roots_are_rejected_by_native_and_r1cs_checks() {
    let checked = [3, 5].map(|root| {
        let inputs = Isqrt { value: 17, root };
        (
            inputs.check_constraints().map_err(refusal),
            r1cs_accepts(&inputs),
        )
    });
    assert_eq!(
        checked,
        [(Err(("CircuitError.RuleBroken", Some(ISQRT_RULE))), false); 2]
    );
}

#[test]
fn a_missing_upper_bound_accepts_a_smaller_declared_root() {
    let checked = [3, 5].map(|root| {
        let inputs = IsqrtWithoutUpperBound { value: 17, root };
        (
            inputs.check_constraints().map(|_| ()).map_err(refusal),
            r1cs_accepts(&inputs),
        )
    });
    assert_eq!(
        checked,
        [
            (Ok(()), true),
            (Err(("CircuitError.RuleBroken", Some(ISQRT_RULE))), false),
        ]
    );
}

#[test]
fn field_sqrt_accepts_either_declared_root_and_rejects_an_incorrect_one() {
    let root = Field::from(3u64);
    let checked = [root, -root, root + Field::from(1u64)].map(|root| {
        let inputs = FieldSqrt {
            value: Field::from(9u64),
            root,
        };
        (
            inputs.check_constraints().map_err(refusal),
            r1cs_accepts(&inputs),
        )
    });
    assert_eq!(
        checked,
        [
            (Ok(1), true),
            (Ok(1), true),
            (Err(("CircuitError.RuleBroken", Some(SQRT_RULE))), false),
        ]
    );
}

#[test]
fn a_non_square_rejects_supplied_root_candidates_in_r1cs() {
    let checked = [0u64, 1, 2, 3, u64::MAX].map(|root| {
        let inputs = FieldSqrt {
            value: Field::from(5u64),
            root: Field::from(root),
        };
        (
            inputs.check_constraints().map_err(refusal),
            r1cs_accepts(&inputs),
        )
    });
    assert_eq!(
        checked,
        [(Err(("CircuitError.RuleBroken", Some(SQRT_RULE))), false); 5]
    );
}

const PRODUCT_RULE: &str = "(3a + 2)(b - 5) = result + 7";

#[derive(Clone, Copy, Debug, ProofInput)]
struct LinearProduct {
    left: Field,
    right: Field,
    result: Field,
}

impl Constraints for LinearProductCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let left = &self.left * Field::from(3u64) + Field::from(2u64);
        let right = &self.right - Field::from(5u64);
        left.assert_product(&right, &(&self.result + Field::from(7u64)), PRODUCT_RULE)
    }
}

#[test]
fn external_linear_combinations_constrain_declared_inputs_in_one_r1cs_row() {
    let checked = [17u64, 18].map(|result| {
        let inputs = LinearProduct {
            left: Field::from(2u64),
            right: Field::from(8u64),
            result: Field::from(result),
        };
        (
            inputs.check_constraints().map_err(refusal),
            r1cs_accepts(&inputs),
        )
    });
    assert_eq!(
        checked,
        [
            (Ok(1), true),
            (Err(("CircuitError.RuleBroken", Some(PRODUCT_RULE))), false),
        ]
    );
}

#[derive(Clone, Copy, Debug, ProofInput)]
struct UnusedRoot {
    value: Field,
    root: Field,
}

impl Constraints for UnusedRootCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.value.assert_equal(&constant(7u64), "value is seven")
    }
}

#[test]
fn existing_private_variable_checks_find_unused_declared_inputs() {
    let report = check_private_variables(&UnusedRoot {
        value: Field::from(7u64),
        root: Field::from(3u64),
    })
    .expect("private variable report");
    let free: Vec<_> = report
        .free
        .iter()
        .map(|free| (free.variable, free.role))
        .collect();
    assert_eq!(free, vec![(1, VariableRole::Constrained)]);
}
