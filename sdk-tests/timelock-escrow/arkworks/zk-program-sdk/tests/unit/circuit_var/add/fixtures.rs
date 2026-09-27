use std::fmt::Debug;

use zk_program_sdk::{
    circuit::{Assert, CircuitType, CircuitVar, Constraints, Field},
    conversion::{Allocator, Placeholder, ProofInput},
    CircuitError, ZkCircuit,
};

use super::vectors::Vector;

pub const RULE: &str = "the sum is left plus right";
pub const FILE: &str = file!();

pub type Refusal = (&'static str, Option<&'static str>, &'static str);

pub fn outcome<T>(result: Result<T, CircuitError>) -> Result<T, Refusal> {
    result.map_err(|error| (error.name(), error.broken_rule(), error.location().file()))
}

pub const RULE_BROKEN: Refusal = ("CircuitError.RuleBroken", Some(RULE), FILE);

type VariableForm = fn(&CircuitVar, &CircuitVar) -> CircuitVar;
type ConstantForm = fn(&CircuitVar, Field) -> CircuitVar;

pub const VARIABLE_FORMS: [(&str, VariableForm); 6] = [
    ("a + b", |a, b| a.clone() + b.clone()),
    ("a + &b", |a, b| a.clone() + b),
    ("&a + b", |a, b| a + b.clone()),
    ("&a + &b", |a, b| a + b),
    ("a += b", |a, b| {
        let mut sum = a.clone();
        sum += b.clone();
        sum
    }),
    ("a += &b", |a, b| {
        let mut sum = a.clone();
        sum += b;
        sum
    }),
];

pub const CONSTANT_FORMS: [(&str, ConstantForm); 3] = [
    ("a + k", |a, k| a.clone() + k),
    ("&a + k", |a, k| a + k),
    ("a += k", |a, k| {
        let mut sum = a.clone();
        sum += k;
        sum
    }),
];

pub trait Operands {
    fn form(&self) -> CircuitVar;
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Variables<const FORM: usize> {
    pub left: Field,
    pub right: Field,
    pub sum: Field,
}

impl<const FORM: usize> Operands for VariablesCircuit<FORM> {
    fn form(&self) -> CircuitVar {
        let (_, form) = VARIABLE_FORMS[FORM];
        form(&self.left, &self.right)
    }
}

impl<const FORM: usize> Constraints for VariablesCircuit<FORM> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.form().assert_equal(&self.sum, RULE)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Constant(pub Field);

#[derive(Clone, Debug)]
pub struct ConstantCircuit(pub Field);

impl CircuitType for ConstantCircuit {}

impl ProofInput for Constant {
    type Circuit = ConstantCircuit;

    fn instantiate(&self, _allocator: &Allocator) -> Result<ConstantCircuit, CircuitError> {
        Ok(ConstantCircuit(self.0))
    }
}

impl Placeholder for Constant {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self(Field::from(0u64)))
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct WithConstant<const FORM: usize> {
    pub left: Field,
    pub right: Constant,
    pub sum: Field,
}

impl<const FORM: usize> Operands for WithConstantCircuit<FORM> {
    fn form(&self) -> CircuitVar {
        let (_, form) = CONSTANT_FORMS[FORM];
        form(&self.left, self.right.0)
    }
}

impl<const FORM: usize> Constraints for WithConstantCircuit<FORM> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.form().assert_equal(&self.sum, RULE)
    }
}

pub trait Visit {
    type Output;

    fn visit<F>(&self, fixture: F) -> Self::Output
    where
        F: ZkCircuit + Copy + Debug,
        F::Circuit: Operands;
}

pub type Visited<T> = Vec<(&'static str, T)>;

pub fn variable_forms<V: Visit>(
    visitor: &V,
    (left, right, sum): (Field, Field, Field),
) -> Visited<V::Output> {
    variable_form_names()
        .into_iter()
        .zip([
            visitor.visit(Variables::<0> { left, right, sum }),
            visitor.visit(Variables::<1> { left, right, sum }),
            visitor.visit(Variables::<2> { left, right, sum }),
            visitor.visit(Variables::<3> { left, right, sum }),
            visitor.visit(Variables::<4> { left, right, sum }),
            visitor.visit(Variables::<5> { left, right, sum }),
        ])
        .collect()
}

pub fn constant_forms<V: Visit>(
    visitor: &V,
    (left, right, sum): (Field, Field, Field),
) -> Visited<V::Output> {
    let right = Constant(right);
    constant_form_names()
        .into_iter()
        .zip([
            visitor.visit(WithConstant::<0> { left, right, sum }),
            visitor.visit(WithConstant::<1> { left, right, sum }),
            visitor.visit(WithConstant::<2> { left, right, sum }),
        ])
        .collect()
}

pub fn every_form<V: Visit>(visitor: &V, fields: (Field, Field, Field)) -> Visited<V::Output> {
    let mut outputs = variable_forms(visitor, fields);
    outputs.extend(constant_forms(visitor, fields));
    outputs
}

pub fn per_vector<T>(
    vectors: &[Vector],
    forms: impl Fn((Field, Field, Field)) -> Visited<T>,
) -> Visited<Visited<T>> {
    vectors
        .iter()
        .map(|vector| (vector.name, forms(vector.fields())))
        .collect()
}

pub fn expected<T>(
    vectors: &[Vector],
    forms: &[&'static str],
    value: impl Fn(&Vector, &'static str) -> T,
) -> Visited<Visited<T>> {
    vectors
        .iter()
        .map(|vector| {
            let outputs = forms
                .iter()
                .map(|form| (*form, value(vector, form)))
                .collect();
            (vector.name, outputs)
        })
        .collect()
}

pub fn variable_form_names() -> Vec<&'static str> {
    VARIABLE_FORMS.iter().map(|(name, _)| *name).collect()
}

pub fn constant_form_names() -> Vec<&'static str> {
    CONSTANT_FORMS.iter().map(|(name, _)| *name).collect()
}

pub fn every_form_name() -> Vec<&'static str> {
    [variable_form_names(), constant_form_names()].concat()
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Unasserted {
    pub left: Field,
    pub right: Field,
}

impl Constraints for UnassertedCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let constant = Field::from(7u64);
        let _sums: Vec<CircuitVar> = VARIABLE_FORMS
            .iter()
            .map(|(_, form)| form(&self.left, &self.right))
            .chain(
                CONSTANT_FORMS
                    .iter()
                    .map(|(_, form)| form(&self.left, constant)),
            )
            .collect();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Double {
    pub a: Field,
    pub sum: Field,
}

impl Constraints for DoubleCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        (&self.a + &self.a).assert_equal(&self.sum, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct AddThenSubtract {
    pub a: Field,
    pub b: Field,
    pub sum: Field,
}

impl Constraints for AddThenSubtractCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        ((&self.a + &self.b) - &self.b).assert_equal(&self.sum, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct PlusFive {
    pub a: Field,
    pub sum: Field,
}

impl Constraints for PlusFiveCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        (&self.a + Field::from(5u64)).assert_equal(&self.sum, RULE)
    }
}
