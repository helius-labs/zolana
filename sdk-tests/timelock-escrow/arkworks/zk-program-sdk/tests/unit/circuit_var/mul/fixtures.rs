use zk_program_sdk::{
    circuit::{Assert, CircuitType, CircuitVar, Constraints, Field},
    conversion::{Allocator, Placeholder, ProofInput},
    CircuitError,
};

use crate::harness::fixture::{rule_broken, Fixture, Refusal, Visit, Visited};

pub const RULE: &str = "the product is left times right";
pub const FILE: &str = file!();

pub const RULE_BROKEN: Refusal = rule_broken(RULE, FILE);

pub const CLAIMED_WIRE: usize = 3;
pub const WITNESS_WIRE: usize = 4;
pub const CONSTANT_CLAIMED_WIRE: usize = 2;

/// The claimed product's wire in a fixture's assignment: a variable form
/// allocates the product witness after it, a constant form allocates none.
pub fn claimed_wire(assignment_len: usize) -> usize {
    match assignment_len {
        5 => CLAIMED_WIRE,
        3 => CONSTANT_CLAIMED_WIRE,
        len => panic!("no mul fixture has {len} wires"),
    }
}

type VariableForm = fn(&CircuitVar, &CircuitVar) -> CircuitVar;
type ConstantForm = fn(&CircuitVar, Field) -> CircuitVar;

pub const VARIABLE_FORMS: [(&str, VariableForm); 6] = [
    ("a * b", |a, b| a.clone() * b.clone()),
    ("a * &b", |a, b| a.clone() * b),
    ("&a * b", |a, b| a * b.clone()),
    ("&a * &b", |a, b| a * b),
    ("a *= b", |a, b| {
        let mut product = a.clone();
        product *= b.clone();
        product
    }),
    ("a *= &b", |a, b| {
        let mut product = a.clone();
        product *= b;
        product
    }),
];

pub const CONSTANT_FORMS: [(&str, ConstantForm); 3] = [
    ("a * k", |a, k| a.clone() * k),
    ("&a * k", |a, k| a * k),
    ("a *= k", |a, k| {
        let mut product = a.clone();
        product *= k;
        product
    }),
];

pub trait Operands {
    fn form(&self) -> CircuitVar;
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Variables<const FORM: usize> {
    pub left: Field,
    pub right: Field,
    pub product: Field,
}

impl<const FORM: usize> Operands for VariablesCircuit<FORM> {
    fn form(&self) -> CircuitVar {
        let (_, form) = VARIABLE_FORMS[FORM];
        form(&self.left, &self.right)
    }
}

impl<const FORM: usize> Fixture<CircuitVar> for Variables<FORM> {
    fn computed(circuit: &VariablesCircuit<FORM>) -> CircuitVar {
        circuit.form()
    }
}

impl<const FORM: usize> Constraints for VariablesCircuit<FORM> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.form().assert_equal(&self.product, RULE)
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
    pub product: Field,
}

impl<const FORM: usize> Operands for WithConstantCircuit<FORM> {
    fn form(&self) -> CircuitVar {
        let (_, form) = CONSTANT_FORMS[FORM];
        form(&self.left, self.right.0)
    }
}

impl<const FORM: usize> Fixture<CircuitVar> for WithConstant<FORM> {
    fn computed(circuit: &WithConstantCircuit<FORM>) -> CircuitVar {
        circuit.form()
    }
}

impl<const FORM: usize> Constraints for WithConstantCircuit<FORM> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.form().assert_equal(&self.product, RULE)
    }
}

pub fn variable_forms<V: Visit<CircuitVar>>(
    visitor: &V,
    (left, right, product): (Field, Field, Field),
) -> Visited<V::Output> {
    variable_form_names()
        .into_iter()
        .zip([
            visitor.visit(&Variables::<0> {
                left,
                right,
                product,
            }),
            visitor.visit(&Variables::<1> {
                left,
                right,
                product,
            }),
            visitor.visit(&Variables::<2> {
                left,
                right,
                product,
            }),
            visitor.visit(&Variables::<3> {
                left,
                right,
                product,
            }),
            visitor.visit(&Variables::<4> {
                left,
                right,
                product,
            }),
            visitor.visit(&Variables::<5> {
                left,
                right,
                product,
            }),
        ])
        .collect()
}

pub fn constant_forms<V: Visit<CircuitVar>>(
    visitor: &V,
    (left, right, product): (Field, Field, Field),
) -> Visited<V::Output> {
    let right = Constant(right);
    constant_form_names()
        .into_iter()
        .zip([
            visitor.visit(&WithConstant::<0> {
                left,
                right,
                product,
            }),
            visitor.visit(&WithConstant::<1> {
                left,
                right,
                product,
            }),
            visitor.visit(&WithConstant::<2> {
                left,
                right,
                product,
            }),
        ])
        .collect()
}

pub fn every_form<V: Visit<CircuitVar>>(
    visitor: &V,
    fields: (Field, Field, Field),
) -> Visited<V::Output> {
    let mut outputs = variable_forms(visitor, fields);
    outputs.extend(constant_forms(visitor, fields));
    outputs
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
pub struct UnassertedVariables {
    pub left: Field,
    pub right: Field,
}

impl Constraints for UnassertedVariablesCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let _products: Vec<CircuitVar> = VARIABLE_FORMS
            .iter()
            .map(|(_, form)| form(&self.left, &self.right))
            .collect();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct UnassertedConstants {
    pub left: Field,
}

impl Constraints for UnassertedConstantsCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let constant = Field::from(7u64);
        let _products: Vec<CircuitVar> = CONSTANT_FORMS
            .iter()
            .map(|(_, form)| form(&self.left, constant))
            .collect();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Square {
    pub a: Field,
    pub product: Field,
}

impl Constraints for SquareCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        (&self.a * &self.a).assert_equal(&self.product, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct SumTimes {
    pub a: Field,
    pub b: Field,
    pub c: Field,
    pub product: Field,
}

impl Constraints for SumTimesCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        ((&self.a + &self.b) * &self.c).assert_equal(&self.product, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct TimesFive {
    pub a: Field,
    pub product: Field,
}

impl Constraints for TimesFiveCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        (&self.a * Field::from(5u64)).assert_equal(&self.product, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct TimesZero {
    pub a: Field,
    pub product: Field,
}

impl Constraints for TimesZeroCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        (&self.a * Field::from(0u64)).assert_equal(&self.product, RULE)
    }
}
