use zk_program_sdk::{
    circuit::{Assert, CircuitType, CircuitVar, Constraints, Field},
    conversion::{Allocator, Placeholder, ProofInput},
    CircuitError,
};

use crate::harness::fixture::{rule_broken, Fixture, Refusal, Visit, Visited};

pub const RULE: &str = "the difference is left minus right";
pub const FILE: &str = file!();

pub const RULE_BROKEN: Refusal = rule_broken(RULE, FILE);

type VariableForm = fn(&CircuitVar, &CircuitVar) -> CircuitVar;
type ConstantForm = fn(&CircuitVar, Field) -> CircuitVar;

pub const VARIABLE_FORMS: [(&str, VariableForm); 6] = [
    ("a - b", |a, b| a.clone() - b.clone()),
    ("a - &b", |a, b| a.clone() - b),
    ("&a - b", |a, b| a - b.clone()),
    ("&a - &b", |a, b| a - b),
    ("a -= b", |a, b| {
        let mut difference = a.clone();
        difference -= b.clone();
        difference
    }),
    ("a -= &b", |a, b| {
        let mut difference = a.clone();
        difference -= b;
        difference
    }),
];

pub const CONSTANT_FORMS: [(&str, ConstantForm); 3] = [
    ("a - k", |a, k| a.clone() - k),
    ("&a - k", |a, k| a - k),
    ("a -= k", |a, k| {
        let mut difference = a.clone();
        difference -= k;
        difference
    }),
];

pub trait Operands {
    fn form(&self) -> CircuitVar;
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Variables<const FORM: usize> {
    pub left: Field,
    pub right: Field,
    pub difference: Field,
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
        self.form().assert_equal(&self.difference, RULE)
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
    pub difference: Field,
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
        self.form().assert_equal(&self.difference, RULE)
    }
}

pub fn variable_forms<V: Visit<CircuitVar>>(
    visitor: &V,
    (left, right, difference): (Field, Field, Field),
) -> Visited<V::Output> {
    variable_form_names()
        .into_iter()
        .zip([
            visitor.visit(&Variables::<0> {
                left,
                right,
                difference,
            }),
            visitor.visit(&Variables::<1> {
                left,
                right,
                difference,
            }),
            visitor.visit(&Variables::<2> {
                left,
                right,
                difference,
            }),
            visitor.visit(&Variables::<3> {
                left,
                right,
                difference,
            }),
            visitor.visit(&Variables::<4> {
                left,
                right,
                difference,
            }),
            visitor.visit(&Variables::<5> {
                left,
                right,
                difference,
            }),
        ])
        .collect()
}

pub fn constant_forms<V: Visit<CircuitVar>>(
    visitor: &V,
    (left, right, difference): (Field, Field, Field),
) -> Visited<V::Output> {
    let right = Constant(right);
    constant_form_names()
        .into_iter()
        .zip([
            visitor.visit(&WithConstant::<0> {
                left,
                right,
                difference,
            }),
            visitor.visit(&WithConstant::<1> {
                left,
                right,
                difference,
            }),
            visitor.visit(&WithConstant::<2> {
                left,
                right,
                difference,
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
pub struct Unasserted {
    pub left: Field,
    pub right: Field,
}

impl Constraints for UnassertedCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let constant = Field::from(7u64);
        let _differences: Vec<CircuitVar> = VARIABLE_FORMS
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
pub struct SelfMinusSelf {
    pub a: Field,
    pub difference: Field,
}

impl Constraints for SelfMinusSelfCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        (&self.a - &self.a).assert_equal(&self.difference, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct MinusFive {
    pub a: Field,
    pub difference: Field,
}

impl Constraints for MinusFiveCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        (&self.a - Field::from(5u64)).assert_equal(&self.difference, RULE)
    }
}
