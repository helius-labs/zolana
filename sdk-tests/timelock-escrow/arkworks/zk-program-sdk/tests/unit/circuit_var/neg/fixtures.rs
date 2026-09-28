use zk_program_sdk::{
    circuit::{value, Assert, CircuitVar, Constraints, Field},
    conversion::ProofInput,
    CircuitError,
};

use crate::harness::fixture::{rule_broken, Fixture, Refusal, Visit, Visited};

pub const RULE: &str = "the negation is minus the value";
pub const FILE: &str = file!();

pub const RULE_BROKEN: Refusal = rule_broken(RULE, FILE);

type Form = fn(&CircuitVar) -> CircuitVar;

pub const FORMS: [(&str, Form); 2] = [("-a", |a| -a.clone()), ("-&a", |a| -a)];

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Negated<const FORM: usize> {
    pub value: Field,
    pub negation: Field,
}

impl<const FORM: usize> NegatedCircuit<FORM> {
    fn form(&self) -> CircuitVar {
        let (_, form) = FORMS[FORM];
        form(&self.value)
    }
}

impl<const FORM: usize> Fixture<CircuitVar> for Negated<FORM> {
    fn computed(circuit: &NegatedCircuit<FORM>) -> CircuitVar {
        circuit.form()
    }
}

impl<const FORM: usize> Constraints for NegatedCircuit<FORM> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.form().assert_equal(&self.negation, RULE)
    }
}

pub fn every_form<V: Visit<CircuitVar>>(
    visitor: &V,
    (value, negation): (Field, Field),
) -> Visited<V::Output> {
    form_names()
        .into_iter()
        .zip([
            visitor.visit(&Negated::<0> { value, negation }),
            visitor.visit(&Negated::<1> { value, negation }),
        ])
        .collect()
}

pub fn form_names() -> Vec<&'static str> {
    FORMS.iter().map(|(name, _)| *name).collect()
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Unasserted {
    pub value: Field,
}

impl Constraints for UnassertedCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let _negations: Vec<CircuitVar> = FORMS.iter().map(|(_, form)| form(&self.value)).collect();
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct DoubleNegation {
    pub value: Field,
    pub negation: Field,
}

impl Constraints for DoubleNegationCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        (-(-&self.value)).assert_equal(&self.negation, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct PlusNegation {
    pub value: Field,
    pub negation: Field,
}

impl Constraints for PlusNegationCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        (&self.value + -&self.value).assert_equal(&self.negation, RULE)
    }
}

pub fn read(var: &CircuitVar) -> (Result<Field, CircuitError>, u32) {
    (value(var), line!())
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ReadsValue {
    pub value: Field,
}

impl Constraints for ReadsValueCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        read(&self.value).0.map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct EqualsSeven {
    pub value: Field,
}

impl Constraints for EqualsSevenCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        zk_program_sdk::circuit::constant(7u64).assert_equal(&self.value, RULE)
    }
}
