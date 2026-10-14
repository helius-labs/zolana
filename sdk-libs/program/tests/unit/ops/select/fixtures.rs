use zolana_program::{
    circuit::{constant, Assert, Bool, CircuitVar, Constraints, Field, Select},
    conversion::ProofInput,
    CircuitError,
};

use crate::harness::fixture::{rule_broken, Fixture, Refusal, Visit, Visited};

pub const RULE: &str = "the selected value is the chosen branch";
pub const FILE: &str = file!();

pub const RULE_BROKEN: Refusal = rule_broken(RULE, FILE);

pub const TRUE_CONSTANT: u64 = 7;
pub const FALSE_CONSTANT: u64 = 3;

type Form = fn(&Bool, &CircuitVar, &CircuitVar) -> CircuitVar;

pub const FORMS: [(&str, Form); 2] = [
    ("CircuitVar::select(c, t, f)", |c, t, f| {
        CircuitVar::select(c, t, f)
    }),
    ("c.select(t, f)", |c, t, f| c.select(t, f)),
];

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Selected<const FORM: usize> {
    pub condition: bool,
    pub if_true: Field,
    pub if_false: Field,
    pub selected: Field,
}

impl<const FORM: usize> SelectedCircuit<FORM> {
    fn form(&self) -> CircuitVar {
        let (_, form) = FORMS[FORM];
        form(&self.condition, &self.if_true, &self.if_false)
    }
}

impl<const FORM: usize> Fixture<CircuitVar> for Selected<FORM> {
    fn computed(circuit: &SelectedCircuit<FORM>) -> CircuitVar {
        circuit.form()
    }
}

impl<const FORM: usize> Constraints for SelectedCircuit<FORM> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.form().assert_equal(&self.selected, RULE)
    }
}

pub fn form_names() -> Vec<&'static str> {
    FORMS.iter().map(|(name, _)| *name).collect()
}

pub fn every_form<V: Visit<CircuitVar>>(
    visitor: &V,
    (condition, if_true, if_false, selected): (bool, Field, Field, Field),
) -> Visited<V::Output> {
    form_names()
        .into_iter()
        .zip([
            visitor.visit(&Selected::<0> {
                condition,
                if_true,
                if_false,
                selected,
            }),
            visitor.visit(&Selected::<1> {
                condition,
                if_true,
                if_false,
                selected,
            }),
        ])
        .collect()
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct SelectConstantCondition<const CONDITION: bool> {
    pub if_true: Field,
    pub if_false: Field,
    pub selected: Field,
}

impl<const CONDITION: bool> Constraints for SelectConstantConditionCircuit<CONDITION> {
    fn constraints(&self) -> Result<(), CircuitError> {
        CircuitVar::select(&Bool::constant(CONDITION), &self.if_true, &self.if_false)
            .assert_equal(&self.selected, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct SelectConstantBranches {
    pub condition: bool,
    pub selected: Field,
}

impl Constraints for SelectConstantBranchesCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        CircuitVar::select(
            &self.condition,
            &constant(TRUE_CONSTANT),
            &constant(FALSE_CONSTANT),
        )
        .assert_equal(&self.selected, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Unasserted {
    pub condition: bool,
    pub if_true: Field,
    pub if_false: Field,
}

impl Constraints for UnassertedCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let _selected = CircuitVar::select(&self.condition, &self.if_true, &self.if_false);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ArraySelected<const N: usize> {
    pub condition: bool,
    pub if_true: [Field; N],
    pub if_false: [Field; N],
    pub selected: [Field; N],
}

impl<const N: usize> Fixture<[CircuitVar; N]> for ArraySelected<N> {
    fn computed(circuit: &ArraySelectedCircuit<N>) -> [CircuitVar; N] {
        Select::select(&circuit.condition, &circuit.if_true, &circuit.if_false)
    }
}

impl<const N: usize> Constraints for ArraySelectedCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        <[CircuitVar; N]>::select(&self.condition, &self.if_true, &self.if_false)
            .assert_equal(&self.selected, RULE)
    }
}
