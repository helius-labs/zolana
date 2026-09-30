use zolana_program::{
    circuit::{assert_in, constant, is_in, value, Assert, CircuitVar, Constraints, Field},
    conversion::ProofInput,
    CircuitError,
};

use crate::harness::fixture::{outcome, rule_broken, Fixture, Refusal};

pub const FLAG_RULE: &str = "the membership flag is the native one";
pub const MEMBER_RULE: &str = "the value is a member of the set";
pub const FILE: &str = file!();

pub const FLAG_BROKEN: Refusal = rule_broken(FLAG_RULE, FILE);
pub const MEMBER_BROKEN: Refusal = rule_broken(MEMBER_RULE, FILE);

pub type Flagged = Result<Field, Refusal>;

/// `is_in(value, set)` asserted equal to the claimed flag.
#[derive(Clone, Copy, Debug, ProofInput)]
pub struct IsIn<const N: usize> {
    pub value: Field,
    pub set: [Field; N],
    pub member: Field,
}

impl<const N: usize> Fixture<Flagged> for IsIn<N> {
    fn computed(circuit: &IsInCircuit<N>) -> Flagged {
        outcome(is_in(&circuit.value, &circuit.set).and_then(|flag| value(&CircuitVar::from(flag))))
    }
}

impl<const N: usize> Constraints for IsInCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        CircuitVar::from(is_in(&self.value, &self.set)?).assert_equal(&self.member, FLAG_RULE)
    }
}

/// `assert_in(value, set)`.
#[derive(Clone, Copy, Debug, ProofInput)]
pub struct AssertIn<const N: usize> {
    pub value: Field,
    pub set: [Field; N],
}

impl<const N: usize> Constraints for AssertInCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        assert_in(&self.value, &self.set, MEMBER_RULE)
    }
}

/// A value asserted to be in the constant set {3, 5}.
#[derive(Clone, Copy, Debug, ProofInput)]
pub struct InConstants {
    pub value: Field,
}

impl Constraints for InConstantsCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        assert_in(&self.value, &[constant(3u64), constant(5u64)], MEMBER_RULE)
    }
}

pub fn is_in_fixture<const N: usize>(value: Field, set: [Field; N], member: bool) -> IsIn<N> {
    IsIn {
        value,
        set,
        member: Field::from(member),
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ConstantMembership {
    pub member: Field,
}
impl Constraints for ConstantMembershipCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        CircuitVar::from(is_in(&constant(5u64), &[constant(3u64), constant(5u64)])?)
            .assert_equal(&self.member, FLAG_RULE)
    }
}
