use zolana_program::{
    circuit::{constant, Assert, Bool, CircuitType, CircuitVar, Constraints, Field},
    conversion::{Allocator, Placeholder, ProofInput},
    CircuitError, Owner,
};

use crate::harness::fixture::{rule_broken, Fixture, Refusal};

pub const RULE: &str = "the sides are equal";
pub const NOT_EQUAL_RULE: &str = "the sides differ";
pub const CLAIM_RULE: &str = "the claim is whether the sides are equal";
pub const BOOL_RULE: &str = "a bool proof input is neither 0 nor 1";
pub const TAG_RULE: &str = "the owner tag is neither S nor P";
pub const TAG_FILE: &str = "sdk-libs/program/src/conversion/owner.rs";
pub const FILE: &str = file!();

pub const RULE_BROKEN: Refusal = rule_broken(RULE, FILE);
pub const NOT_EQUAL_BROKEN: Refusal = rule_broken(NOT_EQUAL_RULE, FILE);

pub const LEFT_CONSTANT: u64 = 3;
pub const RIGHT_CONSTANT: u64 = 5;

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct AssertEqual {
    pub left: Field,
    pub right: Field,
}

impl Constraints for AssertEqualCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left.assert_equal(&self.right, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct IsEqual {
    pub left: Field,
    pub right: Field,
    pub claimed: Field,
}

impl Fixture<Result<Bool, CircuitError>> for IsEqual {
    fn computed(circuit: &IsEqualCircuit) -> Result<Bool, CircuitError> {
        circuit.left.is_equal(&circuit.right)
    }
}

impl Constraints for IsEqualCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        CircuitVar::from(self.left.is_equal(&self.right)?).assert_equal(&self.claimed, CLAIM_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct AssertEqualIf {
    pub left: Field,
    pub right: Field,
    pub condition: bool,
}

impl Constraints for AssertEqualIfCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left
            .assert_equal_if(&self.right, &self.condition, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct AssertEqualIfConstant<const CONDITION: bool> {
    pub left: Field,
    pub right: Field,
}

impl<const CONDITION: bool> Constraints for AssertEqualIfConstantCircuit<CONDITION> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left
            .assert_equal_if(&self.right, &Bool::constant(CONDITION), RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct AssertEqualIfItself {
    pub left: Field,
    pub condition: bool,
}

impl Constraints for AssertEqualIfItselfCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left.assert_equal_if(&self.left, &self.condition, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ConstantsIf {
    pub condition: bool,
}

impl Constraints for ConstantsIfCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        constant(LEFT_CONSTANT).assert_equal_if(&constant(RIGHT_CONSTANT), &self.condition, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct EqualConstantsIf {
    pub condition: bool,
}

impl Constraints for EqualConstantsIfCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        constant(LEFT_CONSTANT).assert_equal_if(&constant(LEFT_CONSTANT), &self.condition, RULE)
    }
}

#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Constant(pub bool);

#[derive(Clone, Debug)]
pub struct ConstantCircuit(pub bool);

impl CircuitType for ConstantCircuit {}

impl ProofInput for Constant {
    type Circuit = ConstantCircuit;

    fn instantiate(&self, _allocator: &Allocator) -> Result<ConstantCircuit, CircuitError> {
        Ok(ConstantCircuit(self.0))
    }
}

impl Placeholder for Constant {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self(false))
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ConditionInCircuit {
    pub left: Field,
    pub right: Field,
    pub condition: Constant,
}

impl Constraints for ConditionInCircuitCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left
            .assert_equal_if(&self.right, &Bool::constant(self.condition.0), RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct AssertNotEqual {
    pub left: Field,
    pub right: Field,
}

impl Constraints for AssertNotEqualCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left.assert_not_equal(&self.right, NOT_EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Unasserted {
    pub left: Field,
    pub right: Field,
}

impl Constraints for UnassertedCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left.is_equal(&self.right).map(|_| ())
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ArrayAssertEqual<const N: usize> {
    pub left: [Field; N],
    pub right: [Field; N],
}

impl<const N: usize> Constraints for ArrayAssertEqualCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left.assert_equal(&self.right, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ArrayIsEqual<const N: usize> {
    pub left: [Field; N],
    pub right: [Field; N],
    pub claimed: Field,
}

impl<const N: usize> Fixture<Result<Bool, CircuitError>> for ArrayIsEqual<N> {
    fn computed(circuit: &ArrayIsEqualCircuit<N>) -> Result<Bool, CircuitError> {
        circuit.left.is_equal(&circuit.right)
    }
}

impl<const N: usize> Constraints for ArrayIsEqualCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        CircuitVar::from(self.left.is_equal(&self.right)?).assert_equal(&self.claimed, CLAIM_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ArrayAssertEqualIf<const N: usize> {
    pub left: [Field; N],
    pub right: [Field; N],
    pub condition: bool,
}

impl<const N: usize> Constraints for ArrayAssertEqualIfCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left
            .assert_equal_if(&self.right, &self.condition, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ArrayAssertNotEqual<const N: usize> {
    pub left: [Field; N],
    pub right: [Field; N],
}

impl<const N: usize> Constraints for ArrayAssertNotEqualCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left.assert_not_equal(&self.right, NOT_EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct OwnerTag {
    pub owner: Owner,
}

impl Constraints for OwnerTagCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        Ok(())
    }
}

pub fn owner_tag(tag: u8) -> OwnerTag {
    OwnerTag {
        owner: Owner {
            tag,
            key: [7u8; 32],
            nullifier_pk: [9u8; 32],
        },
    }
}
