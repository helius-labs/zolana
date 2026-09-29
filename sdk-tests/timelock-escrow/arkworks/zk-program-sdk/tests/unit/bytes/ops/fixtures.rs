use zk_program_sdk::{
    circuit::{self, Assert, Bool, Constraints, Field, Select},
    conversion::ProofInput,
    Bytes, CircuitError,
};

use crate::harness::fixture::{rule_broken, Refusal};

pub const EQUAL_RULE: &str = "the left bytes equal the right bytes";
pub const EQUAL_IF_RULE: &str = "the left bytes equal the right bytes if the condition holds";
pub const NOT_EQUAL_RULE: &str = "the left bytes differ from the right bytes";
pub const IS_EQUAL_RULE: &str = "the claim is whether the bytes are equal";
pub const SELECT_RULE: &str = "the selected bytes are the chosen side";
pub const FILE: &str = file!();

pub const EQUAL_BROKEN: Refusal = rule_broken(EQUAL_RULE, FILE);
pub const EQUAL_IF_BROKEN: Refusal = rule_broken(EQUAL_IF_RULE, FILE);
pub const NOT_EQUAL_BROKEN: Refusal = rule_broken(NOT_EQUAL_RULE, FILE);
pub const IS_EQUAL_BROKEN: Refusal = rule_broken(IS_EQUAL_RULE, FILE);
pub const SELECT_BROKEN: Refusal = rule_broken(SELECT_RULE, FILE);

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct AssertEqual<const N: usize> {
    pub left: Bytes<N>,
    pub right: Bytes<N>,
}

impl<const N: usize> Constraints for AssertEqualCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left.assert_equal(&self.right, EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct AssertEqualIf<const N: usize> {
    pub left: Bytes<N>,
    pub right: Bytes<N>,
    pub condition: bool,
}

impl<const N: usize> Constraints for AssertEqualIfCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left
            .assert_equal_if(&self.right, &self.condition, EQUAL_IF_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct AssertNotEqual<const N: usize> {
    pub left: Bytes<N>,
    pub right: Bytes<N>,
}

impl<const N: usize> Constraints for AssertNotEqualCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left.assert_not_equal(&self.right, NOT_EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct IsEqual<const N: usize> {
    pub left: Bytes<N>,
    pub right: Bytes<N>,
    pub claimed: bool,
}

impl<const N: usize> Constraints for IsEqualCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        self.left
            .is_equal(&self.right)?
            .assert_equal(&self.claimed, IS_EQUAL_RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Selected<const N: usize> {
    pub condition: bool,
    pub if_true: Bytes<N>,
    pub if_false: Bytes<N>,
    pub selected: [Field; N],
}

impl<const N: usize> Constraints for SelectedCircuit<N> {
    fn constraints(&self) -> Result<(), CircuitError> {
        circuit::Bytes::select(&self.condition, &self.if_true, &self.if_false)
            .bytes()
            .assert_equal(&self.selected, SELECT_RULE)
    }
}

pub fn constant_select<const N: usize>(
    condition: bool,
    if_true: &[u8; N],
    if_false: &[u8; N],
) -> circuit::Bytes<N> {
    Bool::constant(condition).select(
        &circuit::Bytes::constant(if_true),
        &circuit::Bytes::constant(if_false),
    )
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct ConstantOps;
impl Constraints for ConstantOpsCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let left = circuit::Bytes::constant(&[3; 32]);
        let right = circuit::Bytes::constant(&[7; 32]);
        left.assert_equal(&left, EQUAL_RULE)?;
        left.assert_not_equal(&right, NOT_EQUAL_RULE)?;
        left.assert_equal_if(&right, &Bool::constant(false), EQUAL_IF_RULE)?;
        left.is_equal(&right)?.assert_false(IS_EQUAL_RULE)?;
        circuit::Bytes::select(&Bool::constant(true), &left, &right)
            .assert_equal(&left, SELECT_RULE)
    }
}
