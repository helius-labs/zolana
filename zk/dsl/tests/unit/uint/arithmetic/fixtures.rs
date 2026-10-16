//! Every fixture takes its operands as field inputs, range-checks them into
//! `Uint<BITS>` and asserts the operation's result equal to `claimed`, so
//! wires 1, 2 and 3 are x, y and claimed, x's digits follow from wire 4,
//! y's from wire 4 + BITS, and the operation's own witnesses from
//! wire 4 + 2 * BITS. `Sum` takes three operands and the claim on wire 4.

use ark_bn254::Fr;
use ark_ff::One;
use zolana_program::{
    circuit::{Assert, Circuit, CircuitVar, Field, Uint},
    conversion::ProofInput,
    CircuitError,
};

use crate::uint::rows::low_bits;

pub const RULE: &str = "the result is the claimed value";
pub const ADD_RULE: &str = "the sum fits in the width";
pub const MUL_RULE: &str = "the product fits in the width";
pub const SUB_RULE: &str = "the difference is not negative";
pub const FILE: &str = file!();

pub const X_WIRE: usize = 1;
pub const Y_WIRE: usize = 2;
pub const CLAIMED_WIRE: usize = 3;
pub const FIRST_BIT: usize = 4;

pub const fn gadget_wire(bits: usize) -> usize {
    FIRST_BIT + 2 * bits
}

fn operands<const BITS: usize>(
    x: &CircuitVar,
    y: &CircuitVar,
) -> Result<(Uint<BITS>, Uint<BITS>), CircuitError> {
    Ok((Uint::try_from(x)?, Uint::try_from(y)?))
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Add<const BITS: usize, const OUT: usize> {
    pub x: Field,
    pub y: Field,
    pub claimed: Field,
}

impl<const BITS: usize, const OUT: usize> Circuit for AddCircuit<BITS, OUT> {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let (x, y) = operands::<BITS>(&self.x, &self.y)?;
        CircuitVar::from(x.add::<OUT>(&y)).assert_equal(&self.claimed, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Mul<const BITS: usize, const OUT: usize> {
    pub x: Field,
    pub y: Field,
    pub claimed: Field,
}

impl<const BITS: usize, const OUT: usize> Circuit for MulCircuit<BITS, OUT> {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let (x, y) = operands::<BITS>(&self.x, &self.y)?;
        CircuitVar::from(x.mul::<OUT>(&y)).assert_equal(&self.claimed, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct Sum<const BITS: usize, const OUT: usize> {
    pub values: [Field; 3],
    pub claimed: Field,
}

impl<const BITS: usize, const OUT: usize> Circuit for SumCircuit<BITS, OUT> {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let [a, b, c] = &self.values;
        let values = [Uint::try_from(a)?, Uint::try_from(b)?, Uint::try_from(c)?];
        CircuitVar::from(Uint::<BITS>::sum::<OUT, 3>(&values)).assert_equal(&self.claimed, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct CheckedAdd<const BITS: usize> {
    pub x: Field,
    pub y: Field,
    pub claimed: Field,
}

impl<const BITS: usize> Circuit for CheckedAddCircuit<BITS> {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let (x, y) = operands::<BITS>(&self.x, &self.y)?;
        CircuitVar::from(x.checked_add(&y, ADD_RULE)?).assert_equal(&self.claimed, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct CheckedMul<const BITS: usize> {
    pub x: Field,
    pub y: Field,
    pub claimed: Field,
}

impl<const BITS: usize> Circuit for CheckedMulCircuit<BITS> {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let (x, y) = operands::<BITS>(&self.x, &self.y)?;
        CircuitVar::from(x.checked_mul(&y, MUL_RULE)?).assert_equal(&self.claimed, RULE)
    }
}

#[derive(Clone, Copy, Debug, ProofInput)]
pub struct CheckedSub<const BITS: usize> {
    pub x: Field,
    pub y: Field,
    pub claimed: Field,
}

impl<const BITS: usize> Circuit for CheckedSubCircuit<BITS> {
    type Output = ();

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        let (x, y) = operands::<BITS>(&self.x, &self.y)?;
        CircuitVar::from(x.checked_sub(&y, SUB_RULE)?).assert_equal(&self.claimed, RULE)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    Add,
    Mul,
    CheckedAdd,
    CheckedMul,
    CheckedSub,
}

/// The witness arkworks assigns for x, y and claimed, whether or not they
/// satisfy the rows: each range-checked value decomposed into its low digits.
pub fn witness(op: Op, bits: usize, x: Fr, y: Fr, claimed: Fr) -> Vec<Fr> {
    let gadget = match op {
        Op::Add => vec![],
        Op::Mul => vec![x * y],
        Op::CheckedAdd => low_bits(x + y, bits),
        Op::CheckedMul => [vec![x * y], low_bits(x * y, bits)].concat(),
        Op::CheckedSub => low_bits(x - y, bits),
    };
    [
        vec![Fr::one(), x, y, claimed],
        low_bits(x, bits),
        low_bits(y, bits),
        gadget,
    ]
    .concat()
}

pub fn result(op: Op, x: Fr, y: Fr) -> Fr {
    match op {
        Op::Add | Op::CheckedAdd => x + y,
        Op::Mul | Op::CheckedMul => x * y,
        Op::CheckedSub => x - y,
    }
}
