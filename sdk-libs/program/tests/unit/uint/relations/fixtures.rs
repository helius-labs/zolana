use zolana_program::{
    circuit::{Assert, CircuitVar, Constraints, Field, Select, Uint},
    conversion::ProofInput,
    CircuitError,
};

pub const RULE: &str = "the uint relation holds";
pub const CLAIM: &str = "the uint result equals its claim";

/// OP: less-than, less-or-equal, min, max, cross-width equality, trait equality.
#[derive(Clone, Debug, ProofInput)]
pub struct Compare<const BITS: u32, const OP: u8> {
    pub x: Field,
    pub y: Field,
    pub claimed: Field,
}
impl<const BITS: u32, const OP: u8> Constraints for CompareCircuit<BITS, OP> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let x = Uint::<BITS>::try_from(&self.x)?;
        let y = Uint::<BITS>::try_from(&self.y)?;
        let result: CircuitVar = match OP {
            0 => x.is_less_than(&y)?.into(),
            1 => x.is_less_or_equal(&y)?.into(),
            2 => x.min(&y)?.into(),
            3 => x.max(&y)?.into(),
            4 => x.is_equal(&Uint::<253>::try_from(&self.y)?)?.into(),
            5 => Assert::is_equal(&x, &y)?.into(),
            _ => unreachable!("test operation"),
        };
        result.assert_equal(&self.claimed, CLAIM)
    }
}

/// OP: strict/inclusive order, cross-width equal/unequal, trait equal/unequal.
#[derive(Clone, Debug, ProofInput)]
pub struct Pair<const BITS: u32, const OP: u8> {
    pub x: Field,
    pub y: Field,
}
impl<const BITS: u32, const OP: u8> Constraints for PairCircuit<BITS, OP> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let x = Uint::<BITS>::try_from(&self.x)?;
        let y = Uint::<BITS>::try_from(&self.y)?;
        match OP {
            0 => x.assert_less_than(&y, RULE),
            1 => x.assert_less_or_equal(&y, RULE),
            2 => x.assert_equal(&Uint::<253>::try_from(&self.y)?, RULE),
            3 => x.assert_not_equal(&Uint::<253>::try_from(&self.y)?, RULE),
            4 => Assert::assert_equal(&x, &y, RULE),
            5 => Assert::assert_not_equal(&x, &y, RULE),
            _ => unreachable!("test operation"),
        }
    }
}

#[derive(Clone, Debug, ProofInput)]
pub struct Range<const BITS: u32> {
    pub x: Field,
    pub low: Field,
    pub high: Field,
}
impl<const BITS: u32> Constraints for RangeCircuit<BITS> {
    fn constraints(&self) -> Result<(), CircuitError> {
        Uint::<BITS>::try_from(&self.x)?.assert_in_range(
            &Uint::try_from(&self.low)?,
            &Uint::try_from(&self.high)?,
            RULE,
        )
    }
}

#[derive(Clone, Debug, ProofInput)]
pub struct Zero<const BITS: u32> {
    pub x: Field,
    pub claimed: Field,
}
impl<const BITS: u32> Constraints for ZeroCircuit<BITS> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let x = Uint::<BITS>::try_from(&self.x)?;
        CircuitVar::from(x.is_zero()?).assert_equal(&self.claimed, CLAIM)
    }
}

#[derive(Clone, Debug, ProofInput)]
pub struct AssertZero<const BITS: u32, const NONZERO: bool> {
    pub x: Field,
}
impl<const BITS: u32, const NONZERO: bool> Constraints for AssertZeroCircuit<BITS, NONZERO> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let x = Uint::<BITS>::try_from(&self.x)?;
        if NONZERO {
            x.assert_not_zero(RULE)
        } else {
            x.assert_zero(RULE)
        }
    }
}

#[derive(Clone, Debug, ProofInput)]
pub struct Conditional<const BITS: u32> {
    pub x: Field,
    pub y: Field,
    pub condition: bool,
}
impl<const BITS: u32> Constraints for ConditionalCircuit<BITS> {
    fn constraints(&self) -> Result<(), CircuitError> {
        Assert::assert_equal_if(
            &Uint::<BITS>::try_from(&self.x)?,
            &Uint::try_from(&self.y)?,
            &self.condition,
            RULE,
        )
    }
}

#[derive(Clone, Debug, ProofInput)]
pub struct Selection<const BITS: u32> {
    pub x: Field,
    pub y: Field,
    pub condition: bool,
    pub claimed: Field,
}
impl<const BITS: u32> Constraints for SelectionCircuit<BITS> {
    fn constraints(&self) -> Result<(), CircuitError> {
        let x = Uint::<BITS>::try_from(&self.x)?;
        let y = Uint::<BITS>::try_from(&self.y)?;
        CircuitVar::from(Uint::select(&self.condition, &x, &y)).assert_equal(&self.claimed, CLAIM)
    }
}

#[derive(Clone, Debug, ProofInput)]
pub struct Division<const BITS: u32, const QUOTIENT: u32, const DIVISOR: u32> {
    pub x: Field,
    pub divisor: Field,
    pub quotient: Field,
    pub remainder: Field,
}
impl<const BITS: u32, const QUOTIENT: u32, const DIVISOR: u32> Constraints
    for DivisionCircuit<BITS, QUOTIENT, DIVISOR>
{
    fn constraints(&self) -> Result<(), CircuitError> {
        let (q, r) = Uint::<BITS>::try_from(&self.x)?
            .div_rem::<QUOTIENT, DIVISOR>(&Uint::try_from(&self.divisor)?, RULE)?;
        CircuitVar::from(q).assert_equal(&self.quotient, CLAIM)?;
        CircuitVar::from(r).assert_equal(&self.remainder, CLAIM)
    }
}

pub fn compare<const BITS: u32, const OP: u8>(x: u128, y: u128) -> Compare<BITS, OP> {
    let claimed = match OP {
        0 => u128::from(x < y),
        1 => u128::from(x <= y),
        2 => x.min(y),
        3 => x.max(y),
        4 | 5 => u128::from(x == y),
        _ => unreachable!("test operation"),
    };
    Compare {
        x: x.into(),
        y: y.into(),
        claimed: claimed.into(),
    }
}

pub fn division<const BITS: u32, const QUOTIENT: u32, const DIVISOR: u32>(
    x: u128,
    divisor: u128,
) -> Division<BITS, QUOTIENT, DIVISOR> {
    Division {
        x: x.into(),
        divisor: divisor.into(),
        quotient: x.checked_div(divisor).unwrap_or_default().into(),
        remainder: x.checked_rem(divisor).unwrap_or_default().into(),
    }
}

pub fn pair_holds(op: u8, x: u64, y: u64) -> bool {
    match op {
        0 => x < y,
        1 => x <= y,
        2 | 4 => x == y,
        3 | 5 => x != y,
        _ => unreachable!("test operation"),
    }
}

/// A fully coordinated candidate: changing x/y also changes their digits and the
/// comparison's digits or inverse hint. Thus an invalid relation must fail its own row.
pub fn pair_witness(op: u8, x: u64, y: u64) -> Vec<ark_bn254::Fr> {
    use crate::uint::rows::low_bits;
    use ark_ff::Field as _;
    let (x, y, one) = (
        ark_bn254::Fr::from(x),
        ark_bn254::Fr::from(y),
        ark_bn254::Fr::from(1u64),
    );
    let mut witness = [vec![one, x, y], low_bits(x, 4), low_bits(y, 4)].concat();
    if op == 2 || op == 3 {
        witness.extend(low_bits(y, 253));
    }
    if op < 2 {
        witness.extend(low_bits(y - x - ark_bn254::Fr::from(u64::from(op == 0)), 4));
    }
    if op == 3 || op == 5 {
        witness.push((x - y).inverse().unwrap_or_default());
    }
    witness
}

#[derive(Clone, Debug, ProofInput)]
pub struct CrossWidth {
    pub x: Field,
    pub y: Field,
    pub claimed: Field,
}
impl Constraints for CrossWidthCircuit {
    fn constraints(&self) -> Result<(), CircuitError> {
        let x = Uint::<4>::try_from(&self.x)?;
        let y = Uint::<64>::try_from(&self.y)?;
        CircuitVar::from(x.is_equal(&y)?).assert_equal(&self.claimed, CLAIM)
    }
}
