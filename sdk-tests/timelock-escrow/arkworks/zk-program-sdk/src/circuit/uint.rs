use ark_ff::{AdditiveGroup, BigInteger, One, PrimeField};
use ark_relations::r1cs::SynthesisError;

use super::{
    constant, field,
    labels::{self, Scope},
    var::{bits_le, range_check, system_of},
    zero, Assert, Bool, CircuitVar, Field, Select,
};
use crate::RelationError;

const MAX_BITS: u32 = 253;
const MAX_ORDERED_BITS: u32 = 252;
const MAX_DIVIDED_BITS: u32 = 128;

#[must_use]
#[derive(Clone, Debug)]
pub struct Uint<const BITS: u32> {
    var: CircuitVar,
}

mod sealed {
    pub trait Sealed {}
}

pub trait Unsigned: sealed::Sealed {
    const BITS: u32;

    fn var(&self) -> CircuitVar;
}

impl<const BITS: u32> sealed::Sealed for Uint<BITS> {}

impl<const BITS: u32> Unsigned for Uint<BITS> {
    const BITS: u32 = BITS;

    fn var(&self) -> CircuitVar {
        self.var.clone()
    }
}

impl<const BITS: u32> Uint<BITS> {
    const VALID: () = assert!(
        BITS >= 1 && BITS <= MAX_BITS,
        "a Uint holds between 1 and 253 bits"
    );

    pub fn zero() -> Self {
        let () = Self::VALID;
        Self { var: zero() }
    }

    pub fn constant(value: u64) -> Result<Self, RelationError> {
        let () = Self::VALID;
        if value.checked_shr(BITS).is_some_and(|high| high != 0) {
            return Err(RelationError::OutOfRange(BITS as usize));
        }
        Ok(Self {
            var: constant(value),
        })
    }

    #[track_caller]
    pub fn from_var(var: &CircuitVar, rule: &'static str) -> Result<Self, RelationError> {
        let () = Self::VALID;
        fits(var, BITS, rule)?;
        Ok(Self { var: var.clone() })
    }

    pub(crate) fn trusted(var: CircuitVar) -> Self {
        let () = Self::VALID;
        Self { var }
    }

    pub fn var(&self) -> CircuitVar {
        self.var.clone()
    }

    pub fn add<const OUT: u32>(&self, other: &Self) -> Uint<OUT> {
        const {
            assert!(
                OUT > BITS && OUT <= MAX_BITS,
                "a sum of two Uint<BITS> needs more than BITS and at most 253 bits"
            )
        };
        Uint {
            var: self.var.plus(&other.var),
        }
    }

    pub fn mul<const OUT: u32>(&self, other: &Self) -> Uint<OUT> {
        const {
            assert!(
                OUT >= 2 * BITS && OUT <= MAX_BITS,
                "a product of two Uint<BITS> needs at least 2 * BITS and at most 253 bits"
            )
        };
        Uint {
            var: self.var.times(&other.var),
        }
    }

    pub fn sum<const OUT: u32, const N: usize>(values: &[Self; N]) -> Uint<OUT> {
        const {
            assert!(
                OUT >= BITS + ceil_log2(N) && OUT <= MAX_BITS,
                "a sum of N Uint<BITS> needs at least BITS + ceil(log2(N)) and at most 253 bits"
            )
        };
        Uint {
            var: field::sum(values.iter().map(|value| &value.var)),
        }
    }

    pub fn widen<const OUT: u32>(&self) -> Uint<OUT> {
        const {
            assert!(
                OUT >= BITS && OUT <= MAX_BITS,
                "widen goes to at least as many bits and at most 253"
            )
        };
        Uint {
            var: self.var.clone(),
        }
    }

    #[track_caller]
    pub fn narrow<const OUT: u32>(&self, rule: &'static str) -> Result<Uint<OUT>, RelationError> {
        const { assert!(OUT >= 1 && OUT < BITS, "narrow goes to fewer bits") };
        fits(&self.var, OUT, rule)?;
        Ok(Uint {
            var: self.var.clone(),
        })
    }

    #[track_caller]
    pub fn checked_sub(&self, other: &Self, rule: &'static str) -> Result<Self, RelationError> {
        let () = Self::ORDERED;
        let difference = self.var.minus(&other.var);
        fits(&difference, BITS, rule)?;
        Ok(Self { var: difference })
    }

    #[track_caller]
    pub fn assert_less_or_equal(
        &self,
        other: &Self,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        let () = Self::ORDERED;
        fits(&other.var.minus(&self.var), BITS, rule)
    }

    #[track_caller]
    pub fn assert_less_than(&self, other: &Self, rule: &'static str) -> Result<(), RelationError> {
        let () = Self::ORDERED;
        fits(
            &other.var.minus(&self.var).offset(-Field::one()),
            BITS,
            rule,
        )
    }

    #[track_caller]
    pub fn is_less_or_equal(&self, other: &Self) -> Result<Bool, RelationError> {
        let () = Self::ORDERED;
        self.ordered_below(other, Field::ZERO)
    }

    #[track_caller]
    pub fn is_less_than(&self, other: &Self) -> Result<Bool, RelationError> {
        let () = Self::ORDERED;
        self.ordered_below(other, Field::one())
    }

    #[track_caller]
    pub fn assert_in_range(
        &self,
        low: &Self,
        high: &Self,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        low.assert_less_or_equal(self, rule)?;
        self.assert_less_or_equal(high, rule)
    }

    #[track_caller]
    pub fn min(&self, other: &Self) -> Result<Self, RelationError> {
        Ok(self.is_less_than(other)?.select(self, other))
    }

    #[track_caller]
    pub fn max(&self, other: &Self) -> Result<Self, RelationError> {
        Ok(self.is_less_than(other)?.select(other, self))
    }

    #[track_caller]
    pub fn assert_equal<const OTHER: u32>(
        &self,
        other: &Uint<OTHER>,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        self.var.assert_equal(&other.var, rule)
    }

    #[track_caller]
    pub fn assert_not_equal<const OTHER: u32>(
        &self,
        other: &Uint<OTHER>,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        self.var.assert_not_equal(&other.var, rule)
    }

    #[track_caller]
    pub fn is_equal<const OTHER: u32>(&self, other: &Uint<OTHER>) -> Result<Bool, RelationError> {
        Bool::of_equality(&self.var, &other.var)
    }

    #[track_caller]
    pub fn is_zero(&self) -> Result<Bool, RelationError> {
        Bool::of_equality(&self.var, &zero())
    }

    #[track_caller]
    pub fn assert_zero(&self, rule: &'static str) -> Result<(), RelationError> {
        self.var.assert_equal(&zero(), rule)
    }

    #[track_caller]
    pub fn assert_not_zero(&self, rule: &'static str) -> Result<(), RelationError> {
        self.var.assert_not_equal(&zero(), rule)
    }

    #[track_caller]
    pub fn div_rem<const QUOTIENT: u32, const DIVISOR: u32>(
        &self,
        divisor: &Uint<DIVISOR>,
        rule: &'static str,
    ) -> Result<(Uint<QUOTIENT>, Uint<DIVISOR>), RelationError> {
        const {
            assert!(
                BITS <= MAX_DIVIDED_BITS && DIVISOR <= MAX_DIVIDED_BITS,
                "div_rem divides values of at most 128 bits"
            )
        };
        const {
            assert!(
                QUOTIENT >= 1 && QUOTIENT + DIVISOR <= MAX_ORDERED_BITS,
                "the quotient and the divisor of div_rem hold at most 252 bits together"
            )
        };
        let cs = system_of([&self.var, &divisor.var]);
        if cs.is_none() {
            let (quotient, remainder) = divide(&self.var, &divisor.var)
                .filter(|(quotient, _)| quotient.checked_shr(QUOTIENT).is_none_or(|high| high == 0))
                .ok_or(RelationError::Violated(rule))?;
            return Ok((
                Uint::trusted(constant(Field::from(quotient))),
                Uint::trusted(constant(Field::from(remainder))),
            ));
        }
        let _scope = Scope::open(&cs, "a division");
        let division = divide(&self.var, &divisor.var).unwrap_or((0, 0));
        let quotient = CircuitVar::witness(&cs, || Ok(Field::from(division.0)))?;
        let remainder = CircuitVar::witness(&cs, || Ok(Field::from(division.1)))?;
        let quotient = Uint::<QUOTIENT>::from_var(&quotient, rule)?;
        let remainder = Uint::<DIVISOR>::from_var(&remainder, rule)?;
        remainder.assert_less_than(divisor, rule)?;
        labels::check(&cs, rule, || {
            quotient
                .var
                .enforce_product(&divisor.var, &self.var.minus(&remainder.var))
        })?;
        Ok((quotient, remainder))
    }

    const ORDERED: () = assert!(
        BITS >= 1 && BITS <= MAX_ORDERED_BITS,
        "subtraction and comparison work on at most 252 bits"
    );

    #[track_caller]
    fn ordered_below(&self, other: &Self, gap: Field) -> Result<Bool, RelationError> {
        let offset = power_of_two(BITS) - gap;
        let shifted = other.var.minus(&self.var).offset(offset);
        if let Some(value) = shifted.constant_value() {
            return Ok(Bool::constant(value.into_bigint().get_bit(BITS as usize)));
        }
        let _scope = Scope::open(&shifted.cs(), "a comparison");
        let bits = bits_le(&shifted, BITS as usize + 1)?;
        let top = bits.last().ok_or(SynthesisError::Unsatisfiable)?;
        Ok(Bool::from_checked(top.clone()))
    }
}

impl<const BITS: u32> Select for Uint<BITS> {
    fn select(condition: &Bool, if_true: &Self, if_false: &Self) -> Self {
        Uint::trusted(CircuitVar::select(condition, &if_true.var, &if_false.var))
    }
}

impl<const BITS: u32> Assert for Uint<BITS> {
    #[track_caller]
    fn is_equal(&self, other: &Self) -> Result<Bool, RelationError> {
        Bool::of_equality(&self.var, &other.var)
    }

    #[track_caller]
    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError> {
        self.var.assert_equal(&other.var, rule)
    }

    #[track_caller]
    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        self.var.assert_equal_if(&other.var, condition, rule)
    }

    #[track_caller]
    fn assert_not_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError> {
        self.var.assert_not_equal(&other.var, rule)
    }
}

#[track_caller]
fn fits(var: &CircuitVar, bits: u32, rule: &'static str) -> Result<(), RelationError> {
    range_check(var, bits as usize, rule).map_err(|error| match error {
        RelationError::OutOfRange(_) => RelationError::Violated(rule),
        error => error,
    })
}

fn divide(dividend: &CircuitVar, divisor: &CircuitVar) -> Option<(u128, u128)> {
    let dividend = small(&dividend.assigned().ok()?)?;
    let divisor = small(&divisor.assigned().ok()?)?;
    Some((
        dividend.checked_div(divisor)?,
        dividend.checked_rem(divisor)?,
    ))
}

fn small(value: &Field) -> Option<u128> {
    let [low, high, rest @ ..] = value.into_bigint().0;
    rest.iter()
        .all(|limb| *limb == 0)
        .then_some(u128::from(low) | (u128::from(high) << 64))
}

fn power_of_two(bits: u32) -> Field {
    (0..bits).fold(Field::one(), |power, _| power.double())
}

const fn ceil_log2(n: usize) -> u32 {
    if n <= 1 {
        0
    } else {
        (n - 1).ilog2() + 1
    }
}
