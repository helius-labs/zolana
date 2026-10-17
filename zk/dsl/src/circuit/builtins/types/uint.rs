use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, One, PrimeField};
use ark_relations::gr1cs::SynthesisError;

use crate::{
    circuit::{
        builtins::field::{
            bits::{bits_le, range_check},
            primitive,
            var::{small, system_of},
        },
        constant,
        labels::{self, Scope},
        zero, Assert, Bool, CircuitVar, Select,
    },
    CircuitError, CircuitErrorKind,
};

const MAX_BITS: usize = 253;
const MAX_ORDERED_BITS: usize = 252;
const MAX_DIVIDED_BITS: usize = 128;

#[must_use]
#[derive(Clone, Debug)]
pub struct Uint<const BITS: usize> {
    var: CircuitVar,
}

pub type U8 = Uint<8>;
pub type U16 = Uint<16>;
pub type U32 = Uint<32>;
pub type U64 = Uint<64>;
pub type U128 = Uint<128>;

impl<const BITS: usize> Uint<BITS> {
    const VALID: () = assert!(
        BITS >= 1 && BITS <= MAX_BITS,
        "a Uint holds between 1 and 253 bits"
    );

    pub fn zero() -> Self {
        let () = Self::VALID;
        Self { var: zero() }
    }

    pub fn constant(value: impl TryInto<u128>) -> Result<Self, CircuitError> {
        let () = Self::VALID;
        let value = value
            .try_into()
            .map_err(|_| CircuitErrorKind::ValueTooLarge { bits: BITS })?;
        if value.checked_shr(BITS as u32).is_some_and(|high| high != 0) {
            return Err(CircuitErrorKind::ValueTooLarge { bits: BITS }.into());
        }
        Ok(Self {
            var: constant(value),
        })
    }

    #[doc(hidden)]
    #[track_caller]
    pub fn from_var(var: &CircuitVar, rule: &'static str) -> Result<Self, CircuitError> {
        let () = Self::VALID;
        fits(var, BITS, rule)?;
        Ok(Self { var: var.clone() })
    }

    #[doc(hidden)]
    pub fn trusted(var: CircuitVar) -> Self {
        let () = Self::VALID;
        Self { var }
    }

    #[doc(hidden)]
    pub fn var(&self) -> CircuitVar {
        self.var.clone()
    }

    pub fn add<const OUT: usize>(&self, other: &Self) -> Uint<OUT> {
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

    pub fn mul<const OUT: usize>(&self, other: &Self) -> Uint<OUT> {
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

    pub fn sum<const OUT: usize, const N: usize>(values: &[Self; N]) -> Uint<OUT> {
        const {
            assert!(
                OUT >= BITS + ceil_log2(N) && OUT <= MAX_BITS,
                "a sum of N Uint<BITS> needs at least BITS + ceil(log2(N)) and at most 253 bits"
            )
        };
        Uint {
            var: primitive::sum(values.iter().map(|value| &value.var)),
        }
    }

    #[track_caller]
    pub fn checked_add(&self, other: &Self, rule: &'static str) -> Result<Self, CircuitError> {
        const {
            assert!(
                BITS < MAX_BITS,
                "checked_add adds values of at most 252 bits"
            )
        };
        let sum = self.var.plus(&other.var);
        fits(&sum, BITS, rule)?;
        Ok(Self { var: sum })
    }

    #[track_caller]
    pub fn checked_mul(&self, other: &Self, rule: &'static str) -> Result<Self, CircuitError> {
        const {
            assert!(
                2 * BITS <= MAX_BITS,
                "checked_mul multiplies values of at most 126 bits"
            )
        };
        let product = self.var.times(&other.var);
        fits(&product, BITS, rule)?;
        Ok(Self { var: product })
    }

    #[track_caller]
    pub fn checked_sub(&self, other: &Self, rule: &'static str) -> Result<Self, CircuitError> {
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
    ) -> Result<(), CircuitError> {
        let () = Self::ORDERED;
        fits(&other.var.minus(&self.var), BITS, rule)
    }

    #[track_caller]
    pub fn assert_less_than(&self, other: &Self, rule: &'static str) -> Result<(), CircuitError> {
        let () = Self::ORDERED;
        fits(&other.var.minus(&self.var).offset(-Fr::one()), BITS, rule)
    }

    #[track_caller]
    pub fn is_less_or_equal(&self, other: &Self) -> Result<Bool, CircuitError> {
        let () = Self::ORDERED;
        self.ordered_below(other, Fr::ZERO)
    }

    #[track_caller]
    pub fn is_less_than(&self, other: &Self) -> Result<Bool, CircuitError> {
        let () = Self::ORDERED;
        self.ordered_below(other, Fr::one())
    }

    #[track_caller]
    pub fn assert_in_range(
        &self,
        low: &Self,
        high: &Self,
        rule: &'static str,
    ) -> Result<(), CircuitError> {
        low.assert_less_or_equal(self, rule)?;
        self.assert_less_or_equal(high, rule)
    }

    #[track_caller]
    pub fn min(&self, other: &Self) -> Result<Self, CircuitError> {
        Ok(self.is_less_than(other)?.select(self, other))
    }

    #[track_caller]
    pub fn max(&self, other: &Self) -> Result<Self, CircuitError> {
        Ok(self.is_less_than(other)?.select(other, self))
    }

    #[track_caller]
    pub fn is_zero(&self) -> Result<Bool, CircuitError> {
        Bool::of_equality(&self.var, &zero())
    }

    #[track_caller]
    pub fn assert_zero(&self, rule: &'static str) -> Result<(), CircuitError> {
        self.var.assert_equal(&zero(), rule)
    }

    #[track_caller]
    pub fn assert_not_zero(&self, rule: &'static str) -> Result<(), CircuitError> {
        self.var.assert_not_equal(&zero(), rule)
    }

    #[track_caller]
    pub fn div_rem<const QUOTIENT: usize, const DIVISOR: usize>(
        &self,
        divisor: &Uint<DIVISOR>,
        rule: &'static str,
    ) -> Result<(Uint<QUOTIENT>, Uint<DIVISOR>), CircuitError> {
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
                .filter(|(quotient, _)| {
                    quotient
                        .checked_shr(QUOTIENT as u32)
                        .is_none_or(|high| high == 0)
                })
                .ok_or(CircuitErrorKind::RuleBroken(rule))?;
            return Ok((
                Uint::trusted(constant(quotient)),
                Uint::trusted(constant(remainder)),
            ));
        }
        let _scope = Scope::open(&cs, "a division");
        let division = divide(&self.var, &divisor.var).unwrap_or((0, 0));
        let quotient = CircuitVar::witness(&cs, || Ok(Fr::from(division.0)))?;
        let remainder = CircuitVar::witness(&cs, || Ok(Fr::from(division.1)))?;
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
    fn ordered_below(&self, other: &Self, gap: Fr) -> Result<Bool, CircuitError> {
        let offset = power_of_two(BITS) - gap;
        let shifted = other.var.minus(&self.var).offset(offset);
        if let Some(value) = shifted.constant_value() {
            return Ok(Bool::constant(value.into_bigint().get_bit(BITS)));
        }
        let _scope = Scope::open(&shifted.cs(), "a comparison");
        let bits = bits_le(&shifted, BITS + 1)?;
        let top = bits.last().ok_or(SynthesisError::Unsatisfiable)?;
        Ok(Bool::from_checked(top.clone()))
    }
}

impl<const BITS: usize> From<Bool> for Uint<BITS> {
    fn from(bit: Bool) -> Self {
        Uint::trusted(bit.into())
    }
}

impl<const BITS: usize> From<Uint<BITS>> for CircuitVar {
    fn from(value: Uint<BITS>) -> Self {
        value.var
    }
}

impl<const BITS: usize> TryFrom<CircuitVar> for Uint<BITS> {
    type Error = CircuitError;

    #[track_caller]
    fn try_from(var: CircuitVar) -> Result<Self, CircuitError> {
        let () = Self::VALID;
        range_check(&var, BITS, "a value does not fit in its bit width")?;
        Ok(Self { var })
    }
}

impl<const BITS: usize> TryFrom<&CircuitVar> for Uint<BITS> {
    type Error = CircuitError;

    #[track_caller]
    fn try_from(var: &CircuitVar) -> Result<Self, CircuitError> {
        Self::try_from(var.clone())
    }
}

macro_rules! conversions {
    ($($narrow:literal => $($wide:literal),+);* $(;)?) => {$($(
        impl From<Uint<$narrow>> for Uint<$wide> {
            fn from(value: Uint<$narrow>) -> Self {
                Uint { var: value.var }
            }
        }

        impl TryFrom<Uint<$wide>> for Uint<$narrow> {
            type Error = CircuitError;

            #[track_caller]
            fn try_from(value: Uint<$wide>) -> Result<Self, CircuitError> {
                fits(
                    &value.var,
                    $narrow,
                    concat!("a value does not fit in ", stringify!($narrow), " bits"),
                )?;
                Ok(Uint { var: value.var })
            }
        }
    )+)*};
}

conversions! {
    8 => 16, 32, 64, 128;
    16 => 32, 64, 128;
    32 => 64, 128;
    64 => 128;
}

impl<const BITS: usize> Select for Uint<BITS> {
    fn select(condition: &Bool, if_true: &Self, if_false: &Self) -> Self {
        Uint::trusted(CircuitVar::select(condition, &if_true.var, &if_false.var))
    }
}

impl<const BITS: usize> Assert for Uint<BITS> {
    #[track_caller]
    fn is_equal(&self, other: &Self) -> Result<Bool, CircuitError> {
        Bool::of_equality(&self.var, &other.var)
    }

    #[track_caller]
    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), CircuitError> {
        self.var.assert_equal(&other.var, rule)
    }

    #[track_caller]
    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), CircuitError> {
        self.var.assert_equal_if(&other.var, condition, rule)
    }

    #[track_caller]
    fn assert_not_equal(&self, other: &Self, rule: &'static str) -> Result<(), CircuitError> {
        self.var.assert_not_equal(&other.var, rule)
    }
}

#[track_caller]
fn fits(var: &CircuitVar, bits: usize, rule: &'static str) -> Result<(), CircuitError> {
    range_check(var, bits, rule).map_err(|error| match error.kind() {
        CircuitErrorKind::ValueTooLarge { .. } => {
            error.replace_kind(CircuitErrorKind::RuleBroken(rule))
        }
        _ => error,
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

fn power_of_two(bits: usize) -> Fr {
    (0..bits).fold(Fr::one(), |power, _| power.double())
}

#[doc(hidden)]
pub const fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        (n - 1).ilog2() as usize + 1
    }
}
