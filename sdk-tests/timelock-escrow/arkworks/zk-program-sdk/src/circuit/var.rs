use std::{cell::OnceCell, cmp::Ordering, fmt, panic::Location};

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, BigInteger, Field as _, One, PrimeField, Zero};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, R1CSVar};
use ark_relations::r1cs::ConstraintSystemRef;

use super::{labels, Bool};
use crate::RelationError;

pub type Field = Fr;
pub type CircuitSystem = ConstraintSystemRef<Field>;
pub type ConstraintSystem = ark_relations::r1cs::ConstraintSystem<Field>;

#[must_use]
#[derive(Clone)]
pub struct CircuitVar(pub(super) FpVar<Field>);

impl fmt::Debug for CircuitVar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            FpVar::Constant(value) => write!(formatter, "CircuitVar::constant({value})"),
            FpVar::Var(_) => formatter.write_str("CircuitVar::variable"),
        }
    }
}

pub fn constant(value: impl Into<Field>) -> CircuitVar {
    CircuitVar(FpVar::Constant(value.into()))
}

pub fn zero() -> CircuitVar {
    constant(0u64)
}

#[track_caller]
pub fn value(var: &CircuitVar) -> Result<Field, RelationError> {
    var.constant_value()
        .ok_or(RelationError::ValueOfVariable(Location::caller()))
}

pub(crate) fn system_of<'a>(vars: impl IntoIterator<Item = &'a CircuitVar>) -> CircuitSystem {
    vars.into_iter()
        .fold(CircuitSystem::None, |cs, var| cs.or(var.cs()))
}

pub fn from_bits_le(bits: &[Bool]) -> CircuitVar {
    let mut weight = Field::one();
    bits.iter().fold(zero(), |sum, bit| {
        let sum = sum.plus(&bit.var().scaled(weight));
        weight.double_in_place();
        sum
    })
}

pub(crate) fn cached(
    cell: &OnceCell<CircuitVar>,
    compute: impl FnOnce() -> Result<CircuitVar, RelationError>,
) -> Result<CircuitVar, RelationError> {
    if let Some(value) = cell.get() {
        return Ok(value.clone());
    }
    let value = compute()?;
    Ok(cell.get_or_init(|| value).clone())
}

pub(crate) fn collect_array<T, const N: usize>(
    items: impl IntoIterator<Item = T>,
) -> Result<[T; N], RelationError> {
    items
        .into_iter()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| RelationError::Violated("an array has its own length"))
}

pub trait Assert: Sized {
    fn is_equal(&self, other: &Self) -> Result<Bool, RelationError>;

    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError>;

    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), RelationError>;

    #[track_caller]
    fn assert_not_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError> {
        self.is_equal(other)?.assert_false(rule)
    }
}

impl Assert for CircuitVar {
    #[track_caller]
    fn is_equal(&self, other: &Self) -> Result<Bool, RelationError> {
        Bool::of_equality(self, other)
    }

    #[track_caller]
    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError> {
        if let (Some(left), Some(right)) = (self.constant_value(), other.constant_value()) {
            return if left == right {
                Ok(())
            } else {
                Err(RelationError::Violated(rule))
            };
        }
        labels::check(&self.cs().or(other.cs()), rule, || {
            self.enforce_equal(other)
        })
    }

    #[track_caller]
    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        let difference = self.minus(other);
        let condition = condition.var();
        match (difference.constant_value(), condition.constant_value()) {
            (_, Some(condition)) if condition.is_zero() => Ok(()),
            (_, Some(_)) => self.assert_equal(other, rule),
            (Some(difference), _) if difference.is_zero() => Ok(()),
            _ => labels::check(&difference.cs().or(condition.cs()), rule, || {
                difference.enforce_product(&condition, &zero())
            }),
        }
    }

    #[track_caller]
    fn assert_not_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError> {
        if let (Some(left), Some(right)) = (self.constant_value(), other.constant_value()) {
            return if left != right {
                Ok(())
            } else {
                Err(RelationError::Violated(rule))
            };
        }
        let cs = self.cs().or(other.cs());
        labels::check(&cs, rule, || {
            let difference = self.minus(other);
            let inverse = CircuitVar::witness(&cs, || {
                Ok(difference.assigned()?.inverse().unwrap_or_default())
            })?;
            difference.enforce_product(&inverse, &constant(1u64))
        })
    }
}

impl<T: Assert, const N: usize> Assert for [T; N] {
    #[track_caller]
    fn is_equal(&self, other: &Self) -> Result<Bool, RelationError> {
        all_equal(self, other)
    }

    #[track_caller]
    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), RelationError> {
        assert_all_equal(self, other, rule)
    }

    #[track_caller]
    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), RelationError> {
        assert_all_equal_if(self, other, condition, rule)
    }
}

#[track_caller]
pub(crate) fn all_equal<T: Assert>(left: &[T], right: &[T]) -> Result<Bool, RelationError> {
    let mut flags = Vec::with_capacity(left.len());
    for (left, right) in left.iter().zip(right) {
        flags.push(left.is_equal(right)?);
    }
    Bool::all(&flags)
}

#[track_caller]
pub(crate) fn assert_all_equal<T: Assert>(
    left: &[T],
    right: &[T],
    rule: &'static str,
) -> Result<(), RelationError> {
    for (left, right) in left.iter().zip(right) {
        left.assert_equal(right, rule)?;
    }
    Ok(())
}

#[track_caller]
pub(crate) fn assert_all_equal_if<T: Assert>(
    left: &[T],
    right: &[T],
    condition: &Bool,
    rule: &'static str,
) -> Result<(), RelationError> {
    for (left, right) in left.iter().zip(right) {
        left.assert_equal_if(right, condition, rule)?;
    }
    Ok(())
}

pub trait Bits {
    fn check_bits(&self, bits: usize) -> Result<(), RelationError>;

    fn check_is_bool(&self) -> Result<(), RelationError>;

    fn to_bits_le<const N: usize>(&self) -> Result<[Bool; N], RelationError>;
}

impl Bits for CircuitVar {
    #[track_caller]
    fn check_bits(&self, bits: usize) -> Result<(), RelationError> {
        range_check(self, bits, "a value does not fit in its bit width")
    }

    #[track_caller]
    fn check_is_bool(&self) -> Result<(), RelationError> {
        assert_bool(self, "a value is neither 0 nor 1")
    }

    #[track_caller]
    fn to_bits_le<const N: usize>(&self) -> Result<[Bool; N], RelationError> {
        let bits = labels::check(&self.cs(), "a value does not fit in its bit width", || {
            bits_le(self, N)
        })?;
        collect_array(bits.into_iter().map(Bool::from_checked))
    }
}

#[track_caller]
pub(crate) fn assert_bool(var: &CircuitVar, rule: &'static str) -> Result<(), RelationError> {
    if let Some(value) = var.constant_value() {
        return if value.is_zero() || value.is_one() {
            Ok(())
        } else {
            Err(RelationError::NotBool)
        };
    }
    labels::check(&var.cs(), rule, || {
        var.enforce_product(&var.offset(-Field::one()), &zero())
    })
}

#[track_caller]
pub(crate) fn range_check(
    var: &CircuitVar,
    bits: usize,
    rule: &'static str,
) -> Result<(), RelationError> {
    labels::check(&var.cs(), rule, || bits_le(var, bits).map(|_| ()))
}

pub(crate) fn bits_le(var: &CircuitVar, bits: usize) -> Result<Vec<CircuitVar>, RelationError> {
    if bits >= Field::MODULUS_BIT_SIZE as usize {
        return Err(RelationError::RangeTooWide(bits));
    }
    if let Some(value) = var.constant_value() {
        let value = value.into_bigint();
        if value.num_bits() as usize > bits {
            return Err(RelationError::OutOfRange(bits));
        }
        return Ok((0..bits)
            .map(|index| constant(u64::from(value.get_bit(index))))
            .collect());
    }
    let (decomposed, _) = var.0.to_bits_le_with_top_bits_zero(bits)?;
    Ok(decomposed
        .into_iter()
        .map(CircuitVar::from_boolean)
        .collect())
}

#[track_caller]
pub(crate) fn assert_equal_unless(
    left: &CircuitVar,
    right: &CircuitVar,
    skip: &Boolean<Field>,
    rule: &'static str,
) -> Result<(), RelationError> {
    if let Boolean::Constant(skip) = skip {
        return if *skip {
            Ok(())
        } else {
            left.assert_equal(right, rule)
        };
    }
    labels::check(&left.cs().or(right.cs()).or(skip.cs()), rule, || {
        left.enforce_equal_if(right, &!skip)
    })
}

mod rules {
    #[diagnostic::on_unimplemented(
        message = "a circuit does no field arithmetic on `CircuitVar`",
        label = "field arithmetic wraps around the modulus, so it proves nothing about integers",
        note = "turn the value into a range-checked `Uint<BITS>` with `Uint::from_var`, or use the field operations `inverse`, `div` and `pow` of `Arithmetic`"
    )]
    pub trait ArithmeticNeedsUint {
        fn impossible(self) -> !;
    }

    #[diagnostic::on_unimplemented(
        message = "a circuit does not compare `CircuitVar` values with Rust operators",
        label = "a Rust comparison only sees the native run, never the constraints",
        note = "use `assert_equal`, `assert_not_equal`, `is_equal` or the zero checks of `Compare`, or the comparisons of `Uint<BITS>`"
    )]
    pub trait ComparisonNeedsAssertOrUint {
        fn impossible(&self) -> !;
    }
}

macro_rules! poisoned_operators {
    ($($operator:ident $method:ident $assign:ident $assign_method:ident),*) => {$(
        impl<Rhs: rules::ArithmeticNeedsUint> core::ops::$operator<Rhs> for CircuitVar {
            type Output = CircuitVar;

            fn $method(self, rhs: Rhs) -> CircuitVar {
                rhs.impossible()
            }
        }

        impl<Rhs: rules::ArithmeticNeedsUint> core::ops::$operator<Rhs> for &CircuitVar {
            type Output = CircuitVar;

            fn $method(self, rhs: Rhs) -> CircuitVar {
                rhs.impossible()
            }
        }

        impl<Rhs: rules::ArithmeticNeedsUint> core::ops::$assign<Rhs> for CircuitVar {
            fn $assign_method(&mut self, rhs: Rhs) {
                rhs.impossible()
            }
        }
    )*};
}

poisoned_operators!(
    Add add AddAssign add_assign,
    Sub sub SubAssign sub_assign,
    Mul mul MulAssign mul_assign,
    Div div DivAssign div_assign,
    Rem rem RemAssign rem_assign
);

impl<Rhs: rules::ComparisonNeedsAssertOrUint> PartialEq<Rhs> for CircuitVar {
    fn eq(&self, other: &Rhs) -> bool {
        other.impossible()
    }
}

impl<Rhs: rules::ComparisonNeedsAssertOrUint> PartialOrd<Rhs> for CircuitVar {
    fn partial_cmp(&self, other: &Rhs) -> Option<Ordering> {
        other.impossible()
    }
}
