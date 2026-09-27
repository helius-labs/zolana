use std::{cell::OnceCell, cmp::Ordering, fmt};

use ark_bn254::Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::ConstraintSystemRef;

use crate::{CircuitError, CircuitErrorKind};

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
pub fn value(var: &CircuitVar) -> Result<Field, CircuitError> {
    Ok(var
        .constant_value()
        .ok_or(CircuitErrorKind::ReadsVariableValue)?)
}

pub(crate) fn system_of<'a>(vars: impl IntoIterator<Item = &'a CircuitVar>) -> CircuitSystem {
    vars.into_iter()
        .fold(CircuitSystem::None, |cs, var| cs.or(var.cs()))
}

pub(crate) fn cached(
    cell: &OnceCell<CircuitVar>,
    compute: impl FnOnce() -> Result<CircuitVar, CircuitError>,
) -> Result<CircuitVar, CircuitError> {
    if let Some(value) = cell.get() {
        return Ok(value.clone());
    }
    let value = compute()?;
    Ok(cell.get_or_init(|| value).clone())
}

pub(crate) fn collect_array<T, const N: usize>(
    items: impl IntoIterator<Item = T>,
) -> Result<[T; N], CircuitError> {
    Ok(items
        .into_iter()
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| CircuitErrorKind::WrongLength("an array has its own length"))?)
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
