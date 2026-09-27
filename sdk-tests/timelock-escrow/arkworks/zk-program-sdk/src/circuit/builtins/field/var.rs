use std::{
    cell::OnceCell,
    cmp::Ordering,
    fmt,
    ops::{Add, Mul, Neg, Sub},
};

use ark_bn254::Fr;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::gr1cs::ConstraintSystemRef;

use crate::{CircuitError, CircuitErrorKind};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Field(Fr);

macro_rules! field_from {
    ($($source:ty),*) => {$(
        impl From<$source> for Field {
            fn from(value: $source) -> Self {
                Self(Fr::from(value))
            }
        }
    )*};
}

field_from!(u8, u16, u32, u64, u128, bool);

impl From<Fr> for Field {
    fn from(value: Fr) -> Self {
        Self(value)
    }
}

impl From<Field> for Fr {
    fn from(value: Field) -> Self {
        value.0
    }
}

impl Add for Field {
    type Output = Field;

    fn add(self, rhs: Field) -> Field {
        Self(self.0 + rhs.0)
    }
}

impl Sub for Field {
    type Output = Field;

    fn sub(self, rhs: Field) -> Field {
        Self(self.0 - rhs.0)
    }
}

impl Mul for Field {
    type Output = Field;

    fn mul(self, rhs: Field) -> Field {
        Self(self.0 * rhs.0)
    }
}

impl Neg for Field {
    type Output = Field;

    fn neg(self) -> Field {
        Self(-self.0)
    }
}

impl fmt::Display for Field {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, formatter)
    }
}

pub type CircuitSystem = ConstraintSystemRef<Fr>;
pub type ConstraintSystem = ark_relations::gr1cs::ConstraintSystem<Fr>;

#[must_use]
#[derive(Clone)]
pub struct CircuitVar(pub(super) FpVar<Fr>);

impl fmt::Debug for CircuitVar {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            FpVar::Constant(value) => write!(formatter, "CircuitVar::constant({value})"),
            FpVar::Var(_) => formatter.write_str("CircuitVar::variable"),
        }
    }
}

pub fn constant(value: impl Into<Field>) -> CircuitVar {
    CircuitVar(FpVar::Constant(value.into().0))
}

pub fn zero() -> CircuitVar {
    constant(0u64)
}

#[track_caller]
pub fn value(var: &CircuitVar) -> Result<Field, CircuitError> {
    let value = var
        .constant_value()
        .ok_or(CircuitErrorKind::ReadsVariableValue)?;
    Ok(Field(value))
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
        message = "`/` on `CircuitVar` multiplies by a field inverse, which is not integer division",
        label = "use `Uint::div_rem` for integer division",
        note = "turn the value into a `Uint<BITS>` with `Uint::try_from` first",
        note = "for deliberate field division, use `CircuitVar::div`"
    )]
    pub trait UseDivRem {
        fn impossible(self) -> !;
    }

    #[diagnostic::on_unimplemented(
        message = "`%` on `CircuitVar` has no meaning in the field",
        label = "use the remainder that `Uint::div_rem` returns",
        note = "turn the value into a `Uint<BITS>` with `Uint::try_from` first"
    )]
    pub trait UseRemOfDivRem {
        fn impossible(self) -> !;
    }

    #[diagnostic::on_unimplemented(
        message = "`==` on `CircuitVar` compares only the native values and adds no constraint",
        label = "use `assert_equal`, `assert_not_equal` or `is_equal`",
        note = "`is_equal` returns a `Bool` that the circuit constrains"
    )]
    pub trait UseAssertEqual {
        fn impossible(&self) -> !;
    }

    #[diagnostic::on_unimplemented(
        message = "`<` and `>` on `CircuitVar` compare only the native values and add no constraint",
        label = "use `Uint::is_less_than`, `Uint::assert_less_than` or `Uint::assert_in_range`",
        note = "turn the value into a `Uint<BITS>` with `Uint::try_from` first"
    )]
    pub trait UseUintComparison: UseAssertEqual {
        fn impossible(&self) -> !;
    }
}

macro_rules! poisoned_operators {
    ($($operator:ident $method:ident $assign:ident $assign_method:ident $rule:ident),*) => {$(
        impl<Rhs: rules::$rule> core::ops::$operator<Rhs> for CircuitVar {
            type Output = CircuitVar;

            fn $method(self, rhs: Rhs) -> CircuitVar {
                rhs.impossible()
            }
        }

        impl<Rhs: rules::$rule> core::ops::$operator<Rhs> for &CircuitVar {
            type Output = CircuitVar;

            fn $method(self, rhs: Rhs) -> CircuitVar {
                rhs.impossible()
            }
        }

        impl<Rhs: rules::$rule> core::ops::$assign<Rhs> for CircuitVar {
            fn $assign_method(&mut self, rhs: Rhs) {
                rhs.impossible()
            }
        }
    )*};
}

poisoned_operators!(
    Div div DivAssign div_assign UseDivRem,
    Rem rem RemAssign rem_assign UseRemOfDivRem
);

macro_rules! field_operators {
    ($($operator:ident $method:ident $assign:ident $assign_method:ident $combine:ident),*) => {$(
        impl core::ops::$operator<&CircuitVar> for &CircuitVar {
            type Output = CircuitVar;

            fn $method(self, rhs: &CircuitVar) -> CircuitVar {
                self.$combine(rhs)
            }
        }

        impl core::ops::$operator<CircuitVar> for &CircuitVar {
            type Output = CircuitVar;

            fn $method(self, rhs: CircuitVar) -> CircuitVar {
                self.$combine(&rhs)
            }
        }

        impl core::ops::$operator<&CircuitVar> for CircuitVar {
            type Output = CircuitVar;

            fn $method(self, rhs: &CircuitVar) -> CircuitVar {
                self.$combine(rhs)
            }
        }

        impl core::ops::$operator<CircuitVar> for CircuitVar {
            type Output = CircuitVar;

            fn $method(self, rhs: CircuitVar) -> CircuitVar {
                self.$combine(&rhs)
            }
        }

        impl core::ops::$operator<Field> for &CircuitVar {
            type Output = CircuitVar;

            fn $method(self, rhs: Field) -> CircuitVar {
                self.$combine(&constant(rhs))
            }
        }

        impl core::ops::$operator<Field> for CircuitVar {
            type Output = CircuitVar;

            fn $method(self, rhs: Field) -> CircuitVar {
                self.$combine(&constant(rhs))
            }
        }

        impl core::ops::$assign<&CircuitVar> for CircuitVar {
            fn $assign_method(&mut self, rhs: &CircuitVar) {
                *self = self.$combine(rhs);
            }
        }

        impl core::ops::$assign<CircuitVar> for CircuitVar {
            fn $assign_method(&mut self, rhs: CircuitVar) {
                *self = self.$combine(&rhs);
            }
        }

        impl core::ops::$assign<Field> for CircuitVar {
            fn $assign_method(&mut self, rhs: Field) {
                *self = self.$combine(&constant(rhs));
            }
        }
    )*};
}

field_operators!(
    Add add AddAssign add_assign plus,
    Sub sub SubAssign sub_assign minus,
    Mul mul MulAssign mul_assign times
);

impl Neg for &CircuitVar {
    type Output = CircuitVar;

    fn neg(self) -> CircuitVar {
        zero().minus(self)
    }
}

impl Neg for CircuitVar {
    type Output = CircuitVar;

    fn neg(self) -> CircuitVar {
        zero().minus(&self)
    }
}

impl<Rhs: rules::UseAssertEqual> PartialEq<Rhs> for CircuitVar {
    fn eq(&self, other: &Rhs) -> bool {
        other.impossible()
    }
}

impl<Rhs: rules::UseUintComparison> PartialOrd<Rhs> for CircuitVar {
    fn partial_cmp(&self, other: &Rhs) -> Option<Ordering> {
        rules::UseUintComparison::impossible(other)
    }
}
