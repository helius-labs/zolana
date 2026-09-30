use ark_bn254::Fr;
use ark_ff::{Field as _, Zero};
use ark_r1cs_std::{boolean::Boolean, GR1CSVar};

use crate::{
    circuit::{builtins::field::var::system_of, constant, labels, zero, Bool, CircuitVar},
    CircuitError,
};

pub trait Assert: Sized {
    #[track_caller]
    fn is_equal(&self, other: &Self) -> Result<Bool, CircuitError>;

    #[track_caller]
    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), CircuitError>;

    #[track_caller]
    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), CircuitError>;

    #[track_caller]
    fn assert_not_equal(&self, other: &Self, rule: &'static str) -> Result<(), CircuitError> {
        self.is_equal(other)?.assert_false(rule)
    }
}

impl Assert for CircuitVar {
    #[track_caller]
    fn is_equal(&self, other: &Self) -> Result<Bool, CircuitError> {
        Bool::of_equality(self, other)
    }

    #[track_caller]
    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), CircuitError> {
        if let (Some(left), Some(right)) = (self.constant_value(), other.constant_value()) {
            return if left == right {
                Ok(())
            } else {
                Err(CircuitError::rule_broken(rule))
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
    ) -> Result<(), CircuitError> {
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
    fn assert_not_equal(&self, other: &Self, rule: &'static str) -> Result<(), CircuitError> {
        if let (Some(left), Some(right)) = (self.constant_value(), other.constant_value()) {
            return if left != right {
                Ok(())
            } else {
                Err(CircuitError::rule_broken(rule))
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

impl CircuitVar {
    #[track_caller]
    pub fn assert_product(
        &self,
        other: &Self,
        product: &Self,
        rule: &'static str,
    ) -> Result<(), CircuitError> {
        if let (Some(left), Some(right), Some(expected)) = (
            self.constant_value(),
            other.constant_value(),
            product.constant_value(),
        ) {
            return if left * right == expected {
                Ok(())
            } else {
                Err(CircuitError::rule_broken(rule))
            };
        }
        labels::check(&system_of([self, other, product]), rule, || {
            self.enforce_product(other, product)
        })
    }
}

impl<T: Assert, const N: usize> Assert for [T; N] {
    #[track_caller]
    fn is_equal(&self, other: &Self) -> Result<Bool, CircuitError> {
        all_equal(self, other)
    }

    #[track_caller]
    fn assert_equal(&self, other: &Self, rule: &'static str) -> Result<(), CircuitError> {
        assert_all_equal(self, other, rule)
    }

    #[track_caller]
    fn assert_equal_if(
        &self,
        other: &Self,
        condition: &Bool,
        rule: &'static str,
    ) -> Result<(), CircuitError> {
        assert_all_equal_if(self, other, condition, rule)
    }
}

#[track_caller]
pub(crate) fn all_equal<T: Assert>(left: &[T], right: &[T]) -> Result<Bool, CircuitError> {
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
) -> Result<(), CircuitError> {
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
) -> Result<(), CircuitError> {
    for (left, right) in left.iter().zip(right) {
        left.assert_equal_if(right, condition, rule)?;
    }
    Ok(())
}

#[track_caller]
pub(crate) fn assert_equal_unless(
    left: &CircuitVar,
    right: &CircuitVar,
    skip: &Boolean<Fr>,
    rule: &'static str,
) -> Result<(), CircuitError> {
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
