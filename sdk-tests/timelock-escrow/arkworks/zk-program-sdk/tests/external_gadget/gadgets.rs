//! Gadgets written the way a crate outside the SDK writes them: through
//! `hint` and the public constraint API only.

use zk_program_sdk::{
    circuit,
    circuit::{hint, CircuitVar, Field, U128, U32, U64},
    CircuitError,
};

pub const ISQRT_HINT: &str = "the integer square root";
pub const ISQRT_RULE: &str = "the root is the integer square root";
pub const SQRT_HINT: &str = "a square root";
pub const SQRT_RULE: &str = "the root squares to the value";
pub const NOT_A_SQUARE: &str = "the value is a square";
pub const FORGOTTEN_HINT: &str = "a hint no constraint reads";

/// `root * root <= value < (root + 1) * (root + 1)`, with `root` in 32 bits.
#[circuit]
#[track_caller]
pub fn isqrt(value: &U64) -> Result<U32, CircuitError> {
    let root = integer_root(value)?;
    root.constrain(ISQRT_RULE, |[root]| {
        let root = U32::try_from(root)?;
        root.mul::<64>(&root)
            .assert_less_or_equal(value, ISQRT_RULE)?;
        let next = root.add::<33>(&U32::constant(1)?);
        U128::from(value.clone()).assert_less_than(&next.mul::<128>(&next), ISQRT_RULE)?;
        Ok(root)
    })
}

/// `isqrt` without the upper bound: any root at or below the true one passes.
#[circuit]
#[track_caller]
pub fn isqrt_without_upper_bound(value: &U64) -> Result<U32, CircuitError> {
    let root = integer_root(value)?;
    root.constrain(ISQRT_RULE, |[root]| {
        let root = U32::try_from(root)?;
        root.mul::<64>(&root)
            .assert_less_or_equal(value, ISQRT_RULE)?;
        Ok(root)
    })
}

/// Either of the two roots satisfies the constraint.
#[circuit]
#[track_caller]
pub fn field_sqrt(value: &CircuitVar) -> Result<CircuitVar, CircuitError> {
    hint(SQRT_HINT, [value], |[value]| match value.sqrt() {
        Some(root) => Ok([root]),
        None => Err(CircuitError::rule_broken(NOT_A_SQUARE)),
    })?
    .constrain(SQRT_RULE, |[root]| {
        root.assert_product(root, value, SQRT_RULE)?;
        Ok(root.clone())
    })
}

/// Constrains nothing about its hint, which synthesis refuses.
#[circuit]
#[track_caller]
pub fn forgetful(value: &CircuitVar) -> Result<(), CircuitError> {
    hint(FORGOTTEN_HINT, [value], |[value]| Ok([value]))?.constrain(FORGOTTEN_HINT, |_| Ok(()))
}

#[track_caller]
fn integer_root(
    value: &U64,
) -> Result<zk_program_sdk::circuit::Unconstrained<[CircuitVar; 1]>, CircuitError> {
    hint(ISQRT_HINT, [&value.clone().into()], |[value]| {
        Ok([Field::from(u64::try_from(value)?.isqrt())])
    })
}
