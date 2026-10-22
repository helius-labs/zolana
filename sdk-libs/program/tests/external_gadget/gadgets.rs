//! Gadgets written outside the SDK as ordinary functions over declared inputs.

use zolana_program::{
    circuit::{CircuitVar, U128, U32, U64},
    CircuitError,
};

/// `root * root <= value < (root + 1) * (root + 1)`, with `root` in 32 bits.
#[deny(clippy::disallowed_types)]
#[track_caller]
pub fn assert_isqrt(value: &U64, root: &U32, rule: &'static str) -> Result<(), CircuitError> {
    root.mul::<64>(root).assert_less_or_equal(value, rule)?;
    let next = root.add::<33>(&U32::constant(1)?);
    U128::from(value.clone()).assert_less_than(&next.mul::<128>(&next), rule)
}

/// Deliberately missing the upper bound: smaller roots also satisfy this.
#[deny(clippy::disallowed_types)]
#[track_caller]
pub fn assert_isqrt_without_upper_bound(
    value: &U64,
    root: &U32,
    rule: &'static str,
) -> Result<(), CircuitError> {
    root.mul::<64>(root).assert_less_or_equal(value, rule)
}

/// Either of the two field roots satisfies the constraint.
#[deny(clippy::disallowed_types)]
#[track_caller]
pub fn assert_field_sqrt(
    value: &CircuitVar,
    root: &CircuitVar,
    rule: &'static str,
) -> Result<(), CircuitError> {
    root.assert_product(root, value, rule)
}
