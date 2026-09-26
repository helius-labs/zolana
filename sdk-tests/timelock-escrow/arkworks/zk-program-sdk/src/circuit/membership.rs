use super::{constant, Bool, CircuitVar, Compare};
use crate::RelationError;

pub fn is_in(value: &CircuitVar, set: &[CircuitVar]) -> Result<Bool, RelationError> {
    distance_product(value, set).is_zero()
}

pub fn assert_in(
    value: &CircuitVar,
    set: &[CircuitVar],
    rule: &'static str,
) -> Result<(), RelationError> {
    distance_product(value, set).assert_zero(rule)
}

fn distance_product(value: &CircuitVar, set: &[CircuitVar]) -> CircuitVar {
    set.iter().fold(constant(1u64), |product, member| {
        product * (value.clone() - member)
    })
}
