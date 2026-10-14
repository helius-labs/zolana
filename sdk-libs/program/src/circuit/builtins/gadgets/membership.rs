use crate::{
    circuit::{constant, zero, Assert, Bool, CircuitVar},
    CircuitError,
};

#[track_caller]
pub fn is_in(value: &CircuitVar, set: &[CircuitVar]) -> Result<Bool, CircuitError> {
    distance_product(value, set).is_equal(&zero())
}

#[track_caller]
pub fn assert_in(
    value: &CircuitVar,
    set: &[CircuitVar],
    rule: &'static str,
) -> Result<(), CircuitError> {
    distance_product(value, set).assert_equal(&zero(), rule)
}

fn distance_product(value: &CircuitVar, set: &[CircuitVar]) -> CircuitVar {
    set.iter().fold(constant(1u64), |product, member| {
        product.times(&value.minus(member))
    })
}
