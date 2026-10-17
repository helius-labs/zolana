use super::{zero, Bool, Bytes, CircuitVar, Uint};

#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a circuit type",
    label = "a circuit type is built only from CircuitVars",
    note = "derive `ProofInput` or `CircuitType` on the client struct to generate its circuit type, or implement `CircuitType` for a circuit struct by hand"
)]
pub trait CircuitType {}

impl CircuitType for CircuitVar {}

impl CircuitType for Bool {}

impl<const BITS: usize> CircuitType for Uint<BITS> {}

impl<const N: usize> CircuitType for Bytes<N> {}

impl<T: CircuitType, const N: usize> CircuitType for [T; N] {}

pub trait CircuitDefault {
    fn circuit_default() -> Self;
}

impl CircuitDefault for CircuitVar {
    fn circuit_default() -> Self {
        zero()
    }
}

impl CircuitDefault for Bool {
    fn circuit_default() -> Self {
        Bool::constant(false)
    }
}

impl<const BITS: usize> CircuitDefault for Uint<BITS> {
    fn circuit_default() -> Self {
        Uint::zero()
    }
}

impl<const N: usize> CircuitDefault for Bytes<N> {
    fn circuit_default() -> Self {
        Bytes::default()
    }
}

impl<T: CircuitDefault, const N: usize> CircuitDefault for [T; N] {
    fn circuit_default() -> Self {
        core::array::from_fn(|_| T::circuit_default())
    }
}
