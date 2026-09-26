use super::{zero, Asset, Bool, Bytes, CircuitVar, Owner, OwnerKey, TxContext, Utxo};

#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a circuit type",
    label = "a circuit type is built only from CircuitVars",
    note = "derive `ProofInput` or `CircuitType` on the client struct to generate its circuit type, or implement `CircuitType` for a circuit struct by hand"
)]
pub trait CircuitType {}

impl CircuitType for CircuitVar {}

impl CircuitType for Bool {}

impl CircuitType for Owner {}

impl CircuitType for OwnerKey {}

impl CircuitType for Asset {}

impl<const N: usize> CircuitType for Bytes<N> {}

impl CircuitType for Utxo {}

impl CircuitType for TxContext {}

impl<T: CircuitType, const N: usize> CircuitType for [T; N] {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CircuitMarker;

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

impl CircuitDefault for Owner {
    fn circuit_default() -> Self {
        Owner::default()
    }
}

impl CircuitDefault for Asset {
    fn circuit_default() -> Self {
        Asset::default()
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
