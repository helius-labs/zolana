use ark_bn254::Fr;
use solana_address::Address;

use super::{var::integer_value, Allocator, FromCircuit, Placeholder, ProofInput};
use crate::{
    circuit::{self, builtins::field::bits::range_check, VariableRole},
    client, CircuitError, CircuitErrorKind,
};

impl<const N: usize> ProofInput for client::Bytes<N> {
    type Circuit = circuit::Bytes<N>;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Bytes<N>, CircuitError> {
        let bytes = self
            .0
            .iter()
            .map(|byte| {
                let var = allocator.witness(
                    Fr::from(*byte),
                    "a byte proof input",
                    VariableRole::Constrained,
                )?;
                range_check(&var, 8, "a byte proof input does not fit in 8 bits")?;
                Ok(var)
            })
            .collect::<Result<Vec<_>, CircuitError>>()?;
        Ok(circuit::Bytes::from_checked(bytes.try_into().map_err(
            |_| CircuitErrorKind::WrongLength("bytes instantiate to their own length"),
        )?))
    }
}

impl<const N: usize> FromCircuit for client::Bytes<N> {
    fn from_circuit(circuit: &circuit::Bytes<N>) -> Result<Self, CircuitError> {
        let bytes = circuit
            .bytes()
            .iter()
            .map(byte_value)
            .collect::<Result<Vec<u8>, CircuitError>>()?;
        Ok(Self(bytes.try_into().map_err(|_| {
            CircuitErrorKind::WrongLength("bytes convert back to their own length")
        })?))
    }
}

impl ProofInput for Address {
    type Circuit = circuit::Bytes<32>;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Bytes<32>, CircuitError> {
        client::Bytes(*self.as_array()).instantiate(allocator)
    }
}

impl FromCircuit for Address {
    fn from_circuit(circuit: &circuit::Bytes<32>) -> Result<Self, CircuitError> {
        Ok(Address::new_from_array(
            client::Bytes::<32>::from_circuit(circuit)?.0,
        ))
    }
}

#[track_caller]
pub(super) fn byte_value(var: &circuit::CircuitVar) -> Result<u8, CircuitError> {
    Ok(u8::try_from(integer_value(var, 8)?)
        .map_err(|_| CircuitErrorKind::ValueTooLarge { bits: 8 })?)
}

impl<const N: usize> Placeholder for client::Bytes<N> {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Self([0u8; N]))
    }
}

impl Placeholder for Address {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Address::default())
    }
}
