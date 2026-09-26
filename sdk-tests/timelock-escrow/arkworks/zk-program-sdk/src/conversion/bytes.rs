use solana_address::Address;

use super::{var::integer_value, Allocator, FromCircuit, Placeholder, ProofInput};
use crate::{
    circuit::{self, constant, Bits},
    client, RelationError,
};

impl<const N: usize> ProofInput for client::Bytes<N> {
    type Circuit = circuit::Bytes<N>;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Bytes<N>, RelationError> {
        let bytes = self
            .0
            .iter()
            .map(|byte| {
                let var = allocator.private_input(&constant(u64::from(*byte)))?;
                var.check_bits(8)?;
                Ok(var)
            })
            .collect::<Result<Vec<_>, RelationError>>()?;
        Ok(circuit::Bytes::from_checked(bytes.try_into().map_err(
            |_| RelationError::Violated("bytes instantiate to their own length"),
        )?))
    }
}

impl<const N: usize> FromCircuit for client::Bytes<N> {
    fn from_circuit(circuit: &circuit::Bytes<N>) -> Result<Self, RelationError> {
        let bytes = circuit
            .bytes()
            .iter()
            .map(byte_value)
            .collect::<Result<Vec<u8>, RelationError>>()?;
        Ok(Self(bytes.try_into().map_err(|_| {
            RelationError::Violated("bytes convert back to their own length")
        })?))
    }
}

impl ProofInput for Address {
    type Circuit = circuit::Bytes<32>;

    fn instantiate(&self, allocator: &Allocator) -> Result<circuit::Bytes<32>, RelationError> {
        client::Bytes(*self.as_array()).instantiate(allocator)
    }
}

impl FromCircuit for Address {
    fn from_circuit(circuit: &circuit::Bytes<32>) -> Result<Self, RelationError> {
        Ok(Address::new_from_array(
            client::Bytes::<32>::from_circuit(circuit)?.0,
        ))
    }
}

pub(super) fn byte_value(var: &circuit::CircuitVar) -> Result<u8, RelationError> {
    u8::try_from(integer_value(var, 8)?).map_err(|_| RelationError::OutOfRange(8))
}

impl<const N: usize> Placeholder for client::Bytes<N> {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Self([0u8; N]))
    }
}

impl Placeholder for Address {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Address::default())
    }
}
