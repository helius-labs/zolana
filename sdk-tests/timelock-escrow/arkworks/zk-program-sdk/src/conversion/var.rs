use ark_ff::{BigInteger, PrimeField};

use super::{Allocator, FromCircuit, ProofInput};
use crate::{
    circuit::{constant, value, Assert, CircuitVar, Field},
    RelationError,
};

pub fn field(bytes: &[u8; 32], name: &'static str) -> Result<Field, RelationError> {
    let field = Field::from_be_bytes_mod_order(bytes);
    if field_bytes(&field) == *bytes {
        Ok(field)
    } else {
        Err(RelationError::NonCanonical(name))
    }
}

pub fn var(bytes: &[u8; 32], name: &'static str) -> Result<CircuitVar, RelationError> {
    Ok(constant(field(bytes, name)?))
}

pub fn field_bytes(field: &Field) -> [u8; 32] {
    be_bytes(field)
}

pub(crate) fn be_bytes(element: &impl PrimeField) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let big_endian = element.into_bigint().to_bytes_be();
    for (target, source) in bytes.iter_mut().rev().zip(big_endian.iter().rev()) {
        *target = *source;
    }
    bytes
}

pub fn to_bytes(var: &CircuitVar) -> Result<[u8; 32], RelationError> {
    Ok(field_bytes(&value(var)?))
}

impl ProofInput for CircuitVar {
    type Circuit = CircuitVar;

    fn instantiate(&self, allocator: &Allocator) -> Result<CircuitVar, RelationError> {
        allocator.private_input(self)
    }
}

impl<T: ProofInput, const N: usize> ProofInput for [T; N] {
    type Circuit = [T::Circuit; N];

    fn instantiate(&self, allocator: &Allocator) -> Result<Self::Circuit, RelationError> {
        let instantiated = self
            .iter()
            .map(|item| item.instantiate(allocator))
            .collect::<Result<Vec<_>, _>>()?;
        instantiated
            .try_into()
            .map_err(|_| RelationError::Violated("an array instantiates to its own length"))
    }
}

fn integer(allocator: &Allocator, value: u64, bits: usize) -> Result<CircuitVar, RelationError> {
    let value = allocator.private_input(&constant(value))?;
    value.check_bits(bits)?;
    Ok(value)
}

impl ProofInput for u64 {
    type Circuit = CircuitVar;

    fn instantiate(&self, allocator: &Allocator) -> Result<CircuitVar, RelationError> {
        integer(allocator, *self, 64)
    }
}

impl ProofInput for u32 {
    type Circuit = CircuitVar;

    fn instantiate(&self, allocator: &Allocator) -> Result<CircuitVar, RelationError> {
        integer(allocator, u64::from(*self), 32)
    }
}

impl ProofInput for u16 {
    type Circuit = CircuitVar;

    fn instantiate(&self, allocator: &Allocator) -> Result<CircuitVar, RelationError> {
        integer(allocator, u64::from(*self), 16)
    }
}

impl ProofInput for bool {
    type Circuit = CircuitVar;

    fn instantiate(&self, allocator: &Allocator) -> Result<CircuitVar, RelationError> {
        let value = allocator.private_input(&constant(u64::from(*self)))?;
        value.check_is_bool()?;
        Ok(value)
    }
}

impl ProofInput for [u8; 32] {
    type Circuit = CircuitVar;

    fn instantiate(&self, allocator: &Allocator) -> Result<CircuitVar, RelationError> {
        allocator.private_input(&var(self, "32-byte input")?)
    }
}

impl<T: FromCircuit, const N: usize> FromCircuit for [T; N] {
    fn from_circuit(circuit: &[T::Circuit; N]) -> Result<Self, RelationError> {
        let values = circuit
            .iter()
            .map(T::from_circuit)
            .collect::<Result<Vec<_>, _>>()?;
        values
            .try_into()
            .map_err(|_| RelationError::Violated("an array converts back to its own length"))
    }
}

pub(super) fn integer_value(var: &CircuitVar, bits: usize) -> Result<u64, RelationError> {
    let value = value(var)?.into_bigint();
    if value.num_bits() as usize > bits {
        return Err(RelationError::OutOfRange(bits));
    }
    value
        .as_ref()
        .first()
        .copied()
        .ok_or(RelationError::OutOfRange(bits))
}

impl FromCircuit for u64 {
    fn from_circuit(circuit: &CircuitVar) -> Result<u64, RelationError> {
        integer_value(circuit, 64)
    }
}

impl FromCircuit for u32 {
    fn from_circuit(circuit: &CircuitVar) -> Result<u32, RelationError> {
        u32::try_from(integer_value(circuit, 32)?).map_err(|_| RelationError::OutOfRange(32))
    }
}

impl FromCircuit for u16 {
    fn from_circuit(circuit: &CircuitVar) -> Result<u16, RelationError> {
        u16::try_from(integer_value(circuit, 16)?).map_err(|_| RelationError::OutOfRange(16))
    }
}

impl FromCircuit for bool {
    fn from_circuit(circuit: &CircuitVar) -> Result<bool, RelationError> {
        match value(circuit)? {
            value if value == Field::from(0u64) => Ok(false),
            value if value == Field::from(1u64) => Ok(true),
            _ => Err(RelationError::NotBool),
        }
    }
}

impl FromCircuit for [u8; 32] {
    fn from_circuit(circuit: &CircuitVar) -> Result<[u8; 32], RelationError> {
        to_bytes(circuit)
    }
}
