use ark_ff::{BigInteger, PrimeField};

use super::{Allocator, FromCircuit, Placeholder, ProofInput};
use crate::{
    circuit::{constant, value, var::assert_bool, Bool, CircuitVar, Field, Uint, VariableRole},
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

#[track_caller]
pub fn to_bytes(var: &CircuitVar) -> Result<[u8; 32], RelationError> {
    Ok(field_bytes(&value(var)?))
}

impl ProofInput for Field {
    type Circuit = CircuitVar;

    fn instantiate(&self, allocator: &Allocator) -> Result<CircuitVar, RelationError> {
        allocator.witness(*self, "a field proof input", VariableRole::Constrained)
    }
}

impl FromCircuit for Field {
    fn from_circuit(circuit: &CircuitVar) -> Result<Field, RelationError> {
        value(circuit)
    }
}

impl Placeholder for Field {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(Field::from(0u64))
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

#[track_caller]
fn integer<const BITS: u32>(
    allocator: &Allocator,
    value: u64,
    text: &'static str,
    rule: &'static str,
) -> Result<Uint<BITS>, RelationError> {
    Uint::from_var(
        &allocator.witness(Field::from(value), text, VariableRole::Constrained)?,
        rule,
    )
}

impl ProofInput for u64 {
    type Circuit = Uint<64>;

    fn instantiate(&self, allocator: &Allocator) -> Result<Uint<64>, RelationError> {
        integer(
            allocator,
            *self,
            "a u64 proof input",
            "a u64 proof input does not fit in 64 bits",
        )
    }
}

impl ProofInput for u32 {
    type Circuit = Uint<32>;

    fn instantiate(&self, allocator: &Allocator) -> Result<Uint<32>, RelationError> {
        integer(
            allocator,
            u64::from(*self),
            "a u32 proof input",
            "a u32 proof input does not fit in 32 bits",
        )
    }
}

impl ProofInput for u16 {
    type Circuit = Uint<16>;

    fn instantiate(&self, allocator: &Allocator) -> Result<Uint<16>, RelationError> {
        integer(
            allocator,
            u64::from(*self),
            "a u16 proof input",
            "a u16 proof input does not fit in 16 bits",
        )
    }
}

impl ProofInput for bool {
    type Circuit = Bool;

    fn instantiate(&self, allocator: &Allocator) -> Result<Bool, RelationError> {
        let value = allocator.witness(
            Field::from(*self),
            "a bool proof input",
            VariableRole::Constrained,
        )?;
        assert_bool(&value, "a bool proof input is neither 0 nor 1")?;
        Ok(Bool::from_checked(value))
    }
}

impl ProofInput for [u8; 32] {
    type Circuit = CircuitVar;

    fn instantiate(&self, allocator: &Allocator) -> Result<CircuitVar, RelationError> {
        allocator.witness(
            field(self, "32-byte input")?,
            "a 32-byte proof input",
            VariableRole::Constrained,
        )
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

pub(crate) fn u16_value(var: &CircuitVar) -> Result<u16, RelationError> {
    u16::try_from(integer_value(var, 16)?).map_err(|_| RelationError::OutOfRange(16))
}

pub(crate) fn u64_value(var: &CircuitVar) -> Result<u64, RelationError> {
    integer_value(var, 64)
}

impl FromCircuit for u64 {
    fn from_circuit(circuit: &Uint<64>) -> Result<u64, RelationError> {
        u64_value(&circuit.var())
    }
}

impl FromCircuit for u32 {
    fn from_circuit(circuit: &Uint<32>) -> Result<u32, RelationError> {
        u32::try_from(integer_value(&circuit.var(), 32)?).map_err(|_| RelationError::OutOfRange(32))
    }
}

impl FromCircuit for u16 {
    fn from_circuit(circuit: &Uint<16>) -> Result<u16, RelationError> {
        u16_value(&circuit.var())
    }
}

impl FromCircuit for bool {
    fn from_circuit(circuit: &Bool) -> Result<bool, RelationError> {
        match value(&circuit.var())? {
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

impl Placeholder for u64 {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(0)
    }
}

impl Placeholder for u32 {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(0)
    }
}

impl Placeholder for u16 {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(0)
    }
}

impl Placeholder for bool {
    fn placeholder() -> Result<Self, RelationError> {
        Ok(false)
    }
}

impl Placeholder for [u8; 32] {
    fn placeholder() -> Result<Self, RelationError> {
        Ok([0u8; 32])
    }
}

impl<T: Placeholder, const N: usize> Placeholder for [T; N] {
    fn placeholder() -> Result<Self, RelationError> {
        (0..N)
            .map(|_| T::placeholder())
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| RelationError::Violated("a placeholder array has its own length"))
    }
}
