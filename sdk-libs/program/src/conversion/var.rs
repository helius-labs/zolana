use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

use super::{Allocator, FromCircuit, Placeholder, ProofInput};
use crate::{
    circuit::{
        builtins::field::bits::assert_bool, constant, value, Bool, CircuitVar, Field, Uint,
        VariableRole,
    },
    CircuitError, CircuitErrorKind,
};

pub fn field(bytes: &[u8; 32], name: &'static str) -> Result<Field, CircuitError> {
    let field = Field::from(Fr::from_be_bytes_mod_order(bytes));
    if field_bytes(&field) == *bytes {
        Ok(field)
    } else {
        Err(CircuitErrorKind::BytesTooLarge(name).into())
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Field {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        zolana_keypair::serde_helpers::bytes::serialize(&field_bytes(self), serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Field {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: [u8; 32] = zolana_keypair::serde_helpers::bytes::deserialize(deserializer)?;
        field(&bytes, "a field").map_err(serde::de::Error::custom)
    }
}

pub fn var(bytes: &[u8; 32], name: &'static str) -> Result<CircuitVar, CircuitError> {
    Ok(constant(field(bytes, name)?))
}

pub fn field_bytes(field: &Field) -> [u8; 32] {
    be_bytes(&Fr::from(*field))
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
pub fn to_bytes(var: &CircuitVar) -> Result<[u8; 32], CircuitError> {
    Ok(field_bytes(&value(var)?))
}

impl ProofInput for Field {
    type Circuit = CircuitVar;

    fn instantiate(&self, allocator: &Allocator) -> Result<CircuitVar, CircuitError> {
        allocator.witness(
            Fr::from(*self),
            "a field proof input",
            VariableRole::Constrained,
        )
    }
}

impl FromCircuit for Field {
    fn from_circuit(circuit: &CircuitVar) -> Result<Field, CircuitError> {
        value(circuit)
    }
}

impl Placeholder for Field {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(Field::from(0u64))
    }
}

impl<T: ProofInput, const N: usize> ProofInput for [T; N] {
    type Circuit = [T::Circuit; N];

    fn instantiate(&self, allocator: &Allocator) -> Result<Self::Circuit, CircuitError> {
        let instantiated = self
            .iter()
            .map(|item| item.instantiate(allocator))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(instantiated.try_into().map_err(|_| {
            CircuitErrorKind::WrongLength("an array instantiates to its own length")
        })?)
    }
}

#[track_caller]
fn integer<const BITS: u32>(
    allocator: &Allocator,
    value: u64,
    text: &'static str,
    rule: &'static str,
) -> Result<Uint<BITS>, CircuitError> {
    Uint::from_var(
        &allocator.witness(Fr::from(value), text, VariableRole::Constrained)?,
        rule,
    )
}

impl ProofInput for u64 {
    type Circuit = Uint<64>;

    fn instantiate(&self, allocator: &Allocator) -> Result<Uint<64>, CircuitError> {
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

    fn instantiate(&self, allocator: &Allocator) -> Result<Uint<32>, CircuitError> {
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

    fn instantiate(&self, allocator: &Allocator) -> Result<Uint<16>, CircuitError> {
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

    fn instantiate(&self, allocator: &Allocator) -> Result<Bool, CircuitError> {
        let value = allocator.witness(
            Fr::from(*self),
            "a bool proof input",
            VariableRole::Constrained,
        )?;
        assert_bool(&value, "a bool proof input is neither 0 nor 1")?;
        Ok(Bool::from_checked(value))
    }
}

impl ProofInput for [u8; 32] {
    type Circuit = CircuitVar;

    fn instantiate(&self, allocator: &Allocator) -> Result<CircuitVar, CircuitError> {
        allocator.witness(
            field(self, "32-byte input")?.into(),
            "a 32-byte proof input",
            VariableRole::Constrained,
        )
    }
}

impl<T: FromCircuit, const N: usize> FromCircuit for [T; N] {
    fn from_circuit(circuit: &[T::Circuit; N]) -> Result<Self, CircuitError> {
        let values = circuit
            .iter()
            .map(T::from_circuit)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(values.try_into().map_err(|_| {
            CircuitErrorKind::WrongLength("an array converts back to its own length")
        })?)
    }
}

#[track_caller]
pub(super) fn integer_value(var: &CircuitVar, bits: usize) -> Result<u64, CircuitError> {
    let value = Fr::from(value(var)?).into_bigint();
    if value.num_bits() as usize > bits {
        return Err(CircuitErrorKind::ValueTooLarge { bits }.into());
    }
    Ok(value
        .as_ref()
        .first()
        .copied()
        .ok_or(CircuitErrorKind::ValueTooLarge { bits })?)
}

#[track_caller]
pub(crate) fn u16_value(var: &CircuitVar) -> Result<u16, CircuitError> {
    Ok(u16::try_from(integer_value(var, 16)?)
        .map_err(|_| CircuitErrorKind::ValueTooLarge { bits: 16 })?)
}

#[track_caller]
pub(crate) fn u64_value(var: &CircuitVar) -> Result<u64, CircuitError> {
    integer_value(var, 64)
}

impl FromCircuit for u64 {
    fn from_circuit(circuit: &Uint<64>) -> Result<u64, CircuitError> {
        u64_value(&circuit.var())
    }
}

impl FromCircuit for u32 {
    fn from_circuit(circuit: &Uint<32>) -> Result<u32, CircuitError> {
        Ok(u32::try_from(integer_value(&circuit.var(), 32)?)
            .map_err(|_| CircuitErrorKind::ValueTooLarge { bits: 32 })?)
    }
}

impl FromCircuit for u16 {
    fn from_circuit(circuit: &Uint<16>) -> Result<u16, CircuitError> {
        u16_value(&circuit.var())
    }
}

impl FromCircuit for bool {
    fn from_circuit(circuit: &Bool) -> Result<bool, CircuitError> {
        match value(&circuit.var())? {
            value if value == Field::from(0u64) => Ok(false),
            value if value == Field::from(1u64) => Ok(true),
            _ => Err(CircuitErrorKind::NotZeroOrOne.into()),
        }
    }
}

impl FromCircuit for [u8; 32] {
    fn from_circuit(circuit: &CircuitVar) -> Result<[u8; 32], CircuitError> {
        to_bytes(circuit)
    }
}

impl Placeholder for u64 {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(0)
    }
}

impl Placeholder for u32 {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(0)
    }
}

impl Placeholder for u16 {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(0)
    }
}

impl Placeholder for bool {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok(false)
    }
}

impl Placeholder for [u8; 32] {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok([0u8; 32])
    }
}

impl<T: Placeholder, const N: usize> Placeholder for [T; N] {
    fn placeholder() -> Result<Self, CircuitError> {
        Ok((0..N)
            .map(|_| T::placeholder())
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| CircuitErrorKind::WrongLength("a placeholder array has its own length"))?)
    }
}
