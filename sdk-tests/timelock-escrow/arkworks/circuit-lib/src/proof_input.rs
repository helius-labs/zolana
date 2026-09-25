use ark_r1cs_std::{alloc::AllocVar, R1CSVar};

use crate::{constant, Assert, CircuitSystem, CircuitVar, RelationError};

#[derive(Clone, Debug)]
pub enum Allocator {
    Native,
    R1cs(CircuitSystem),
}

impl Allocator {
    pub fn private_input(&self, value: &CircuitVar) -> Result<CircuitVar, RelationError> {
        match self {
            Self::Native => Ok(value.clone()),
            Self::R1cs(cs) => Ok(CircuitVar::new_witness(cs.clone(), || value.value())?),
        }
    }

    pub fn public_input(&self, value: &CircuitVar) -> Result<CircuitVar, RelationError> {
        match self {
            Self::Native => Ok(value.clone()),
            Self::R1cs(cs) => Ok(CircuitVar::new_input(cs.clone(), || value.value())?),
        }
    }
}

pub trait ProofInput {
    type Circuit;

    fn instantiate(&self, allocator: &Allocator) -> Result<Self::Circuit, RelationError>;
}

pub trait RangeCheck {
    fn range_check(value: &CircuitVar) -> Result<(), RelationError>;
}

impl RangeCheck for CircuitVar {
    fn range_check(_: &CircuitVar) -> Result<(), RelationError> {
        Ok(())
    }
}

impl ProofInput for CircuitVar {
    type Circuit = CircuitVar;

    fn instantiate(&self, allocator: &Allocator) -> Result<CircuitVar, RelationError> {
        let value = allocator.private_input(self)?;
        Self::range_check(&value)?;
        Ok(value)
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

#[derive(Clone, Debug)]
pub struct Uint<const BITS: usize>(CircuitVar);

pub type U64 = Uint<64>;
pub type U32 = Uint<32>;
pub type U16 = Uint<16>;

impl<const BITS: usize> Uint<BITS> {
    pub fn new(value: CircuitVar) -> Self {
        Self(value)
    }
}

impl<const BITS: usize> From<u64> for Uint<BITS> {
    fn from(value: u64) -> Self {
        Self(constant(value))
    }
}

impl<const BITS: usize> RangeCheck for Uint<BITS> {
    fn range_check(value: &CircuitVar) -> Result<(), RelationError> {
        value.check_bits(BITS)
    }
}

impl<const BITS: usize> ProofInput for Uint<BITS> {
    type Circuit = CircuitVar;

    fn instantiate(&self, allocator: &Allocator) -> Result<CircuitVar, RelationError> {
        let value = allocator.private_input(&self.0)?;
        Self::range_check(&value)?;
        Ok(value)
    }
}

#[derive(Clone, Debug)]
pub struct Bool(CircuitVar);

impl Bool {
    pub fn new(value: CircuitVar) -> Self {
        Self(value)
    }
}

impl From<bool> for Bool {
    fn from(value: bool) -> Self {
        Self(constant(u64::from(value)))
    }
}

impl RangeCheck for Bool {
    fn range_check(value: &CircuitVar) -> Result<(), RelationError> {
        value.check_is_bool()
    }
}

impl ProofInput for Bool {
    type Circuit = CircuitVar;

    fn instantiate(&self, allocator: &Allocator) -> Result<CircuitVar, RelationError> {
        let value = allocator.private_input(&self.0)?;
        Self::range_check(&value)?;
        Ok(value)
    }
}
