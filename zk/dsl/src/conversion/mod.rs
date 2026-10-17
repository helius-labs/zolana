mod bytes;
mod var;

use std::{
    any::{Any, TypeId},
    cell::RefCell,
    collections::HashMap,
};

use ark_bn254::Fr;

#[doc(hidden)]
pub use bytes::byte_value;
#[cfg(feature = "client")]
pub(crate) use var::be_bytes;
#[doc(hidden)]
pub use var::u16_value;
pub use var::{field, field_bytes, to_bytes};
pub use zolana_zk_macros::ProofInput;

use crate::{
    circuit::{constant, labels, CircuitSystem, CircuitType, CircuitVar, VariableRole},
    CircuitError, CircuitErrorKind,
};

/// What a native instantiation records for the client, kept per record type so
/// each crate that converts proof inputs keeps its own records.
#[derive(Default)]
pub struct Records {
    entries: HashMap<TypeId, Box<dyn Any>>,
}

impl Records {
    pub fn get<T: 'static>(&self) -> Option<&T> {
        self.entries
            .get(&TypeId::of::<T>())
            .and_then(|entry| entry.downcast_ref())
    }

    fn entry<T: Default + 'static>(&mut self) -> Option<&mut T> {
        self.entries
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Box::new(T::default()))
            .downcast_mut()
    }
}

pub enum Allocator {
    /// Evaluates proof inputs as constants for client-side execution.
    /// Reads permitted here may still be refused by R1CS synthesis.
    Native(RefCell<Records>),
    R1cs(CircuitSystem),
}

impl Allocator {
    pub fn native() -> Self {
        Self::Native(RefCell::default())
    }

    #[doc(hidden)]
    #[track_caller]
    pub fn witness(
        &self,
        value: Fr,
        text: &'static str,
        role: VariableRole,
    ) -> Result<CircuitVar, CircuitError> {
        match self {
            Self::Native(_) => Ok(constant(value)),
            Self::R1cs(cs) => {
                labels::allocate(cs, text, role, || CircuitVar::witness(cs, || Ok(value)))
            }
        }
    }

    #[doc(hidden)]
    pub fn cs(&self) -> CircuitSystem {
        match self {
            Self::Native(_) => CircuitSystem::None,
            Self::R1cs(cs) => cs.clone(),
        }
    }

    pub fn into_records(self) -> Records {
        match self {
            Self::Native(records) => records.into_inner(),
            Self::R1cs(_) => Records::default(),
        }
    }

    #[doc(hidden)]
    pub fn record<T: Default + 'static>(&self, write: impl FnOnce(&mut T)) {
        if let Self::Native(records) = self {
            if let Some(entry) = records.borrow_mut().entry() {
                write(entry);
            }
        }
    }
}

pub trait ProofInput {
    type Circuit: CircuitType;

    fn instantiate(&self, allocator: &Allocator) -> Result<Self::Circuit, CircuitError>;
}

pub trait FromCircuit: ProofInput + Sized {
    fn from_circuit(circuit: &Self::Circuit) -> Result<Self, CircuitError>;
}

pub trait Placeholder: Sized {
    fn placeholder() -> Result<Self, CircuitError>;
}

pub trait Dummy: Sized {
    fn dummy(first: Option<&Self>) -> Result<Self, CircuitError>;
}

#[track_caller]
pub fn instantiate_padded<T: ProofInput + Dummy, const MIN: usize, const MAX: usize>(
    items: &[T],
    field: &'static str,
    allocator: &Allocator,
) -> Result<[T::Circuit; MAX], CircuitError> {
    const { assert!(MIN <= MAX, "a padded field takes min_len <= max_len") };
    let given = items.len();
    if given > MAX {
        return Err(CircuitErrorKind::TooManyItems {
            field,
            max: MAX,
            given,
        }
        .into());
    }
    if given < MIN {
        return Err(CircuitErrorKind::TooFewItems {
            field,
            min: MIN,
            given,
        }
        .into());
    }
    let dummy = T::dummy(items.first())?;
    let instantiated = items
        .iter()
        .chain(std::iter::repeat_n(&dummy, MAX.saturating_sub(given)))
        .map(|item| item.instantiate(allocator))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(instantiated.try_into().map_err(|_| {
        CircuitErrorKind::WrongLength("padded items instantiate to their maximum length")
    })?)
}

pub fn placeholders<T: Placeholder, const MAX: usize>() -> Result<Vec<T>, CircuitError> {
    (0..MAX).map(|_| T::placeholder()).collect()
}
