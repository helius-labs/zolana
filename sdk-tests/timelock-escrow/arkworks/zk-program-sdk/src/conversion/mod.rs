mod asset;
mod bytes;
mod owner;
mod transaction;
mod utxo;
mod var;

use std::{cell::RefCell, collections::HashMap};

use zolana_keypair::ShieldedAddress;
use zolana_transaction::{Mint, WalletUtxo};

#[cfg(any(feature = "client", feature = "setup"))]
pub(crate) use var::be_bytes;
#[cfg(feature = "client")]
pub(crate) use var::u16_value;
pub use var::{field, field_bytes, to_bytes, var};
pub use zk_program_sdk_macros::ProofInput;

use crate::{
    circuit::{constant, labels, CircuitSystem, CircuitType, CircuitVar, Field, VariableRole},
    CircuitError,
};

#[derive(Clone, Default)]
pub struct Records {
    pub(crate) owners: HashMap<[u8; 32], ShieldedAddress>,
    pub(crate) mints: HashMap<[u8; 32], Mint>,
    pub(crate) utxos: HashMap<[u8; 32], WalletUtxo>,
}

impl Records {
    pub fn owner(&self, owner_hash: &[u8; 32]) -> Option<&ShieldedAddress> {
        self.owners.get(owner_hash)
    }

    pub fn mint(&self, asset_hash: &[u8; 32]) -> Option<&Mint> {
        self.mints.get(asset_hash)
    }

    pub fn utxo(&self, utxo_hash: &[u8; 32]) -> Option<&WalletUtxo> {
        self.utxos.get(utxo_hash)
    }
}

pub enum Allocator {
    Native(RefCell<Records>),
    R1cs(CircuitSystem),
}

impl Allocator {
    pub fn native() -> Self {
        Self::Native(RefCell::default())
    }

    #[track_caller]
    pub(crate) fn witness(
        &self,
        value: Field,
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

    pub(crate) fn cs(&self) -> CircuitSystem {
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

    fn record(&self, write: impl FnOnce(&mut Records)) {
        if let Self::Native(records) = self {
            write(&mut records.borrow_mut());
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
