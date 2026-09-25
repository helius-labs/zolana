use core::ops::{Deref, DerefMut};

use borsh::BorshSerialize;

use super::{utxo_domain, Output, OutputTokenUtxo, Utxo};
use crate::{
    circuit::{zero, Assert, Asset, CircuitVar, Owner},
    conversion::FromCircuit,
    RelationError,
};

pub trait DataHash {
    fn hash(&self) -> Result<CircuitVar, RelationError>;
}

pub trait UtxoData: DataHash + Sized {
    type Client: FromCircuit<Circuit = Self> + BorshSerialize;

    fn utxo_data(&self) -> Result<Vec<u8>, RelationError> {
        borsh::to_vec(&Self::Client::from_circuit(self)?)
            .map_err(|error| RelationError::StateEncoding(error.to_string()))
    }
}

impl DataHash for CircuitVar {
    fn hash(&self) -> Result<CircuitVar, RelationError> {
        Ok(self.clone())
    }
}

#[derive(Clone, Debug)]
enum DataLifecycle {
    Init,
    Mut(CircuitVar),
    Burn(CircuitVar),
}

#[must_use]
#[derive(Clone, Debug)]
pub struct DataUtxo<S> {
    owner: Owner,
    asset: Asset,
    amount: CircuitVar,
    unpaid: CircuitVar,
    state: S,
    lifecycle: DataLifecycle,
}

impl<S: DataHash> DataUtxo<S> {
    pub fn new_init(owner: &Owner) -> Result<Self, RelationError>
    where
        S: Default,
    {
        Ok(Self {
            owner: owner.clone(),
            asset: Asset::sol(),
            amount: zero(),
            unpaid: zero(),
            state: S::default(),
            lifecycle: DataLifecycle::Init,
        })
    }

    pub fn from_output_utxo(output: OutputTokenUtxo) -> Result<Self, RelationError>
    where
        S: Default,
    {
        Ok(Self {
            owner: output.owner,
            asset: output.asset,
            amount: output.amount,
            unpaid: zero(),
            state: S::default(),
            lifecycle: DataLifecycle::Init,
        })
    }

    pub fn new_mut(input: &Utxo, state: S) -> Result<Self, RelationError> {
        let input_hash = Self::spent_input(input, &state)?;
        Ok(Self::from_input(
            input,
            state,
            DataLifecycle::Mut(input_hash),
        ))
    }

    pub fn new_burn(input: &Utxo, state: S) -> Result<Self, RelationError> {
        let input_hash = Self::spent_input(input, &state)?;
        Ok(Self::from_input(
            input,
            state,
            DataLifecycle::Burn(input_hash),
        ))
    }

    pub fn owner(&self) -> &Owner {
        &self.owner
    }

    pub fn asset(&self) -> &Asset {
        &self.asset
    }

    pub fn amount(&self) -> &CircuitVar {
        &self.amount
    }

    pub fn transfer(
        &mut self,
        recipient: &Owner,
        amount: CircuitVar,
    ) -> Result<OutputTokenUtxo, RelationError> {
        match self.lifecycle {
            DataLifecycle::Burn(_) => {
                self.unpaid -= &amount;
                Ok(OutputTokenUtxo {
                    owner: recipient.clone(),
                    asset: self.asset.clone(),
                    amount,
                })
            }
            _ => Err(RelationError::Violated(
                "only a burned data utxo transfers its value",
            )),
        }
    }

    pub(crate) fn input_hash(&self) -> Option<CircuitVar> {
        match &self.lifecycle {
            DataLifecycle::Mut(input_hash) | DataLifecycle::Burn(input_hash) => {
                Some(input_hash.clone())
            }
            DataLifecycle::Init => None,
        }
    }

    pub(crate) fn output(&self) -> Result<Option<Output>, RelationError> {
        if let DataLifecycle::Burn(_) = self.lifecycle {
            self.unpaid
                .assert_equal(&zero(), "a burned data utxo leaves value unpaid")?;
            return Ok(None);
        }
        Ok(Some(Output {
            owner: self.owner.clone(),
            asset: self.asset.clone(),
            amount: self.amount.clone(),
            data_hash: self.state.hash()?,
            data: None,
        }))
    }

    fn spent_input(input: &Utxo, state: &S) -> Result<CircuitVar, RelationError> {
        input
            .domain
            .assert_equal(&utxo_domain(), "the utxo is not a spendable utxo")?;
        input.assert_default_ring()?;
        input.data_hash.assert_equal(
            &state.hash()?,
            "the input does not commit to its program state",
        )?;
        input.hash()
    }

    fn from_input(input: &Utxo, state: S, lifecycle: DataLifecycle) -> Self {
        Self {
            owner: input.owner.clone(),
            asset: input.asset.clone(),
            amount: input.amount.clone(),
            unpaid: input.amount.clone(),
            state,
            lifecycle,
        }
    }
}

impl<S> Deref for DataUtxo<S> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.state
    }
}

impl<S> DerefMut for DataUtxo<S> {
    fn deref_mut(&mut self) -> &mut S {
        &mut self.state
    }
}
