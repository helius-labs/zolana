use core::ops::{Deref, DerefMut};

use borsh::BorshSerialize;

use super::{utxo_domain, Balance, Ledger, Output, OutputTokenUtxo, SpentInput, Utxo};
use crate::{
    circuit::{zero, Assert, Asset, CircuitVar, Owner, PublicTransfer},
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DataLifecycle {
    Init,
    Mut,
    Burn,
}

#[must_use]
#[derive(Clone, Debug)]
pub struct DataUtxo<S> {
    ledger: Ledger,
    state: S,
    spent: Option<SpentInput>,
    lifecycle: DataLifecycle,
}

impl<S> Balance for DataUtxo<S> {
    fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    fn ledger_mut(&mut self) -> &mut Ledger {
        &mut self.ledger
    }
}

impl<S: Default> DataUtxo<S> {
    pub fn new_init(owner: &Owner) -> Self {
        Self {
            ledger: Ledger::new(owner.clone(), Asset::sol(), zero()),
            state: S::default(),
            spent: None,
            lifecycle: DataLifecycle::Init,
        }
    }

    pub fn from_output_utxo(output: OutputTokenUtxo) -> Self {
        Self {
            ledger: Ledger::new(output.owner, output.asset, output.amount),
            state: S::default(),
            spent: None,
            lifecycle: DataLifecycle::Init,
        }
    }
}

impl<S: DataHash + Clone> DataUtxo<S> {
    pub fn new_mut(input: &Utxo, state: &S) -> Result<Self, RelationError> {
        Self::spend(input, state, DataLifecycle::Mut)
    }

    pub fn new_burn(input: &Utxo, state: &S) -> Result<Self, RelationError> {
        Self::spend(input, state, DataLifecycle::Burn)
    }

    fn spend(input: &Utxo, state: &S, lifecycle: DataLifecycle) -> Result<Self, RelationError> {
        input
            .domain
            .assert_equal(&utxo_domain(), "the utxo is not a spendable utxo")?;
        input.assert_default_ring()?;
        input.data_hash.assert_equal(
            &state.hash()?,
            "the input does not commit to its program state",
        )?;
        Ok(Self {
            ledger: Ledger::new(
                input.owner.clone(),
                input.asset.clone(),
                input.amount.clone(),
            ),
            state: state.clone(),
            spent: Some(input.spent(input.hash()?)),
            lifecycle,
        })
    }
}

impl<S> DataUtxo<S> {
    pub(crate) fn spent_input(&self) -> Option<SpentInput> {
        self.spent.clone()
    }

    pub(crate) fn public_transfers(&self) -> &[PublicTransfer] {
        self.ledger.public_transfers()
    }
}

impl<S: DataHash> DataUtxo<S> {
    pub(crate) fn output(&self) -> Result<Option<Output>, RelationError> {
        if self.lifecycle == DataLifecycle::Burn {
            self.ledger
                .balance()
                .assert_equal(&zero(), "a burned data utxo leaves a balance")?;
            return Ok(None);
        }
        Ok(Some(Output {
            owner: self.ledger.owner(),
            asset: self.ledger.asset(),
            amount: self.ledger.balance(),
            data_hash: self.state.hash()?,
            data: None,
        }))
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
