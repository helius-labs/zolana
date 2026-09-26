use core::ops::{Deref, DerefMut};

use borsh::BorshSerialize;

use super::{utxo_domain, Balance, HasLedger, Ledger, Output, SpentInput, Utxo};
use crate::{
    circuit::{poseidon, zero, Assert, Asset, Bool, Bytes, CircuitVar, Owner, PublicTransfer},
    conversion::{to_bytes, FromCircuit},
    hasher::{DataHasher, Poseidon},
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

pub fn checked_utxo_data<S>(state: &S) -> Result<Vec<u8>, RelationError>
where
    S: UtxoData,
    S::Client: DataHasher,
{
    let client = S::Client::from_circuit(state)?;
    if DataHasher::hash::<Poseidon>(&client)? != to_bytes(&DataHash::hash(state)?)? {
        return Err(RelationError::DataHashMismatch);
    }
    borsh::to_vec(&client).map_err(|error| RelationError::StateEncoding(error.to_string()))
}

impl DataHash for CircuitVar {
    fn hash(&self) -> Result<CircuitVar, RelationError> {
        Ok(self.clone())
    }
}

impl DataHash for Bool {
    fn hash(&self) -> Result<CircuitVar, RelationError> {
        Ok(self.var())
    }
}

impl DataHash for Asset {
    fn hash(&self) -> Result<CircuitVar, RelationError> {
        Asset::hash(self)
    }
}

impl<const N: usize> DataHash for Bytes<N> {
    fn hash(&self) -> Result<CircuitVar, RelationError> {
        self.hash_bytes()
    }
}

impl<T: DataHash, const N: usize> DataHash for [T; N] {
    fn hash(&self) -> Result<CircuitVar, RelationError> {
        poseidon(
            &self
                .iter()
                .map(DataHash::hash)
                .collect::<Result<Vec<_>, _>>()?,
        )
    }
}

#[must_use]
#[derive(Debug)]
pub struct DataUtxo<S> {
    ledger: Ledger,
    state: S,
    spent: Option<SpentInput>,
    burn: bool,
}

impl<S> HasLedger for DataUtxo<S> {
    fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    fn ledger_mut(&mut self) -> &mut Ledger {
        &mut self.ledger
    }

    fn is_burned(&self) -> bool {
        self.burn
    }
}

impl<S> Balance for DataUtxo<S> {}

impl<S: Default> DataUtxo<S> {
    pub fn new_init(owner: &Owner, asset: &Asset) -> Self {
        Self {
            ledger: Ledger::new(owner.clone(), asset.clone(), zero()),
            state: S::default(),
            spent: None,
            burn: false,
        }
    }
}

impl<S: DataHash + Clone> DataUtxo<S> {
    pub fn new_mut(input: &Utxo, state: &S) -> Result<Self, RelationError> {
        Self::spend(input, state, false)
    }

    pub fn new_burn(input: &Utxo, state: &S) -> Result<Self, RelationError> {
        Self::spend(input, state, true)
    }

    fn spend(input: &Utxo, state: &S, burn: bool) -> Result<Self, RelationError> {
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
            burn,
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

    pub(crate) fn transferred(&self) -> &CircuitVar {
        self.ledger.transferred()
    }
}

impl<S: DataHash> DataUtxo<S> {
    pub(crate) fn output(&self) -> Result<Option<Output>, RelationError> {
        if self.burn {
            self.balance()
                .assert_equal(&zero(), "a burned data utxo leaves a balance")?;
            return Ok(None);
        }
        Ok(Some(Output {
            owner: self.owner(),
            asset: self.asset(),
            amount: self.balance(),
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
