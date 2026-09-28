use core::ops::{Deref, DerefMut};

use borsh::BorshSerialize;

use super::{utxo_domain, Accumulator, Balance, HasLedger, Ledger, Output, SpentInput, Utxo};
use crate::{
    circuit::{
        constant, labels::Scope, poseidon, zero, Assert, Asset, Bool, Bytes, CircuitVar, Owner,
        PublicTransfer, Uint,
    },
    conversion::{to_bytes, FromCircuit},
    hasher::{
        DataHasher, Poseidon, CLOSED_DATA_HASH_DOMAIN, DATA_HASH_DOMAIN, UNIQUE_DATA_HASH_DOMAIN,
    },
    CircuitError, CircuitErrorKind,
};

const CLOSED_LEAVES_BALANCE: &str = "a closed data utxo leaves a balance";

pub trait DataHash {
    fn hash(&self) -> Result<CircuitVar, CircuitError>;
}

pub trait UtxoData: DataHash + Sized {
    type Client: FromCircuit<Circuit = Self> + BorshSerialize;

    fn utxo_data(&self) -> Result<Vec<u8>, CircuitError> {
        Ok(borsh::to_vec(&Self::Client::from_circuit(self)?)
            .map_err(CircuitErrorKind::StateEncoding)?)
    }
}

pub fn checked_utxo_data<S>(state: &S) -> Result<Vec<u8>, CircuitError>
where
    S: UtxoData,
    S::Client: DataHasher,
{
    let client = S::Client::from_circuit(state)?;
    if DataHasher::hash::<Poseidon>(&client)? != to_bytes(&DataHash::hash(state)?)? {
        return Err(CircuitErrorKind::DataHashMismatch.into());
    }
    Ok(borsh::to_vec(&client).map_err(CircuitErrorKind::StateEncoding)?)
}

impl DataHash for CircuitVar {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        Ok(self.clone())
    }
}

impl DataHash for Bool {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        Ok(self.var())
    }
}

impl<const BITS: u32> DataHash for Uint<BITS> {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        Ok(self.var())
    }
}

impl DataHash for Asset {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        Asset::hash(self)
    }
}

impl<const N: usize> DataHash for Bytes<N> {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        self.hash_bytes()
    }
}

impl<T: DataHash, const N: usize> DataHash for [T; N] {
    fn hash(&self) -> Result<CircuitVar, CircuitError> {
        poseidon(
            &self
                .iter()
                .map(DataHash::hash)
                .collect::<Result<Vec<_>, _>>()?,
        )
    }
}

#[derive(Clone, Debug)]
pub(super) enum Leaves {
    State,
    Address(CircuitVar),
    Nothing,
}

#[must_use]
#[derive(Debug)]
pub struct DataUtxo<S> {
    ledger: Ledger,
    state: S,
    address: Option<CircuitVar>,
    spent: Option<SpentInput>,
    leaves: Leaves,
}

impl<S> HasLedger for DataUtxo<S> {
    fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    fn ledger_mut(&mut self) -> &mut Ledger {
        &mut self.ledger
    }

    fn is_closed(&self) -> bool {
        !matches!(self.leaves, Leaves::State)
    }
}

impl<S> Balance for DataUtxo<S> {}

impl<S: Default> DataUtxo<S> {
    pub fn new_init(owner: &Owner) -> Self {
        Self::fresh(owner, S::default(), None)
    }
}

impl<S: DataHash + Clone> DataUtxo<S> {
    #[track_caller]
    pub fn new_mut(input: &Utxo, state: &S) -> Result<Self, CircuitError> {
        Self::spend(input, state.clone(), None, Leaves::State)
    }

    #[track_caller]
    pub fn new_close(input: &Utxo, state: &S) -> Result<Self, CircuitError> {
        Self::spend(input, state.clone(), None, Leaves::Nothing)
    }
}

impl<S: DataHash> DataUtxo<S> {
    #[track_caller]
    pub(super) fn spend(
        input: &Utxo,
        state: S,
        address: Option<CircuitVar>,
        leaves: Leaves,
    ) -> Result<Self, CircuitError> {
        let _scope = Scope::open(&input.domain.cs(), "a data utxo's input");
        input
            .domain
            .assert_equal(&utxo_domain(), "the utxo is not a spendable utxo")?;
        input.assert_default_ring()?;
        input.data_hash.assert_equal(
            &data_hash(address.as_ref(), &state)?,
            "the input does not commit to its program state",
        )?;
        Ok(Self {
            ledger: Ledger::new(
                input.owner.clone(),
                input.asset.clone(),
                Accumulator::amount(&input.amount),
            ),
            state,
            address,
            // The domain check above already excludes dummies.
            spent: Some(input.spent(input.hash_with(&input.owner.hash()?, &input.asset.hash()?)?)),
            leaves,
        })
    }
}

impl<S> DataUtxo<S> {
    pub(super) fn fresh(owner: &Owner, state: S, address: Option<CircuitVar>) -> Self {
        Self {
            ledger: Ledger::new(owner.clone(), Asset::sol(), Accumulator::zero()),
            state,
            address,
            spent: None,
            leaves: Leaves::State,
        }
    }

    #[track_caller]
    pub fn with_asset(mut self, asset: &Asset) -> Result<Self, CircuitError> {
        if self.spent.is_some() || !self.ledger.is_untouched() {
            return Err(CircuitErrorKind::AssetOfUsedUtxo.into());
        }
        self.ledger.set_asset(asset);
        Ok(self)
    }

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
    #[track_caller]
    pub(crate) fn output(&self) -> Result<Option<Output>, CircuitError> {
        let balance = self.ledger.balance_var();
        let data_hash = match &self.leaves {
            Leaves::State => data_hash(self.address.as_ref(), &self.state)?,
            Leaves::Address(address) => {
                balance.assert_equal(&zero(), CLOSED_LEAVES_BALANCE)?;
                poseidon(&[
                    constant(u64::from(CLOSED_DATA_HASH_DOMAIN)),
                    address.clone(),
                ])?
            }
            Leaves::Nothing => {
                balance.assert_equal(&zero(), CLOSED_LEAVES_BALANCE)?;
                return Ok(None);
            }
        };
        Ok(Some(Output {
            owner: self.owner(),
            asset: self.asset(),
            amount: Uint::trusted(balance),
            data_hash,
            data: None,
        }))
    }
}

#[track_caller]
fn data_hash<S: DataHash>(
    address: Option<&CircuitVar>,
    state: &S,
) -> Result<CircuitVar, CircuitError> {
    match address {
        None => poseidon(&[constant(u64::from(DATA_HASH_DOMAIN)), state.hash()?]),
        Some(address) => poseidon(&[
            constant(u64::from(UNIQUE_DATA_HASH_DOMAIN)),
            address.clone(),
            state.hash()?,
        ]),
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
