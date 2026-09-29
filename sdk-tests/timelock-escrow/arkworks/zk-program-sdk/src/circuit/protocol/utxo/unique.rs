use core::ops::{Deref, DerefMut};

use zolana_interface::ADDRESS_DOMAIN;
use zolana_program::ADDRESS_TREE_ID;

use super::{data::Leaves, Balance, DataUtxo, HasBalance, Utxo, UtxoData, UtxoTrait};
use crate::{
    circuit::{
        builtins::field::var::system_of, constant, labels::Scope, poseidon, zero, Asset,
        CircuitVar, DataHash, Owner,
    },
    conversion::to_bytes,
    CircuitError,
};

#[must_use]
#[derive(Debug)]
pub struct UniqueDataUtxo<S> {
    utxo: DataUtxo<S>,
    address: CircuitVar,
    creates_address: bool,
}

impl<S> HasBalance for UniqueDataUtxo<S> {
    fn balance(&self) -> &Balance {
        self.utxo.balance()
    }

    fn balance_mut(&mut self) -> &mut Balance {
        self.utxo.balance_mut()
    }

    fn is_closed(&self) -> bool {
        self.utxo.is_closed()
    }
}

impl<S> UtxoTrait for UniqueDataUtxo<S> {}

impl<S: Default> UniqueDataUtxo<S> {
    #[track_caller]
    pub fn new_init(owner: &Owner) -> Result<Self, CircuitError> {
        let address = derive_address(owner)?;
        Ok(Self {
            utxo: DataUtxo::fresh(owner, S::default(), Some(address.clone())),
            address,
            creates_address: true,
        })
    }
}

impl<S: DataHash + Clone> UniqueDataUtxo<S> {
    #[track_caller]
    pub fn new_mut(input: &Utxo, address: &CircuitVar, state: &S) -> Result<Self, CircuitError> {
        Self::spend(input, address, state, Leaves::State)
    }

    #[track_caller]
    pub fn new_close(input: &Utxo, address: &CircuitVar, state: &S) -> Result<Self, CircuitError> {
        Self::spend(input, address, state, Leaves::Address(address.clone()))
    }

    #[track_caller]
    pub fn new_burn(input: &Utxo, address: &CircuitVar, state: &S) -> Result<Self, CircuitError> {
        Self::spend(input, address, state, Leaves::Nothing)
    }

    #[track_caller]
    fn spend(
        input: &Utxo,
        address: &CircuitVar,
        state: &S,
        leaves: Leaves,
    ) -> Result<Self, CircuitError> {
        Ok(Self {
            utxo: DataUtxo::spend(input, state.clone(), Some(address.clone()), leaves)?,
            address: address.clone(),
            creates_address: false,
        })
    }
}

impl<S> UniqueDataUtxo<S> {
    #[track_caller]
    pub fn with_asset(mut self, asset: &Asset) -> Result<Self, CircuitError> {
        self.utxo = self.utxo.with_asset(asset)?;
        Ok(self)
    }

    pub fn address(&self) -> CircuitVar {
        self.address.clone()
    }

    pub(crate) fn data_utxo(&self) -> &DataUtxo<S> {
        &self.utxo
    }

    pub(crate) fn created_address(&self) -> Option<CircuitVar> {
        self.creates_address.then(|| self.address())
    }
}

impl<S: UtxoData> UniqueDataUtxo<S> {
    pub(crate) fn utxo_data(&self) -> Result<Option<Vec<u8>>, CircuitError> {
        if self.utxo.is_closed() {
            return Ok(None);
        }
        let mut data = to_bytes(&self.address)?.to_vec();
        data.extend(self.utxo.utxo_data()?);
        Ok(Some(data))
    }
}

#[track_caller]
fn derive_address(owner: &Owner) -> Result<CircuitVar, CircuitError> {
    let _scope = Scope::open(
        &system_of([owner.key().tag()]),
        "a unique data utxo's address",
    );
    let seed = owner.key().identity()?;
    let owner_hash = Owner::new(owner.key().clone(), poseidon(&[zero()])?).hash()?;
    let slot = Utxo {
        domain: constant(u64::from(ADDRESS_DOMAIN)),
        blinding: seed.clone(),
        tree_id: constant(u64::from(ADDRESS_TREE_ID)),
        ..Utxo::default()
    };
    poseidon(&[slot.hash_with(&owner_hash, &zero())?, seed, zero()])
}

impl<S> Deref for UniqueDataUtxo<S> {
    type Target = S;

    fn deref(&self) -> &S {
        &self.utxo
    }
}

impl<S> DerefMut for UniqueDataUtxo<S> {
    fn deref_mut(&mut self) -> &mut S {
        &mut self.utxo
    }
}
