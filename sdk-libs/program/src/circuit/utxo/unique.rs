use core::ops::{Deref, DerefMut};

use zolana_instruction::ADDRESS_TREE_ID;
use zolana_interface::ADDRESS_DOMAIN;

use super::{data::OutputState, Balance, DataUtxo, HasBalance, Utxo, UtxoData};
use crate::{
    circuit::{
        builtins::field::var::system_of, constant, labels::Scope, poseidon, zero, Assert,
        CircuitVar, DataHash, SolanaAddress, UtxoOwner,
    },
    conversion::to_bytes,
    CircuitError,
};

#[must_use]
#[derive(Debug)]
pub struct UniqueDataUtxo<S> {
    utxo: DataUtxo<S>,
    address: CircuitVar,
    created: Option<CreatedAddress>,
}

#[derive(Clone, Debug)]
pub(crate) struct CreatedAddress {
    pub(crate) owner: UtxoOwner,
    pub(crate) seed: CircuitVar,
    pub(crate) address: CircuitVar,
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

impl<S: Default> UniqueDataUtxo<S> {
    #[track_caller]
    /// The seed scopes the address within the owner. Derive it from the
    /// program id and account identifier to separate applications and accounts.
    pub fn new_init(owner: &UtxoOwner, seed: &CircuitVar) -> Result<Self, CircuitError> {
        owner.key().tag().assert_equal(
            &constant(u64::from(zolana_hasher::primitives::SOLANA_OWNER_TAG)),
            "an address owner must be a Solana signer",
        )?;
        let address = derive_address(owner, seed)?;
        Ok(Self {
            utxo: DataUtxo::fresh(owner, S::default(), Some(address.clone())),
            created: Some(CreatedAddress {
                owner: owner.clone(),
                seed: seed.clone(),
                address: address.clone(),
            }),
            address,
        })
    }
}

impl<S: DataHash + Clone> UniqueDataUtxo<S> {
    #[track_caller]
    pub fn new_mut(input: &Utxo, address: &CircuitVar, state: &S) -> Result<Self, CircuitError> {
        Ok(Self {
            utxo: DataUtxo::spend(input, state.clone(), Some(address.clone()))?,
            address: address.clone(),
            created: None,
        })
    }
}

impl<S> UniqueDataUtxo<S> {
    /// Requires a final balance of zero and leaves an address tombstone.
    /// Transfers into the UTXO are rejected after it is closed.
    pub fn close(mut self) -> Self {
        self.utxo = self
            .utxo
            .with_output_state(OutputState::Closed(self.address.clone()));
        self
    }

    /// Requires a final balance of zero and produces no output.
    /// Transfers into the UTXO are rejected after it is burned.
    pub fn burn(mut self) -> Self {
        self.utxo = self.utxo.close();
        self
    }

    #[track_caller]
    pub fn with_asset(mut self, asset: &SolanaAddress) -> Result<Self, CircuitError> {
        self.utxo = self.utxo.with_asset(asset)?;
        Ok(self)
    }

    pub fn address(&self) -> CircuitVar {
        self.address.clone()
    }

    pub(crate) fn data_utxo(&self) -> &DataUtxo<S> {
        &self.utxo
    }

    pub(crate) fn created_address(&self) -> Option<CreatedAddress> {
        self.created.clone()
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
pub(crate) fn derive_address(
    owner: &UtxoOwner,
    seed: &CircuitVar,
) -> Result<CircuitVar, CircuitError> {
    let _scope = Scope::open(
        &system_of([owner.key().tag()]),
        "a unique data utxo's address",
    );
    let owner_hash = UtxoOwner::new(owner.key().clone(), poseidon(&[zero()])?).hash()?;
    let slot = Utxo {
        domain: constant(u64::from(ADDRESS_DOMAIN)),
        blinding: seed.clone(),
        tree_id: constant(u64::from(ADDRESS_TREE_ID)),
        ..Utxo::default()
    };
    poseidon(&[slot.hash_with(&owner_hash, &zero())?, seed.clone(), zero()])
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
