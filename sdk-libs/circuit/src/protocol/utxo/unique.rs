use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use super::{DataUtxo, Utxo, DataHash, UtxoData, Balance, HasBalance, data::OutputState};
use crate::{CircuitError, Field, UtxoOwner, poseidon, require_eq};

#[derive(Clone, Copy, Debug)]
pub struct CreatedAddress { pub owner: UtxoOwner, pub seed: Field, pub address: Field }

#[must_use]
#[derive(Debug)]
pub struct UniqueDataUtxo<S> { utxo: DataUtxo<S>, address: Field, created: Option<CreatedAddress> }
impl<S> HasBalance for UniqueDataUtxo<S> {
    fn balance(&self) -> &Balance { self.utxo.balance() }
    fn balance_mut(&mut self) -> &mut Balance { self.utxo.balance_mut() }
    fn is_closed(&self) -> bool { self.utxo.is_closed() }
}
impl<S: Default> UniqueDataUtxo<S> {
    pub fn new_init(owner: &UtxoOwner, seed: &Field) -> Result<Self, CircuitError> {
        require_eq(owner.key().tag(), crate::owner::SOLANA_OWNER_TAG);
        let address = derive_address(owner, seed)?;
        Ok(Self { utxo: DataUtxo::fresh(owner, S::default(), Some(address)), address,
            created: Some(CreatedAddress { owner: *owner, seed: *seed, address }) })
    }
}
impl<S: DataHash + Clone> UniqueDataUtxo<S> {
    pub fn new_mut(input: &Utxo, address: &Field, state: &S) -> Result<Self, CircuitError> {
        Ok(Self { utxo: DataUtxo::spend(input, state.clone(), Some(*address))?, address: *address, created: None })
    }
}
impl<S> UniqueDataUtxo<S> {
    pub fn close(mut self) -> Self { self.utxo = self.utxo.with_output_state(OutputState::Closed(self.address)); self }
    pub fn burn(mut self) -> Self { self.utxo = self.utxo.close(); self }
    pub fn with_asset(mut self, asset: &[u8; 32]) -> Result<Self, CircuitError> { self.utxo = self.utxo.with_asset(asset)?; Ok(self) }
    pub fn address(&self) -> Field { self.address }
    pub fn data_utxo(&self) -> &DataUtxo<S> { &self.utxo }
    pub fn created_address(&self) -> Option<CreatedAddress> { self.created }
}
impl<S: UtxoData> UniqueDataUtxo<S> {
    pub fn utxo_data(&self) -> Result<Option<Vec<u8>>, CircuitError> {
        if self.utxo.is_closed() { return Ok(None); }
        #[cfg(not(xark))]
        {
            let mut data = crate::to_bytes(&self.address).to_vec();
            data.extend(self.utxo.utxo_data()?);
            Ok(Some(data))
        }
        #[cfg(xark)]
        { panic!("state serialization requires native execution") }
    }
}
impl<S> Deref for UniqueDataUtxo<S> { type Target = S; fn deref(&self) -> &S { &self.utxo } }
impl<S> DerefMut for UniqueDataUtxo<S> { fn deref_mut(&mut self) -> &mut S { &mut self.utxo } }

pub fn derive_address(owner: &UtxoOwner, seed: &Field) -> Result<Field, CircuitError> {
    let owner_hash = UtxoOwner::new(*owner.key(), poseidon(&[Field::zero()])?).hash()?;
    let slot = Utxo { domain: spr_interface::ADDRESS_DOMAIN, blinding: *seed,
        tree_id: spr_instruction::ADDRESS_TREE_ID, ..Utxo::default() };
    poseidon(&[slot.hash_with(&owner_hash, &Field::zero())?, *seed, Field::zero()])
}
