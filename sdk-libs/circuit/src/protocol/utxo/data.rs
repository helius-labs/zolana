use alloc::vec::Vec;
use core::ops::{Deref, DerefMut};
use super::{Balance, HasBalance, Output, SpentInput, Utxo, UtxoTrait};
use crate::{CircuitError, Field, UtxoOwner, ShieldedAddress, hash_bytes, poseidon, require, require_eq};
#[cfg(not(xark))]
use crate::CircuitErrorKind;
use crate::hasher::{DATA_HASH_DOMAIN, UNIQUE_DATA_HASH_DOMAIN, CLOSED_DATA_HASH_DOMAIN};
use spr_interface::UTXO_DOMAIN;

pub trait DataHash { fn hash(&self) -> Result<Field, CircuitError>; }
impl DataHash for Field { fn hash(&self) -> Result<Field, CircuitError> { Ok(*self) } }
macro_rules! integers {
    ($($t:ty),*) => {$(impl DataHash for $t { fn hash(&self) -> Result<Field, CircuitError> { Ok(Field::from(*self)) } })*};
}
integers!(u8, u16, u32, u64, u128, bool);
impl DataHash for UtxoOwner { fn hash(&self) -> Result<Field, CircuitError> { UtxoOwner::hash(self) } }
impl DataHash for ShieldedAddress { fn hash(&self) -> Result<Field, CircuitError> { ShieldedAddress::hash(self) } }
impl<const N: usize> DataHash for [u8; N] { fn hash(&self) -> Result<Field, CircuitError> { hash_bytes(self) } }

pub trait UtxoData: DataHash + crate::EncryptionCodec {
    fn utxo_data(&self) -> Result<Vec<u8>, CircuitError> {
        #[cfg(not(xark))]
        {
            let bytes = self.serialize_for_encryption().map_err(|_| CircuitErrorKind::InvalidInput("state encoding failed"))?;
            let decoded: Self = Self::deserialize_after_decryption(&bytes).map_err(|_| CircuitErrorKind::InvalidInput("state decoding failed"))?;
            if crate::to_bytes(&decoded.hash()?) != crate::to_bytes(&self.hash()?) {
                return Err(CircuitErrorKind::InvalidInput("state encoding changes its commitment").into());
            }
            Ok(bytes)
        }
        #[cfg(xark)]
        { panic!("state serialization requires native execution") }
    }
}

#[derive(Debug)]
pub(super) enum OutputState { Default, Closed(Field), None }

#[must_use]
#[derive(Debug)]
pub struct DataUtxo<S> {
    balance: Balance, state: S, address: Option<Field>, spent: Option<SpentInput>,
    output_state: OutputState, unwrapped_data_hash: bool,
}
impl<S> HasBalance for DataUtxo<S> {
    fn balance(&self) -> &Balance { &self.balance }
    fn balance_mut(&mut self) -> &mut Balance { &mut self.balance }
    fn is_closed(&self) -> bool { !matches!(self.output_state, OutputState::Default) }
}
impl<S: Default> DataUtxo<S> {
    pub fn new_init(owner: &UtxoOwner) -> Self { Self::fresh(owner, S::default(), None) }
}
impl<S: DataHash + Clone> DataUtxo<S> {
    pub fn new_mut(input: &Utxo, state: &S) -> Result<Self, CircuitError> { Self::spend(input, state.clone(), None) }
}
impl<S: DataHash> DataUtxo<S> {
    pub(super) fn spend(input: &Utxo, state: S, address: Option<Field>) -> Result<Self, CircuitError> {
        Self::spend_with_hash(input, state, address, false)
    }
    fn spend_with_hash(input: &Utxo, state: S, address: Option<Field>, unwrapped: bool) -> Result<Self, CircuitError> {
        require_eq(input.domain, UTXO_DOMAIN);
        let expected = if unwrapped { state.hash()? } else { data_hash(address.as_ref(), &state)? };
        require_eq(input.data_hash, expected);
        let owner_hash = input.owner.hash()?;
        let asset_hash = hash_bytes(&input.asset)?;
        let input_hash = input.hash_default_ring_with(&owner_hash, &asset_hash)?;
        Ok(Self { balance: Balance::new(input.owner, input.asset, u128::from(input.amount)),
            state, address, spent: Some(input.spent(input_hash)), output_state: OutputState::Default,
            unwrapped_data_hash: unwrapped })
    }
    pub fn output(&self) -> Result<Option<Output>, CircuitError> {
        let hash = match &self.output_state {
            OutputState::Default => if self.unwrapped_data_hash { self.state.hash()? } else { data_hash(self.address.as_ref(), &self.state)? },
            OutputState::Closed(address) => { require_eq(self.balance.amount, 0u128); poseidon(&[Field::from(CLOSED_DATA_HASH_DOMAIN), *address])? },
            OutputState::None => { require_eq(self.balance.amount, 0u128); return Ok(None); },
        };
        Ok(Some(Output { owner: self.owner(), asset: self.asset(), amount: self.balance.amount_u64(), data_hash: hash, data: None, empty_if_zero: false }))
    }
}
impl<S> DataUtxo<S> {
    pub fn close(self) -> Self { self.with_output_state(OutputState::None) }
    pub(super) fn with_output_state(mut self, state: OutputState) -> Self { self.output_state = state; self }
    pub(super) fn fresh(owner: &UtxoOwner, state: S, address: Option<Field>) -> Self {
        Self { balance: Balance::new(*owner, [0; 32], 0), state, address, spent: None,
            output_state: OutputState::Default, unwrapped_data_hash: false }
    }
    pub fn with_asset(mut self, asset: &[u8; 32]) -> Result<Self, CircuitError> {
        require(self.spent.is_none() && self.balance.is_untouched());
        self.balance.set_asset(asset);
        Ok(self)
    }
    pub fn spent_input(&self) -> Option<SpentInput> { self.spent }
    pub fn public_transfers(&self) -> &[crate::protocol::PublicTransfer] { &self.balance.public_transfers }
    pub fn transferred(&self) -> &Field { &self.balance.transferred }
}
impl<S> Deref for DataUtxo<S> { type Target = S; fn deref(&self) -> &S { &self.state } }
impl<S> DerefMut for DataUtxo<S> { fn deref_mut(&mut self) -> &mut S { &mut self.state } }
impl DataUtxo<Field> {
    pub fn new_init_with_hash(owner: &UtxoOwner, hash: &Field) -> Self { let mut utxo = Self::fresh(owner, *hash, None); utxo.unwrapped_data_hash = true; utxo }
    pub fn new_mut_with_hash(input: &Utxo, hash: &Field) -> Result<Self, CircuitError> { Self::spend_with_hash(input, *hash, None, true) }
}
fn data_hash<S: DataHash>(address: Option<&Field>, state: &S) -> Result<Field, CircuitError> {
    match address {
        None => poseidon(&[Field::from(DATA_HASH_DOMAIN), state.hash()?]),
        Some(address) => poseidon(&[Field::from(UNIQUE_DATA_HASH_DOMAIN), *address, state.hash()?]),
    }
}
