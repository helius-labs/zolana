use alloc::vec::Vec;
use super::{Balance, HasBalance, Output, SpentInput, Utxo, UtxoTrait};
use crate::{CircuitError, Field, UtxoOwner, hash_bytes, require, require_eq};
use spr_interface::{DUMMY_DOMAIN, UTXO_DOMAIN};

#[must_use]
#[derive(Debug)]
pub struct TokenUtxos {
    balance: Balance,
    spent_inputs: Vec<(SpentInput, bool)>,
    has_real_input: Option<bool>,
    optional: bool,
    close: bool,
    retain_zero_output: bool,
}
impl HasBalance for TokenUtxos {
    fn balance(&self) -> &Balance { &self.balance }
    fn balance_mut(&mut self) -> &mut Balance { &mut self.balance }
    fn is_closed(&self) -> bool { self.close }
}
impl TokenUtxos {
    pub fn new_init(owner: &UtxoOwner, asset: &[u8; 32]) -> Self {
        Self { balance: Balance::new(*owner, *asset, 0), spent_inputs: Vec::new(), has_real_input: None,
            optional: false, close: false, retain_zero_output: false }
    }
    pub fn new_mut(inputs: &[Utxo]) -> Result<Self, CircuitError> {
        const { assert!(usize::BITS <= 64); }
        let mut owner = inputs.first().map(|input| input.owner).unwrap_or_default();
        let mut asset = inputs.first().map(|input| input.asset).unwrap_or([0; 32]);
        let mut has_real = false;
        let mut amount = 0u128;
        for input in inputs {
            let dummy = input.domain == DUMMY_DOMAIN;
            if !dummy { require_eq(input.domain, UTXO_DOMAIN); }
            require_eq(input.data_hash, Field::zero());
            if !has_real && !dummy { owner = input.owner; asset = input.asset; }
            has_real |= !dummy;
            let contribution = if dummy { 0u64 } else { input.amount };
            // A slice has at most usize::MAX u64 values, so this sum fits u128.
            amount = amount.wrapping_add(u128::from(contribution));
        }
        let owner_hash = owner.hash()?;
        let asset_hash = hash_bytes(&asset)?;
        let mut spent_inputs = Vec::with_capacity(inputs.len());
        for input in inputs {
            let dummy = input.domain == DUMMY_DOMAIN;
            // Dummy slots must also carry the protocol's default ring.
            if dummy { input.assert_default_ring()?; }
            if !dummy { require_eq(input.owner, owner); require_eq(input.asset, asset); }
            let hash = if dummy { Field::zero() } else { input.hash_default_ring_with(&owner_hash, &asset_hash)? };
            spent_inputs.push((input.spent(hash), dummy));
        }
        Ok(Self { balance: Balance::new(owner, asset, amount), spent_inputs, has_real_input: Some(has_real),
            optional: false, close: false, retain_zero_output: false })
    }
    pub fn close(mut self) -> Self { self.close = true; self }
    pub fn with_zero_output(mut self) -> Self { self.retain_zero_output = true; self }
    pub fn with_optional(mut self, owner: &UtxoOwner, asset: &[u8; 32]) -> Self {
        require(self.balance.is_untouched());
        if let Some(true) = self.has_real_input { require_eq(self.owner(), *owner); require_eq(self.asset(), *asset); }
        self.balance.set_owner_asset(owner, asset);
        self.optional = true;
        self
    }
    pub fn spent_inputs(&self) -> &[(SpentInput, bool)] { &self.spent_inputs }
    pub fn public_transfers(&self) -> &[crate::protocol::PublicTransfer] { &self.balance.public_transfers }
    pub fn transferred(&self) -> &Field { &self.balance.transferred }
    pub fn change(self) -> Result<Option<Output>, CircuitError> {
        if !self.optional { if let Some(real) = self.has_real_input { require(real); } }
        if self.close { require_eq(self.balance.amount, 0u128); return Ok(None); }
        Ok(Some(Output { owner: self.owner(), asset: self.asset(), amount: self.balance.amount_u64(),
            data_hash: Field::zero(), data: None, empty_if_zero: !self.retain_zero_output }))
    }
}
