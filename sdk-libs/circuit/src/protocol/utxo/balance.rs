use crate::{CircuitError, Field, UtxoOwner, require};
use crate::protocol::PublicTransfer;

#[derive(Clone, Debug)]
pub struct Balance {
    used: bool,
    pub(super) owner: UtxoOwner,
    pub(super) asset: [u8; 32],
    pub(super) amount: u128,
    pub(super) transferred: Field,
    pub(super) public_transfers: Vec<PublicTransfer>,
}
impl Balance {
    pub(super) fn new(owner: UtxoOwner, asset: [u8; 32], amount: u128) -> Self {
        Self { used: false, owner, asset, amount, transferred: Field::zero(), public_transfers: Vec::new() }
    }
    pub(super) fn amount_u64(&self) -> u64 {
        require(self.amount <= u128::from(u64::MAX));
        self.amount as u64
    }
    pub(super) fn is_untouched(&self) -> bool { !self.used }
    pub(super) fn set_owner_asset(&mut self, owner: &UtxoOwner, asset: &[u8; 32]) { self.owner = *owner; self.asset = *asset; }
    pub(super) fn set_asset(&mut self, asset: &[u8; 32]) { self.asset = *asset; }
    pub(super) fn debit(&mut self, amount: u64) {
        let low = self.amount as u64;
        let high = (self.amount >> 64) as u64;
        let borrow = low < amount;
        // The borrow must consume the high word, leaving a u64 remainder.
        crate::require_eq(high, u64::from(borrow));
        self.amount = u128::from(low.wrapping_sub(amount));
        self.used = true;
    }
    fn record_public_transfer(&mut self, is_deposit: bool, amount: u64, account: [u8; 32]) {
        self.used = true;
        self.public_transfers.push(PublicTransfer { asset: self.asset, is_deposit, amount, account });
    }
}

pub trait HasBalance {
    fn balance(&self) -> &Balance;
    fn balance_mut(&mut self) -> &mut Balance;
    fn is_closed(&self) -> bool;
}

fn check_destination(asset: &[u8; 32], destination: &impl HasBalance) {
    require(!destination.is_closed());
    crate::require_eq(*asset, destination.balance().asset);
}

pub trait UtxoTrait: HasBalance {
    fn owner(&self) -> UtxoOwner { self.balance().owner }
    fn asset(&self) -> [u8; 32] { self.balance().asset }
    fn amount(&self) -> Result<u64, CircuitError> { Ok(self.balance().amount_u64()) }
    fn transfer(&mut self, destination: &mut impl UtxoTrait, amount: &u64) -> Result<(), CircuitError> {
        check_destination(&self.balance().asset, destination);
        let source = self.balance_mut();
        source.debit(*amount);
        source.transferred -= Field::from(*amount);
        let target = destination.balance_mut();
        target.amount += u128::from(*amount);
        target.transferred += Field::from(*amount);
        target.used = true;
        Ok(())
    }
    fn transfer_all(&mut self, destination: &mut impl UtxoTrait) -> Result<(), CircuitError> {
        check_destination(&self.balance().asset, destination);
        let source = self.balance_mut();
        let amount = core::mem::replace(&mut source.amount, 0);
        source.used = true;
        source.transferred -= Field::from(amount);
        let target = destination.balance_mut();
        target.amount += amount;
        target.transferred += Field::from(amount);
        target.used = true;
        Ok(())
    }
    fn deposit(&mut self, amount: &u64, source: &[u8; 32]) -> Result<(), CircuitError> {
        require(*amount != 0);
        let balance = self.balance_mut();
        balance.amount += u128::from(*amount);
        balance.record_public_transfer(true, *amount, *source);
        Ok(())
    }
    fn withdraw(&mut self, amount: &u64, destination: &[u8; 32]) -> Result<(), CircuitError> {
        require(*amount != 0);
        let balance = self.balance_mut();
        balance.debit(*amount);
        balance.record_public_transfer(false, *amount, *destination);
        Ok(())
    }
    fn withdraw_all(&mut self, destination: &[u8; 32]) -> Result<u64, CircuitError> {
        let amount = self.balance().amount_u64();
        require(amount != 0);
        let balance = self.balance_mut();
        balance.amount = 0;
        balance.record_public_transfer(false, amount, *destination);
        Ok(amount)
    }
}
impl<T: HasBalance> UtxoTrait for T {}
