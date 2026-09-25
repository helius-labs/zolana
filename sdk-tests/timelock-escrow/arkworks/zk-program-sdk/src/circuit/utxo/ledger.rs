use ark_ff::Zero;
use ark_r1cs_std::boolean::Boolean;

use crate::{
    circuit::{zero, Assert, Asset, Bytes, CircuitVar, Owner, PublicTransfer},
    RelationError,
};

#[derive(Debug)]
pub struct Ledger {
    owner: Owner,
    asset: Asset,
    balance: CircuitVar,
    transferred: CircuitVar,
    public_transfers: Vec<PublicTransfer>,
}

impl Ledger {
    pub(super) fn new(owner: Owner, asset: Asset, balance: CircuitVar) -> Self {
        Self {
            owner,
            asset,
            balance,
            transferred: zero(),
            public_transfers: Vec::new(),
        }
    }

    pub(super) fn public_transfers(&self) -> &[PublicTransfer] {
        &self.public_transfers
    }

    pub(super) fn transferred(&self) -> &CircuitVar {
        &self.transferred
    }

    fn debit(&mut self, amount: &CircuitVar, rule: &'static str) -> Result<(), RelationError> {
        let remaining = self.balance.clone() - amount;
        assert_u64(&remaining, rule)?;
        self.balance = remaining;
        Ok(())
    }

    fn credit(&mut self, amount: &CircuitVar) {
        self.balance += amount;
        self.transferred += amount;
    }

    fn record_public_transfer(
        &mut self,
        is_deposit: bool,
        amount: &CircuitVar,
        account: &Bytes<32>,
    ) {
        self.public_transfers.push(PublicTransfer {
            asset: self.asset.clone(),
            is_deposit,
            amount: amount.clone(),
            account: account.clone(),
        });
    }
}

fn refuse_zero(amount: &CircuitVar) -> Result<(), RelationError> {
    match amount {
        CircuitVar::Constant(value) if value.is_zero() => Err(RelationError::Violated(
            "a public transfer moves a nonzero amount",
        )),
        _ => Ok(()),
    }
}

fn assert_u64(value: &CircuitVar, rule: &'static str) -> Result<(), RelationError> {
    value.check_bits(64).map_err(|error| match error {
        RelationError::OutOfRange(_) => RelationError::Violated(rule),
        error => error,
    })
}

fn check_destination(asset: &Asset, destination: &impl HasLedger) -> Result<(), RelationError> {
    if destination.is_burned() {
        return Err(RelationError::Violated(
            "a burned utxo receives no transfer",
        ));
    }
    let held = &destination.ledger().asset;
    if asset.is_clone_of(held) {
        return Ok(());
    }
    asset.assert_same_unless(held, &Boolean::FALSE, "the destination holds another asset")
}

pub trait HasLedger {
    fn ledger(&self) -> &Ledger;

    fn ledger_mut(&mut self) -> &mut Ledger;

    fn is_burned(&self) -> bool;
}

pub trait Balance: HasLedger {
    fn owner(&self) -> Owner {
        self.ledger().owner.clone()
    }

    fn asset(&self) -> Asset {
        self.ledger().asset.clone()
    }

    fn balance(&self) -> CircuitVar {
        self.ledger().balance.clone()
    }

    fn transfer(
        &mut self,
        destination: &mut impl Balance,
        amount: &CircuitVar,
    ) -> Result<(), RelationError> {
        check_destination(&self.ledger().asset, &*destination)?;
        assert_u64(amount, "the transfer amount is not a u64")?;
        let source = self.ledger_mut();
        source.debit(amount, "the transfer exceeds the balance")?;
        source.transferred -= amount;
        destination.ledger_mut().credit(amount);
        Ok(())
    }

    fn transfer_all(&mut self, destination: &mut impl Balance) -> Result<(), RelationError> {
        check_destination(&self.ledger().asset, &*destination)?;
        let source = self.ledger_mut();
        let amount = core::mem::replace(&mut source.balance, zero());
        source.transferred -= &amount;
        destination.ledger_mut().credit(&amount);
        Ok(())
    }

    fn deposit(&mut self, amount: &CircuitVar, source: &Bytes<32>) -> Result<(), RelationError> {
        refuse_zero(amount)?;
        let ledger = self.ledger_mut();
        ledger.balance += amount;
        ledger.record_public_transfer(true, amount, source);
        Ok(())
    }

    fn withdraw(
        &mut self,
        amount: &CircuitVar,
        destination: &Bytes<32>,
    ) -> Result<(), RelationError> {
        refuse_zero(amount)?;
        let ledger = self.ledger_mut();
        ledger.debit(amount, "the withdrawal exceeds the balance")?;
        ledger.record_public_transfer(false, amount, destination);
        Ok(())
    }

    fn withdraw_all(&mut self, destination: &Bytes<32>) -> Result<CircuitVar, RelationError> {
        let ledger = self.ledger_mut();
        refuse_zero(&ledger.balance)?;
        let amount = core::mem::replace(&mut ledger.balance, zero());
        ledger.record_public_transfer(false, &amount, destination);
        Ok(amount)
    }
}
