use ark_ff::Zero;
use ark_r1cs_std::boolean::Boolean;

use super::OutputTokenUtxo;
use crate::{
    circuit::{var::subtract_within, zero, Asset, Bytes, CircuitVar, Owner, PublicTransfer},
    RelationError,
};

#[derive(Clone, Debug)]
pub struct Ledger {
    owner: Owner,
    asset: Asset,
    balance: CircuitVar,
    public_transfers: Vec<PublicTransfer>,
}

impl Ledger {
    pub(crate) fn new(owner: Owner, asset: Asset, balance: CircuitVar) -> Self {
        Self {
            owner,
            asset,
            balance,
            public_transfers: Vec::new(),
        }
    }

    pub(crate) fn public_transfers(&self) -> &[PublicTransfer] {
        &self.public_transfers
    }

    pub fn owner(&self) -> Owner {
        self.owner.clone()
    }

    pub fn asset(&self) -> Asset {
        self.asset.clone()
    }

    pub fn balance(&self) -> CircuitVar {
        self.balance.clone()
    }

    pub fn transfer(
        &mut self,
        recipient: &Owner,
        amount: &CircuitVar,
    ) -> Result<OutputTokenUtxo, RelationError> {
        self.balance = subtract_within(&self.balance, amount, "the transfer exceeds the balance")?;
        Ok(self.output(recipient, amount.clone()))
    }

    pub fn transfer_all(&mut self, recipient: &Owner) -> OutputTokenUtxo {
        let amount = core::mem::replace(&mut self.balance, zero());
        self.output(recipient, amount)
    }

    pub fn receive(&mut self, output: OutputTokenUtxo) -> Result<(), RelationError> {
        output.asset.assert_same_unless(
            &self.asset,
            &Boolean::FALSE,
            "the received output holds another asset",
        )?;
        self.balance += &output.amount;
        Ok(())
    }

    pub fn deposit(
        &mut self,
        amount: &CircuitVar,
        source: &Bytes<32>,
    ) -> Result<(), RelationError> {
        refuse_zero(amount)?;
        self.balance += amount;
        self.record_public_transfer(true, amount, source);
        Ok(())
    }

    pub fn withdraw(
        &mut self,
        amount: &CircuitVar,
        destination: &Bytes<32>,
    ) -> Result<(), RelationError> {
        refuse_zero(amount)?;
        self.balance =
            subtract_within(&self.balance, amount, "the withdrawal exceeds the balance")?;
        self.record_public_transfer(false, amount, destination);
        Ok(())
    }

    pub fn withdraw_all(&mut self, destination: &Bytes<32>) -> Result<CircuitVar, RelationError> {
        refuse_zero(&self.balance)?;
        let amount = core::mem::replace(&mut self.balance, zero());
        self.record_public_transfer(false, &amount, destination);
        Ok(amount)
    }

    fn output(&self, recipient: &Owner, amount: CircuitVar) -> OutputTokenUtxo {
        OutputTokenUtxo {
            owner: recipient.clone(),
            asset: self.asset.clone(),
            amount,
        }
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

pub trait Balance {
    fn ledger(&self) -> &Ledger;

    fn ledger_mut(&mut self) -> &mut Ledger;

    fn owner(&self) -> Owner {
        self.ledger().owner()
    }

    fn asset(&self) -> Asset {
        self.ledger().asset()
    }

    fn balance(&self) -> CircuitVar {
        self.ledger().balance()
    }

    fn transfer(
        &mut self,
        recipient: &Owner,
        amount: &CircuitVar,
    ) -> Result<OutputTokenUtxo, RelationError> {
        self.ledger_mut().transfer(recipient, amount)
    }

    fn transfer_all(&mut self, recipient: &Owner) -> OutputTokenUtxo {
        self.ledger_mut().transfer_all(recipient)
    }

    fn receive(&mut self, output: OutputTokenUtxo) -> Result<(), RelationError> {
        self.ledger_mut().receive(output)
    }

    fn deposit(&mut self, amount: &CircuitVar, source: &Bytes<32>) -> Result<(), RelationError> {
        self.ledger_mut().deposit(amount, source)
    }

    fn withdraw(
        &mut self,
        amount: &CircuitVar,
        destination: &Bytes<32>,
    ) -> Result<(), RelationError> {
        self.ledger_mut().withdraw(amount, destination)
    }

    fn withdraw_all(&mut self, destination: &Bytes<32>) -> Result<CircuitVar, RelationError> {
        self.ledger_mut().withdraw_all(destination)
    }
}
