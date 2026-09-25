use ark_ff::Zero;
use ark_r1cs_std::boolean::Boolean;

use super::OutputTokenUtxo;
use crate::{
    circuit::{var::subtract_within, zero, Asset, Bytes, CircuitVar, Owner, PublicTransfer},
    RelationError,
};

#[derive(Debug)]
pub struct Ledger {
    owner: Owner,
    asset: Asset,
    balance: CircuitVar,
    public_transfers: Vec<PublicTransfer>,
}

impl Ledger {
    pub(super) fn new(owner: Owner, asset: Asset, balance: CircuitVar) -> Self {
        Self {
            owner,
            asset,
            balance,
            public_transfers: Vec::new(),
        }
    }

    pub(super) fn public_transfers(&self) -> &[PublicTransfer] {
        &self.public_transfers
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

pub trait HasLedger {
    fn ledger(&self) -> &Ledger;

    fn ledger_mut(&mut self) -> &mut Ledger;
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
        recipient: &Owner,
        amount: &CircuitVar,
    ) -> Result<OutputTokenUtxo, RelationError> {
        let ledger = self.ledger_mut();
        ledger.balance =
            subtract_within(&ledger.balance, amount, "the transfer exceeds the balance")?;
        Ok(ledger.output(recipient, amount.clone()))
    }

    fn transfer_all(&mut self, recipient: &Owner) -> OutputTokenUtxo {
        let ledger = self.ledger_mut();
        let amount = core::mem::replace(&mut ledger.balance, zero());
        ledger.output(recipient, amount)
    }

    fn receive(&mut self, output: OutputTokenUtxo) -> Result<(), RelationError> {
        let ledger = self.ledger_mut();
        output.asset.assert_same_unless(
            &ledger.asset,
            &Boolean::FALSE,
            "the received output holds another asset",
        )?;
        ledger.balance += &output.amount;
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
        ledger.balance = subtract_within(
            &ledger.balance,
            amount,
            "the withdrawal exceeds the balance",
        )?;
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
