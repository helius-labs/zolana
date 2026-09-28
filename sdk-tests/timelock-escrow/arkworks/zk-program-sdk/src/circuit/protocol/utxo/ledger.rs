use ark_r1cs_std::boolean::Boolean;

use crate::{
    circuit::{
        builtins::field::{bits::range_check, primitive},
        labels::Scope,
        zero, Asset, Bytes, CircuitSystem, CircuitVar, Owner, PublicTransfer, Uint,
    },
    CircuitError, CircuitErrorKind,
};

const AMOUNT_BITS: u32 = 64;
const MAX_BOUNDED_BITS: u32 = 253;
const NONZERO: &str = "a public transfer moves a nonzero amount";
const BALANCE_FITS: &str = "the balance does not fit in 64 bits";

#[derive(Clone, Debug)]
pub(crate) struct Accumulator {
    var: CircuitVar,
    bits: u32,
}

impl Accumulator {
    pub(crate) fn zero() -> Self {
        Self {
            var: zero(),
            bits: 0,
        }
    }

    pub(crate) fn amount(amount: &Uint<64>) -> Self {
        Self {
            var: amount.var(),
            bits: AMOUNT_BITS,
        }
    }

    pub(crate) fn sum(amounts: &[CircuitVar]) -> Self {
        let growth = match u32::try_from(amounts.len()) {
            Ok(0 | 1) => 0,
            Ok(count) => (count - 1).ilog2() + 1,
            Err(_) => u32::MAX,
        };
        Self {
            var: primitive::sum(amounts),
            bits: AMOUNT_BITS.saturating_add(growth),
        }
    }

    pub(crate) fn var(&self) -> CircuitVar {
        self.var.clone()
    }

    fn add(&mut self, other: &Self) {
        self.var = self.var.plus(&other.var);
        self.bits = match (self.bits, other.bits) {
            (0, bits) | (bits, 0) => bits,
            (left, right) => left.max(right).saturating_add(1),
        };
    }

    #[track_caller]
    fn bounded(&self) -> Result<(), CircuitError> {
        if self.bits > MAX_BOUNDED_BITS {
            return Err(CircuitErrorKind::BitWidthTooLarge {
                bits: self.bits as usize,
            }
            .into());
        }
        Ok(())
    }

    #[track_caller]
    fn narrow(&self, rule: &'static str) -> Result<Uint<64>, CircuitError> {
        if self.bits <= AMOUNT_BITS {
            return Ok(Uint::trusted(self.var.clone()));
        }
        self.bounded()?;
        Uint::from_var(&self.var, rule)
    }

    #[track_caller]
    fn debit(&mut self, amount: &Uint<64>, rule: &'static str) -> Result<(), CircuitError> {
        self.bounded()?;
        let remaining = self.var.minus(&amount.var());
        range_check(&remaining, AMOUNT_BITS as usize, rule).map_err(|error| {
            match error.kind() {
                CircuitErrorKind::ValueTooLarge { .. } => {
                    error.replace_kind(CircuitErrorKind::RuleBroken(rule))
                }
                _ => error,
            }
        })?;
        self.var = remaining;
        self.bits = AMOUNT_BITS;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Ledger {
    owner: Owner,
    asset: Asset,
    balance: Accumulator,
    transferred: CircuitVar,
    public_transfers: Vec<PublicTransfer>,
}

impl Ledger {
    pub(super) fn new(owner: Owner, asset: Asset, balance: Accumulator) -> Self {
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

    pub(super) fn balance_var(&self) -> CircuitVar {
        self.balance.var()
    }

    fn cs(&self, amount: &Uint<64>) -> CircuitSystem {
        amount.var().cs().or(self.balance.var.cs())
    }

    fn credit(&mut self, amount: &Accumulator) {
        self.balance.add(amount);
        self.transferred = self.transferred.plus(&amount.var);
    }

    fn record_public_transfer(&mut self, is_deposit: bool, amount: &Uint<64>, account: &Bytes<32>) {
        self.public_transfers.push(PublicTransfer {
            asset: self.asset.clone(),
            is_deposit,
            amount: amount.clone(),
            account: account.clone(),
        });
    }
}

#[track_caller]
fn check_destination(asset: &Asset, destination: &impl HasLedger) -> Result<(), CircuitError> {
    if destination.is_burned() {
        return Err(CircuitErrorKind::TransferToBurnedUtxo.into());
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

    #[track_caller]
    fn balance(&self) -> Result<Uint<64>, CircuitError> {
        self.ledger().balance.narrow(BALANCE_FITS)
    }

    #[track_caller]
    fn transfer(
        &mut self,
        destination: &mut impl Balance,
        amount: &Uint<64>,
    ) -> Result<(), CircuitError> {
        let _scope = Scope::open(&self.ledger().cs(amount), "a transfer");
        check_destination(&self.ledger().asset, &*destination)?;
        let source = self.ledger_mut();
        source
            .balance
            .debit(amount, "the transfer exceeds the balance")?;
        source.transferred = source.transferred.minus(&amount.var());
        destination
            .ledger_mut()
            .credit(&Accumulator::amount(amount));
        Ok(())
    }

    #[track_caller]
    fn transfer_all(&mut self, destination: &mut impl Balance) -> Result<(), CircuitError> {
        let _scope = Scope::open(
            &self.ledger().balance.var.cs(),
            "a transfer of the whole balance",
        );
        check_destination(&self.ledger().asset, &*destination)?;
        let source = self.ledger_mut();
        let amount = core::mem::replace(&mut source.balance, Accumulator::zero());
        source.transferred = source.transferred.minus(&amount.var);
        destination.ledger_mut().credit(&amount);
        Ok(())
    }

    #[track_caller]
    fn deposit(&mut self, amount: &Uint<64>, source: &Bytes<32>) -> Result<(), CircuitError> {
        amount.assert_not_zero(NONZERO)?;
        let ledger = self.ledger_mut();
        ledger.balance.add(&Accumulator::amount(amount));
        ledger.record_public_transfer(true, amount, source);
        Ok(())
    }

    #[track_caller]
    fn withdraw(&mut self, amount: &Uint<64>, destination: &Bytes<32>) -> Result<(), CircuitError> {
        let _scope = Scope::open(&self.ledger().cs(amount), "a withdrawal");
        amount.assert_not_zero(NONZERO)?;
        let ledger = self.ledger_mut();
        ledger
            .balance
            .debit(amount, "the withdrawal exceeds the balance")?;
        ledger.record_public_transfer(false, amount, destination);
        Ok(())
    }

    #[track_caller]
    fn withdraw_all(&mut self, destination: &Bytes<32>) -> Result<Uint<64>, CircuitError> {
        let amount = self.ledger().balance.narrow(BALANCE_FITS)?;
        amount.assert_not_zero(NONZERO)?;
        let ledger = self.ledger_mut();
        ledger.balance = Accumulator::zero();
        ledger.record_public_transfer(false, &amount, destination);
        Ok(amount)
    }
}
