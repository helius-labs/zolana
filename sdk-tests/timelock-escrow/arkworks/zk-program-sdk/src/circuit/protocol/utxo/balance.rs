use ark_r1cs_std::boolean::Boolean;

use crate::{
    circuit::{
        builtins::{field::primitive, types::uint::ceil_log2},
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
pub(crate) struct Amount {
    var: CircuitVar,
    bits: u32,
}

impl From<&Uint<64>> for Amount {
    fn from(amount: &Uint<64>) -> Self {
        Self {
            var: amount.var(),
            bits: AMOUNT_BITS,
        }
    }
}

impl Amount {
    pub(crate) fn zero() -> Self {
        Self {
            var: zero(),
            bits: 0,
        }
    }

    pub(crate) fn sum(amounts: &[CircuitVar]) -> Self {
        Self {
            var: primitive::sum(amounts),
            bits: AMOUNT_BITS.saturating_add(ceil_log2(amounts.len())),
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
        let remaining = Uint::<64>::from_var(&self.var.minus(&amount.var()), rule)?;
        *self = Self::from(&remaining);
        Ok(())
    }
}

#[derive(Debug)]
pub struct Balance {
    owner: Owner,
    asset: Asset,
    amount: Amount,
    transferred: CircuitVar,
    public_transfers: Vec<PublicTransfer>,
}

impl Balance {
    pub(super) fn new(owner: Owner, asset: Asset, amount: Amount) -> Self {
        Self {
            owner,
            asset,
            amount,
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

    pub(super) fn amount_var(&self) -> CircuitVar {
        self.amount.var()
    }

    pub(super) fn is_untouched(&self) -> bool {
        self.amount.bits == 0 && self.public_transfers.is_empty()
    }

    pub(super) fn set_asset(&mut self, asset: &Asset) {
        self.asset = asset.clone();
    }

    fn cs(&self, amount: &Uint<64>) -> CircuitSystem {
        amount.var().cs().or(self.amount.var.cs())
    }

    fn credit(&mut self, amount: &Amount) {
        self.amount.add(amount);
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
fn check_destination(asset: &Asset, destination: &impl HasBalance) -> Result<(), CircuitError> {
    if destination.is_closed() {
        return Err(CircuitErrorKind::TransferToClosedUtxo.into());
    }
    let held = &destination.balance().asset;
    if asset.is_clone_of(held) {
        return Ok(());
    }
    asset.assert_same_unless(held, &Boolean::FALSE, "the destination holds another asset")
}

pub trait HasBalance {
    fn balance(&self) -> &Balance;

    fn balance_mut(&mut self) -> &mut Balance;

    fn is_closed(&self) -> bool;
}

pub trait UtxoTrait: HasBalance {
    fn owner(&self) -> Owner {
        self.balance().owner.clone()
    }

    fn asset(&self) -> Asset {
        self.balance().asset.clone()
    }

    #[track_caller]
    fn amount(&self) -> Result<Uint<64>, CircuitError> {
        self.balance().amount.narrow(BALANCE_FITS)
    }

    #[track_caller]
    fn transfer(
        &mut self,
        destination: &mut impl UtxoTrait,
        amount: &Uint<64>,
    ) -> Result<(), CircuitError> {
        let _scope = Scope::open(&self.balance().cs(amount), "a transfer");
        check_destination(&self.balance().asset, &*destination)?;
        let source = self.balance_mut();
        source
            .amount
            .debit(amount, "the transfer exceeds the balance")?;
        source.transferred = source.transferred.minus(&amount.var());
        destination.balance_mut().credit(&Amount::from(amount));
        Ok(())
    }

    #[track_caller]
    fn transfer_all(&mut self, destination: &mut impl UtxoTrait) -> Result<(), CircuitError> {
        let _scope = Scope::open(
            &self.balance().amount.var.cs(),
            "a transfer of the whole balance",
        );
        check_destination(&self.balance().asset, &*destination)?;
        let source = self.balance_mut();
        let amount = core::mem::replace(&mut source.amount, Amount::zero());
        source.transferred = source.transferred.minus(&amount.var);
        destination.balance_mut().credit(&amount);
        Ok(())
    }

    #[track_caller]
    fn deposit(&mut self, amount: &Uint<64>, source: &Bytes<32>) -> Result<(), CircuitError> {
        amount.assert_not_zero(NONZERO)?;
        let balance = self.balance_mut();
        balance.amount.add(&Amount::from(amount));
        balance.record_public_transfer(true, amount, source);
        Ok(())
    }

    #[track_caller]
    fn withdraw(&mut self, amount: &Uint<64>, destination: &Bytes<32>) -> Result<(), CircuitError> {
        let _scope = Scope::open(&self.balance().cs(amount), "a withdrawal");
        amount.assert_not_zero(NONZERO)?;
        let balance = self.balance_mut();
        balance
            .amount
            .debit(amount, "the withdrawal exceeds the balance")?;
        balance.record_public_transfer(false, amount, destination);
        Ok(())
    }

    #[track_caller]
    fn withdraw_all(&mut self, destination: &Bytes<32>) -> Result<Uint<64>, CircuitError> {
        let amount = self.balance().amount.narrow(BALANCE_FITS)?;
        amount.assert_not_zero(NONZERO)?;
        let balance = self.balance_mut();
        balance.amount = Amount::zero();
        balance.record_public_transfer(false, &amount, destination);
        Ok(amount)
    }
}
