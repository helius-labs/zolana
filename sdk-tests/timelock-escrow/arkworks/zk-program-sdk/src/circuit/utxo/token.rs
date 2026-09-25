use ark_r1cs_std::{eq::EqGadget, select::CondSelectGadget};
use zolana_interface::DUMMY_DOMAIN;

use super::{utxo_domain, Balance, Ledger, Output, SpentInput, Utxo};
use crate::{
    circuit::{
        constant, var::assert_equal_unless, zero, Assert, Asset, CircuitVar, Owner, PublicTransfer,
    },
    RelationError,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenLifecycle {
    Init,
    Mut,
    Burn,
}

#[must_use]
#[derive(Clone, Debug)]
pub struct TokenUtxo<const N: usize> {
    ledger: Ledger,
    spent_inputs: Vec<SpentInput>,
    lifecycle: TokenLifecycle,
}

impl TokenUtxo<0> {
    pub fn new_init(owner: &Owner, asset: &Asset) -> Self {
        Self {
            ledger: Ledger::new(owner.clone(), asset.clone(), zero()),
            spent_inputs: Vec::new(),
            lifecycle: TokenLifecycle::Init,
        }
    }
}

impl<const N: usize> Balance for TokenUtxo<N> {
    fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    fn ledger_mut(&mut self) -> &mut Ledger {
        &mut self.ledger
    }
}

impl<const N: usize> TokenUtxo<N> {
    pub fn new_mut(inputs: &[Utxo; N]) -> Result<Self, RelationError> {
        Self::spend(inputs, TokenLifecycle::Mut)
    }

    pub fn new_burn(inputs: &[Utxo; N]) -> Result<Self, RelationError> {
        Self::spend(inputs, TokenLifecycle::Burn)
    }

    pub(crate) fn spent_inputs(&self) -> &[SpentInput] {
        &self.spent_inputs
    }

    pub(crate) fn public_transfers(&self) -> &[PublicTransfer] {
        self.ledger.public_transfers()
    }

    pub(crate) fn change(&self) -> Result<Option<Output>, RelationError> {
        match self.lifecycle {
            TokenLifecycle::Init | TokenLifecycle::Mut => Ok(Some(Output {
                owner: self.ledger.owner(),
                asset: self.ledger.asset(),
                amount: self.ledger.balance(),
                data_hash: zero(),
                data: None,
            })),
            TokenLifecycle::Burn => {
                self.ledger
                    .balance()
                    .assert_equal(&zero(), "a burned token utxo leaves a balance")?;
                Ok(None)
            }
        }
    }

    fn spend(inputs: &[Utxo; N], lifecycle: TokenLifecycle) -> Result<Self, RelationError> {
        let first = inputs.first().ok_or(RelationError::Violated(
            "a token utxo spends at least one input",
        ))?;
        first
            .domain
            .assert_equal(&utxo_domain(), "the first input of a token utxo is a dummy")?;
        let owner = first.owner.hash()?;
        let asset = first.asset.hash()?;
        let mut balance = zero();
        let mut spent_inputs = Vec::with_capacity(N);
        for (index, input) in inputs.iter().enumerate() {
            let dummy = input.domain.is_eq(&constant(u64::from(DUMMY_DOMAIN)))?;
            input.assert_default_ring()?;
            input
                .data_hash
                .assert_equal(&zero(), "the input carries program state")?;
            if index > 0 {
                assert_equal_unless(
                    &input.domain,
                    &utxo_domain(),
                    &dummy,
                    "the utxo is not a spendable utxo",
                )?;
                input.asset.assert_same_unless(
                    &first.asset,
                    &dummy,
                    "the inputs hold different assets",
                )?;
                input.owner.assert_same_unless(
                    &first.owner,
                    &dummy,
                    "the inputs belong to different owners",
                )?;
            }
            balance += CircuitVar::conditionally_select(&dummy, &zero(), &input.amount)?;
            spent_inputs.push(input.spent(CircuitVar::conditionally_select(
                &dummy,
                &zero(),
                &input.hash_with(&owner, &asset)?,
            )?));
        }
        Ok(Self {
            ledger: Ledger::new(first.owner.clone(), first.asset.clone(), balance),
            spent_inputs,
            lifecycle,
        })
    }
}
