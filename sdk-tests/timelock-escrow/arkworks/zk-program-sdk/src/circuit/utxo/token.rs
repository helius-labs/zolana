use ark_r1cs_std::{eq::EqGadget, select::CondSelectGadget};
use zolana_interface::DUMMY_DOMAIN;

use super::{utxo_domain, Output, OutputTokenUtxo, Utxo};
use crate::{
    circuit::{constant, var::assert_equal_unless, zero, Assert, CircuitVar},
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
    owner: CircuitVar,
    asset: CircuitVar,
    input_hashes: Vec<CircuitVar>,
    balance: CircuitVar,
    lifecycle: TokenLifecycle,
}

impl TokenUtxo<0> {
    pub fn new_init(owner: &CircuitVar, asset: &CircuitVar) -> Self {
        Self {
            owner: owner.clone(),
            asset: asset.clone(),
            input_hashes: Vec::new(),
            balance: zero(),
            lifecycle: TokenLifecycle::Init,
        }
    }
}

impl<const N: usize> TokenUtxo<N> {
    pub fn new_mut(inputs: [Utxo; N]) -> Result<Self, RelationError> {
        Self::spend(inputs, TokenLifecycle::Mut)
    }

    pub fn new_burn(inputs: [Utxo; N]) -> Result<Self, RelationError> {
        Self::spend(inputs, TokenLifecycle::Burn)
    }

    pub fn owner(&self) -> &CircuitVar {
        &self.owner
    }

    pub fn asset(&self) -> &CircuitVar {
        &self.asset
    }

    pub fn balance(&self) -> &CircuitVar {
        &self.balance
    }

    pub fn transfer(&mut self, recipient: &CircuitVar, amount: CircuitVar) -> OutputTokenUtxo {
        self.balance -= &amount;
        OutputTokenUtxo {
            owner: recipient.clone(),
            asset: self.asset.clone(),
            amount,
        }
    }

    pub fn deposit(&mut self, amount: &CircuitVar) {
        self.balance += amount;
    }

    pub fn withdraw(&mut self, amount: &CircuitVar) {
        self.balance -= amount;
    }

    pub(crate) fn input_hashes(&self) -> &[CircuitVar] {
        &self.input_hashes
    }

    pub(crate) fn change(&self) -> Result<Option<Output>, RelationError> {
        match self.lifecycle {
            TokenLifecycle::Init | TokenLifecycle::Mut => Ok(Some(Output {
                owner: self.owner.clone(),
                asset: self.asset.clone(),
                amount: self.balance.clone(),
                data_hash: zero(),
                data: None,
            })),
            TokenLifecycle::Burn => {
                self.balance
                    .assert_equal(&zero(), "a burned token utxo leaves a balance")?;
                Ok(None)
            }
        }
    }

    fn spend(inputs: [Utxo; N], lifecycle: TokenLifecycle) -> Result<Self, RelationError> {
        let first = inputs.first().ok_or(RelationError::Violated(
            "a token utxo spends at least one input",
        ))?;
        first
            .domain
            .assert_equal(&utxo_domain(), "the first input of a token utxo is a dummy")?;
        let mut balance = zero();
        let mut input_hashes = Vec::with_capacity(N);
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
                assert_equal_unless(
                    &input.asset,
                    &first.asset,
                    &dummy,
                    "the inputs hold different assets",
                )?;
                assert_equal_unless(
                    &input.owner,
                    &first.owner,
                    &dummy,
                    "the inputs belong to different owners",
                )?;
            }
            balance += CircuitVar::conditionally_select(&dummy, &zero(), &input.amount)?;
            input_hashes.push(CircuitVar::conditionally_select(
                &dummy,
                &zero(),
                &input.hash()?,
            )?);
        }
        Ok(Self {
            owner: first.owner.clone(),
            asset: first.asset.clone(),
            input_hashes,
            balance,
            lifecycle,
        })
    }
}
