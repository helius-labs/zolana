use ark_r1cs_std::{eq::EqGadget, select::CondSelectGadget};
use zolana_interface::DUMMY_DOMAIN;

use super::{utxo_domain, Output, OutputTokenUtxo, Utxo};
use crate::{
    circuit::{
        constant, var::assert_equal_unless, zero, Assert, Asset, Bytes, CircuitVar, Owner,
        PublicTransfer,
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
    owner: Owner,
    asset: Asset,
    input_hashes: Vec<CircuitVar>,
    balance: CircuitVar,
    lifecycle: TokenLifecycle,
    public_transfers: Vec<PublicTransfer>,
}

impl TokenUtxo<0> {
    pub fn new_init(owner: &Owner, asset: &Asset) -> Self {
        Self {
            owner: owner.clone(),
            asset: asset.clone(),
            input_hashes: Vec::new(),
            balance: zero(),
            lifecycle: TokenLifecycle::Init,
            public_transfers: Vec::new(),
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

    pub fn owner(&self) -> &Owner {
        &self.owner
    }

    pub fn asset(&self) -> &Asset {
        &self.asset
    }

    pub fn balance(&self) -> &CircuitVar {
        &self.balance
    }

    pub fn transfer(&mut self, recipient: &Owner, amount: CircuitVar) -> OutputTokenUtxo {
        self.balance -= &amount;
        OutputTokenUtxo {
            owner: recipient.clone(),
            asset: self.asset.clone(),
            amount,
        }
    }

    pub fn deposit(&mut self, amount: &CircuitVar, source: &Bytes<32>) {
        self.balance += amount;
        self.record_public_transfer(true, amount, source);
    }

    pub fn withdraw(&mut self, amount: &CircuitVar, destination: &Bytes<32>) {
        self.balance -= amount;
        self.record_public_transfer(false, amount, destination);
    }

    pub(crate) fn input_hashes(&self) -> &[CircuitVar] {
        &self.input_hashes
    }

    pub(crate) fn public_transfers(&self) -> &[PublicTransfer] {
        &self.public_transfers
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

    fn spend(inputs: [Utxo; N], lifecycle: TokenLifecycle) -> Result<Self, RelationError> {
        let first = inputs.first().ok_or(RelationError::Violated(
            "a token utxo spends at least one input",
        ))?;
        first
            .domain
            .assert_equal(&utxo_domain(), "the first input of a token utxo is a dummy")?;
        let owner = first.owner.hash()?;
        let asset = first.asset.hash()?;
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
            input_hashes.push(CircuitVar::conditionally_select(
                &dummy,
                &zero(),
                &input.hash_with(&owner, &asset)?,
            )?);
        }
        Ok(Self {
            owner: first.owner.clone(),
            asset: first.asset.clone(),
            input_hashes,
            balance,
            lifecycle,
            public_transfers: Vec::new(),
        })
    }
}
