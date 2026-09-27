use zolana_interface::DUMMY_DOMAIN;

use super::{utxo_domain, Accumulator, Balance, HasLedger, Ledger, Output, SpentInput, Utxo};
use crate::{
    circuit::{
        constant,
        labels::Scope,
        var::{assert_equal_unless, system_of},
        zero, Assert, Asset, Bool, CircuitVar, Owner, PublicTransfer, Uint,
    },
    CircuitError, CircuitErrorKind,
};

#[must_use]
#[derive(Debug)]
pub struct TokenUtxo {
    ledger: Ledger,
    spent_inputs: Vec<SpentInput>,
    burn: bool,
}

impl HasLedger for TokenUtxo {
    fn ledger(&self) -> &Ledger {
        &self.ledger
    }

    fn ledger_mut(&mut self) -> &mut Ledger {
        &mut self.ledger
    }

    fn is_burned(&self) -> bool {
        self.burn
    }
}

impl Balance for TokenUtxo {}

impl TokenUtxo {
    pub fn new_init(owner: &Owner, asset: &Asset) -> Self {
        Self {
            ledger: Ledger::new(owner.clone(), asset.clone(), Accumulator::zero()),
            spent_inputs: Vec::new(),
            burn: false,
        }
    }

    #[track_caller]
    pub fn new_mut<const N: usize>(inputs: &[Utxo; N]) -> Result<Self, CircuitError> {
        Self::spend(inputs, false)
    }

    #[track_caller]
    pub fn new_burn<const N: usize>(inputs: &[Utxo; N]) -> Result<Self, CircuitError> {
        Self::spend(inputs, true)
    }

    pub(crate) fn spent_inputs(&self) -> &[SpentInput] {
        &self.spent_inputs
    }

    pub(crate) fn public_transfers(&self) -> &[PublicTransfer] {
        self.ledger.public_transfers()
    }

    pub(crate) fn transferred(&self) -> &CircuitVar {
        self.ledger.transferred()
    }

    #[track_caller]
    pub(crate) fn change(&self) -> Result<Option<Output>, CircuitError> {
        let balance = self.ledger.balance_var();
        if self.burn {
            balance.assert_equal(&zero(), "a burned token utxo leaves a balance")?;
            return Ok(None);
        }
        Ok(Some(Output {
            owner: self.owner(),
            asset: self.asset(),
            amount: Uint::trusted(balance),
            data_hash: zero(),
            data: None,
        }))
    }

    #[track_caller]
    fn spend(inputs: &[Utxo], burn: bool) -> Result<Self, CircuitError> {
        let _scope = Scope::open(
            &system_of(inputs.iter().map(|input| &input.domain)),
            "a token utxo's inputs",
        );
        let first = inputs.first().ok_or(CircuitErrorKind::RuleBroken(
            "a token utxo spends at least one input",
        ))?;
        first
            .domain
            .assert_equal(&utxo_domain(), "the first input of a token utxo is a dummy")?;
        let owner = first.owner.hash()?;
        let asset = first.asset.hash()?;
        let mut amounts = Vec::with_capacity(inputs.len());
        let mut spent_inputs = Vec::with_capacity(inputs.len());
        for (index, input) in inputs.iter().enumerate() {
            let dummy = input.domain.equals(&constant(u64::from(DUMMY_DOMAIN)))?;
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
                input
                    .owner
                    .assert_no_nullifier_key_if(&dummy, "a dummy input carries a nullifier key")?;
            }
            let dummy = Bool::from_checked(CircuitVar::from_boolean(dummy));
            amounts.push(dummy.select(&zero(), &input.amount.var()));
            spent_inputs
                .push(input.spent(dummy.select(&zero(), &input.hash_with(&owner, &asset)?)));
        }
        Ok(Self {
            ledger: Ledger::new(
                first.owner.clone(),
                first.asset.clone(),
                Accumulator::sum(&amounts),
            ),
            spent_inputs,
            burn,
        })
    }
}
