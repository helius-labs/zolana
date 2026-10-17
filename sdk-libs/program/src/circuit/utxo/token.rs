use zolana_interface::DUMMY_DOMAIN;

use super::{utxo_domain, Amount, Balance, HasBalance, Output, SpentInput, Utxo, UtxoTrait};
use crate::{
    circuit::{
        builtins::field::var::system_of, constant, labels::Scope, zero, Assert, Asset, Bool,
        CircuitVar, Owner, PublicTransfer,
    },
    CircuitError, CircuitErrorKind,
};

#[must_use]
#[derive(Debug)]
pub struct TokenUtxos {
    balance: Balance,
    spent_inputs: Vec<SpentInput>,
    close: bool,
    retain_zero_output: bool,
}

impl HasBalance for TokenUtxos {
    fn balance(&self) -> &Balance {
        &self.balance
    }

    fn balance_mut(&mut self) -> &mut Balance {
        &mut self.balance
    }

    fn is_closed(&self) -> bool {
        self.close
    }
}

impl TokenUtxos {
    pub fn new_init(owner: &Owner, asset: &Asset) -> Self {
        Self {
            balance: Balance::new(owner.clone(), asset.clone(), Amount::zero()),
            spent_inputs: Vec::new(),
            close: false,
            retain_zero_output: false,
        }
    }

    /// Must be of the same asset and the same owner and same nullifier key -> same owner hash.
    #[track_caller]
    pub fn new_mut<const N: usize>(inputs: &[Utxo; N]) -> Result<Self, CircuitError> {
        Self::spend(inputs, false)
    }

    #[track_caller]
    pub fn new_close<const N: usize>(inputs: &[Utxo; N]) -> Result<Self, CircuitError> {
        Self::spend(inputs, true)
    }

    /// A real, encrypted token output even when its amount is zero.
    pub fn with_zero_output(mut self) -> Self {
        self.retain_zero_output = true;
        self
    }

    /// An optional plain deposit. A dummy contributes no value or commitment;
    /// a real input must have the specified owner and asset.
    #[track_caller]
    pub fn new_optional_close(
        input: &Utxo,
        owner: &Owner,
        asset: &Asset,
    ) -> Result<Self, CircuitError> {
        let dummy = input.domain.is_equal(&constant(u64::from(DUMMY_DOMAIN)))?;
        input.domain.assert_equal_if(
            &utxo_domain(),
            &dummy.not(),
            "an optional token input is spendable",
        )?;
        input.assert_default_ring()?;
        input
            .data_hash
            .assert_equal(&zero(), "a token input carries no program state")?;
        input.owner.assert_equal_if(
            owner,
            &dummy.not(),
            "a deposit belongs to its program owner",
        )?;
        input
            .asset
            .assert_equal_if(asset, &dummy.not(), "a deposit has its expected asset")?;
        let hash = dummy.select(&zero(), &input.hash_with(&owner.hash()?, &asset.hash()?)?);
        let amount = dummy.select(&zero(), &input.amount.var());
        Ok(Self {
            balance: Balance::new(owner.clone(), asset.clone(), Amount::sum(&[amount])),
            spent_inputs: vec![input.spent(hash)],
            close: true,
            retain_zero_output: false,
        })
    }

    pub(crate) fn order_optional(
        mut first: Self,
        mut second: Self,
    ) -> Result<(Self, Self), CircuitError> {
        if first.spent_inputs.len() != 1 || second.spent_inputs.len() != 1 {
            return Err(CircuitErrorKind::RuleBroken(
                "an optional token group has exactly one input",
            )
            .into());
        }
        let first_input =
            first
                .spent_inputs
                .first()
                .cloned()
                .ok_or(CircuitErrorKind::RuleBroken(
                    "the first optional input exists",
                ))?;
        let second_input =
            second
                .spent_inputs
                .first()
                .cloned()
                .ok_or(CircuitErrorKind::RuleBroken(
                    "the second optional input exists",
                ))?;
        let second_first = first_input
            .hash
            .is_equal(&zero())?
            .and(&second_input.hash.is_equal(&zero())?.not());
        let select = |left: &SpentInput, right: &SpentInput| SpentInput {
            hash: second_first.select(&left.hash, &right.hash),
            meta: crate::circuit::UtxoMeta {
                nullifier: second_first.select(&left.meta.nullifier, &right.meta.nullifier),
                latest_tree_id: second_first
                    .select(&left.meta.latest_tree_id, &right.meta.latest_tree_id),
                has_latest_tree_id: second_first.select(
                    &left.meta.has_latest_tree_id,
                    &right.meta.has_latest_tree_id,
                ),
            },
        };
        first.spent_inputs = vec![select(&second_input, &first_input)];
        second.spent_inputs = vec![select(&first_input, &second_input)];
        Ok((first, second))
    }

    pub(crate) fn spent_inputs(&self) -> &[SpentInput] {
        &self.spent_inputs
    }

    pub(crate) fn public_transfers(&self) -> &[PublicTransfer] {
        self.balance.public_transfers()
    }

    pub(crate) fn transferred(&self) -> &CircuitVar {
        self.balance.transferred()
    }

    #[track_caller]
    pub(crate) fn change(&self) -> Result<Option<Output>, CircuitError> {
        let balance = self.balance.amount_var();
        if self.close {
            balance.assert_equal(&zero(), "a closed token utxo leaves a balance")?;
            return Ok(None);
        }
        Ok(Some(Output {
            owner: self.owner(),
            asset: self.asset(),
            amount: self.balance.output_amount()?,
            data_hash: zero(),
            data: None,
            empty_if_zero: !self.retain_zero_output,
        }))
    }

    #[track_caller]
    fn spend(inputs: &[Utxo], close: bool) -> Result<Self, CircuitError> {
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
            let dummy = if index == 0 {
                Bool::constant(false)
            } else {
                input.domain.is_equal(&constant(u64::from(DUMMY_DOMAIN)))?
            };
            input.assert_default_ring()?;
            input
                .data_hash
                .assert_equal(&zero(), "the input carries program state")?;
            if index > 0 {
                input.domain.assert_equal_if(
                    &utxo_domain(),
                    &dummy.not(),
                    "the utxo is not a spendable utxo",
                )?;
                input.asset.assert_equal_if(
                    &first.asset,
                    &dummy.not(),
                    "the inputs hold different assets",
                )?;
                input.owner.assert_equal_if(
                    &first.owner,
                    &dummy.not(),
                    "the inputs belong to different owners",
                )?;
            }
            amounts.push(dummy.select(&zero(), &input.amount.var()));
            spent_inputs
                .push(input.spent(dummy.select(&zero(), &input.hash_with(&owner, &asset)?)));
        }
        Ok(Self {
            balance: Balance::new(
                first.owner.clone(),
                first.asset.clone(),
                Amount::sum(&amounts),
            ),
            spent_inputs,
            close,
            retain_zero_output: false,
        })
    }
}
