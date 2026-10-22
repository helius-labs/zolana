use zolana_interface::DUMMY_DOMAIN;

use super::{utxo_domain, Amount, Balance, HasBalance, Output, SpentInput, Utxo, UtxoTrait};
use crate::{
    circuit::{
        builtins::field::var::system_of, constant, labels::Scope, zero, Assert, Bool, CircuitVar,
        HashBytes, PublicTransfer, Select, SolanaAddress, UtxoOwner,
    },
    CircuitError, CircuitErrorKind,
};

#[must_use]
#[derive(Debug)]
pub struct TokenUtxos {
    balance: Balance,
    spent_inputs: Vec<(SpentInput, Bool)>,
    has_real_input: Option<Bool>,
    optional: bool,
    error: Option<CircuitError>,
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
    pub fn new_init(owner: &UtxoOwner, asset: &SolanaAddress) -> Self {
        Self {
            balance: Balance::new(owner.clone(), asset.clone(), Amount::zero()),
            spent_inputs: Vec::new(),
            has_real_input: None,
            optional: false,
            error: None,
            close: false,
            retain_zero_output: false,
        }
    }

    /// Combines real inputs of one owner and asset, ignoring dummy slots.
    /// Registration requires a real input unless `with_optional` is used.
    #[track_caller]
    pub fn new_mut<const N: usize>(inputs: &[Utxo; N]) -> Result<Self, CircuitError> {
        Self::spend(inputs)
    }

    /// Requires a final balance of zero and produces no output.
    /// Transfers into the group are rejected after it is closed.
    pub fn close(mut self) -> Self {
        self.close = true;
        self
    }

    /// A real, encrypted token output even when its amount is zero.
    pub fn with_zero_output(mut self) -> Self {
        self.retain_zero_output = true;
        self
    }

    /// Allows all input slots to be dummies and checks real inputs against
    /// the supplied owner and asset. Configure this before balance operations.
    #[track_caller]
    pub fn with_optional(mut self, owner: &UtxoOwner, asset: &SolanaAddress) -> Self {
        let result = (|| {
            if !self.balance.is_untouched() {
                return Err(CircuitErrorKind::RuleBroken(
                    "optional token inputs are configured before balance operations",
                )
                .into());
            }
            if let Some(real) = &self.has_real_input {
                self.owner().assert_equal_if(
                    owner,
                    real,
                    "a deposit belongs to its program owner",
                )?;
                self.asset()
                    .assert_equal_if(asset, real, "a deposit has its expected asset")?;
            }
            self.balance.set_owner_asset(owner, asset);
            Ok(())
        })();
        if let Err(error) = result {
            self.error.get_or_insert(error);
        }
        self.optional = true;
        self
    }

    pub(crate) fn spent_inputs(&self) -> &[(SpentInput, Bool)] {
        &self.spent_inputs
    }

    pub(crate) fn public_transfers(&self) -> &[PublicTransfer] {
        self.balance.public_transfers()
    }

    pub(crate) fn transferred(&self) -> &CircuitVar {
        self.balance.transferred()
    }

    #[track_caller]
    pub(crate) fn change(mut self) -> Result<Option<Output>, CircuitError> {
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        if !self.optional {
            if let Some(real) = &self.has_real_input {
                real.assert_true("a token utxo spends at least one real input")?;
            }
        }
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
    fn spend(inputs: &[Utxo]) -> Result<Self, CircuitError> {
        let _scope = Scope::open(
            &system_of(inputs.iter().map(|input| &input.domain)),
            "a token utxo's inputs",
        );
        let mut owner = inputs
            .first()
            .map(|input| input.owner.clone())
            .unwrap_or_default();
        let mut asset = inputs
            .first()
            .map(|input| input.asset.clone())
            .unwrap_or_else(|| SolanaAddress::constant(&zolana_transaction::SOL_MINT));
        let mut has_real = Bool::constant(false);
        let mut dummies = Vec::with_capacity(inputs.len());
        let mut amounts = Vec::with_capacity(inputs.len());
        for (index, input) in inputs.iter().enumerate() {
            let dummy = input.domain.is_equal(&constant(u64::from(DUMMY_DOMAIN)))?;
            let real = dummy.not();
            input.domain.assert_equal_if(
                &utxo_domain(),
                &real,
                "the utxo is not a spendable utxo",
            )?;
            input.assert_default_ring()?;
            input
                .data_hash
                .assert_equal(&zero(), "the input carries program state")?;
            if index > 0 {
                let first_real = has_real.not().and(&real);
                owner = UtxoOwner::select(&first_real, &input.owner, &owner);
                asset = SolanaAddress::select(&first_real, &input.asset, &asset);
            }
            has_real = has_real.or(&real);
            amounts.push(dummy.select(&zero(), &input.amount.var()));
            dummies.push(dummy);
        }
        let owner_hash = owner.hash()?;
        let asset_hash = asset.hash_bytes()?;
        let mut spent_inputs = Vec::with_capacity(inputs.len());
        for (input, dummy) in inputs.iter().zip(dummies) {
            let real = dummy.not();
            input
                .asset
                .assert_equal_if(&asset, &real, "the inputs hold different assets")?;
            input
                .owner
                .assert_equal_if(&owner, &real, "the inputs belong to different owners")?;
            let hash = dummy.select(&zero(), &input.hash_with(&owner_hash, &asset_hash)?);
            spent_inputs.push((input.spent(hash), dummy));
        }
        Ok(Self {
            balance: Balance::new(owner, asset, Amount::sum(&amounts)),
            spent_inputs,
            has_real_input: Some(has_real),
            optional: false,
            error: None,
            close: false,
            retain_zero_output: false,
        })
    }
}
