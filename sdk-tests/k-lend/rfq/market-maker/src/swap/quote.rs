use anyhow::Result;
use solana_address::Address;

use k_lend_rfq_sdk::{
    pair::Pair,
    swap::{Direction, Offer, Quote, SwapError},
};

use crate::{
    api::Inner,
    inventory::balance::{pending::range_check, select::width},
    transactions::{
        budget::{smallest_shape, MAKER_MIN_OUTPUTS, USER_OUTPUTS},
        kvault::read_vault,
    },
};

impl Inner {
    pub async fn quote(&self, pair: &Pair, direction: Direction, amount_in: u64) -> Result<Offer> {
        let fee_bps = {
            let settings = self.settings();
            settings.serves(pair)?;
            settings.quotes.fee_bps
        };
        let rate = read_vault(self.services.rpc.as_ref(), pair.vault).await?;
        let quote = Quote::price(&rate, direction, amount_in, fee_bps)?;
        let (asset_in, asset_out) = direction.assets(pair);
        self.check_range(asset_out, quote.amount_out, false)?;
        self.check_range(asset_in, amount_in, true)?;
        Ok(Offer {
            quote,
            maker: self.identity.own,
            fee_payer: self.identity.payer,
            max_user_inputs: self.quoted_user_inputs(asset_out, quote.amount_out)?,
            user_outputs: USER_OUTPUTS,
        })
    }

    fn check_range(&self, asset: Address, amount: u64, incoming: bool) -> Result<(), SwapError> {
        range_check(
            asset,
            self.services.pending.net_balance(&asset),
            amount,
            incoming,
            self.settings().range(&asset),
        )
    }

    fn quoted_user_inputs(&self, asset: Address, amount: u64) -> Result<usize> {
        let utxos: Vec<u64> = self
            .services
            .pending
            .reservations
            .utxos(&asset)
            .iter()
            .map(|utxo| utxo.amount)
            .collect();
        let available: u64 = utxos.iter().sum();
        let max_inputs = self.max_maker_inputs;
        let too_wide = SwapError::MakerTransferTooWide {
            asset,
            required: amount,
            max_inputs,
        };
        let Some(inputs) = width(utxos, amount, max_inputs) else {
            if available < amount {
                return Err(SwapError::InsufficientInventory {
                    asset,
                    required: amount,
                    available,
                }
                .into());
            }
            return Err(too_wide.into());
        };
        let maker =
            smallest_shape(inputs, MAKER_MIN_OUTPUTS).ok_or(SwapError::NoSupportedShape {
                inputs,
                outputs: MAKER_MIN_OUTPUTS,
            })?;
        Ok(self
            .services
            .budget
            .max_user_inputs(maker)?
            .ok_or(too_wide)?)
    }
}
