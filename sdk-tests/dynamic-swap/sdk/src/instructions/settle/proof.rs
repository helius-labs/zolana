use anyhow::{bail, Result};
use dynamic_swap_program::instructions::settle::SettlePublicInput;
use dynamic_swap_prover::{EscrowSettleProofInputs, ProofInputUtxo};
use zolana_transaction::instructions::{
    transact::{PrivateTxHash, SppProofOutputUtxo},
    types::SppProofInputUtxo,
};

use crate::{err, shared::check_output_utxo};

pub struct SettleProofInputParams {
    pub order_in: SppProofInputUtxo,
    pub pool_in: SppProofInputUtxo,
    pub recipient_out: SppProofOutputUtxo,
    pub pool_out: SppProofOutputUtxo,
    pub authority_out: SppProofOutputUtxo,
    pub order_in_hash: [u8; 32],
    pub pool_in_hash: [u8; 32],
    pub order_amount: u64,
    pub max_price: u64,
    pub recipient_owner_hash: [u8; 32],
    pub created_at_unix_ts: i64,
    pub expires_at_unix_ts: i64,
    pub execution_price: u64,
    pub quote_version: u64,
    pub authority_owner_hash: [u8; 32],
    pub destination_asset: [u8; 32],
    pub remaining_reserved_liability: u64,
    pub slot_value: u64,
    pub available_slots: u64,
    pub refresh_capacity: bool,
    pub external_data_hash: [u8; 32],
}

impl SettleProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<EscrowSettleProofInputs> {
        let order_in = ProofInputUtxo::try_from(&self.order_in).map_err(err)?;
        let pool_in = ProofInputUtxo::try_from(&self.pool_in).map_err(err)?;
        let recipient_out = ProofInputUtxo::try_from(&self.recipient_out).map_err(err)?;
        let pool_out = ProofInputUtxo::try_from(&self.pool_out).map_err(err)?;
        let authority_out = ProofInputUtxo::try_from(&self.authority_out).map_err(err)?;
        if order_in.hash().map_err(err)? != self.order_in_hash
            || pool_in.hash().map_err(err)? != self.pool_in_hash
        {
            bail!("settlement inputs do not match current on-chain hashes");
        }
        let owed = self
            .order_amount
            .checked_mul(self.execution_price)
            .ok_or_else(|| err("payout overflows"))?;
        let recipient_owner = check_output_utxo(
            "recipient_out",
            &self.recipient_out,
            &self.pool_in.utxo.asset,
            owed,
        )?;
        if recipient_owner.owner_hash().map_err(err)? != self.recipient_owner_hash {
            bail!("recipient owner does not match order commitment");
        }
        check_output_utxo(
            "pool_out",
            &self.pool_out,
            &self.pool_in.utxo.asset,
            self.pool_in
                .utxo
                .amount
                .checked_sub(owed)
                .ok_or_else(|| err("pool cannot cover payout"))?,
        )?;
        let authority_owner = check_output_utxo(
            "authority_out",
            &self.authority_out,
            &self.order_in.utxo.asset,
            self.order_amount,
        )?;
        if authority_owner.owner_hash().map_err(err)? != self.authority_owner_hash {
            bail!("authority output owner mismatch");
        }
        let required = self
            .remaining_reserved_liability
            .checked_add(
                self.available_slots
                    .checked_mul(self.slot_value)
                    .ok_or_else(|| err("capacity multiplication overflows"))?,
            )
            .ok_or_else(|| err("capacity requirement overflows"))?;
        if self.pool_out.amount < required {
            bail!("post-settlement pool does not cover advertised capacity");
        }
        let next_required = required
            .checked_add(self.slot_value)
            .ok_or_else(|| err("capacity upper bound overflows"))?;
        if self.refresh_capacity && self.pool_out.amount >= next_required {
            bail!("refreshed capacity is not exact");
        }

        let private_tx_hash = PrivateTxHash::new(
            &[self.order_in_hash, self.pool_in_hash],
            &[
                recipient_out.hash().map_err(err)?,
                pool_out.hash().map_err(err)?,
                authority_out.hash().map_err(err)?,
            ],
            &self.external_data_hash,
        )
        .hash()
        .map_err(err)?;
        let public_input_hash = SettlePublicInput {
            private_tx_hash: &private_tx_hash,
            execution_price: self.execution_price,
            quote_version: self.quote_version,
            order_in_hash: &self.order_in_hash,
            pool_in_hash: &self.pool_in_hash,
            authority_owner_hash: &self.authority_owner_hash,
            destination_asset: &self.destination_asset,
            remaining_reserved_liability: self.remaining_reserved_liability,
            slot_value: self.slot_value,
            available_slots: self.available_slots,
            refresh_capacity: self.refresh_capacity,
        }
        .hash()
        .map_err(err)?;
        Ok(EscrowSettleProofInputs {
            public_input_hash,
            private_tx_hash,
            execution_price: self.execution_price,
            quote_version: self.quote_version,
            order_in_hash: self.order_in_hash,
            pool_in_hash: self.pool_in_hash,
            authority_owner_hash: self.authority_owner_hash,
            destination_asset: self.destination_asset,
            remaining_reserved_liability: self.remaining_reserved_liability,
            slot_value: self.slot_value,
            available_slots: self.available_slots,
            refresh_capacity: self.refresh_capacity,
            order_amount: self.order_amount,
            max_price: self.max_price,
            recipient_owner_hash: self.recipient_owner_hash,
            created_at: self.created_at_unix_ts.try_into().map_err(err)?,
            expires_at: self.expires_at_unix_ts.try_into().map_err(err)?,
            order_in,
            pool_in,
            recipient_out,
            pool_out,
            authority_out,
            external_data_hash: self.external_data_hash,
        })
    }
}
