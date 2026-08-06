use anyhow::{bail, Result};
use dynamic_swap_program::instructions::create_escrow::EscrowOpenPublicInput;
use dynamic_swap_prover::{EscrowOpenProofInputs, ProofInputUtxo};
use zolana_keypair::hash::owner_hash;
use zolana_transaction::instructions::{
    transact::{spp_proof_inputs::asset_field, PrivateTxHash, SppProofOutputUtxo},
    types::SppProofInputUtxo,
};

use crate::err;

pub struct EscrowOpenProofInputParams {
    pub source_in: SppProofInputUtxo,
    pub order_out: SppProofOutputUtxo,
    pub order_amount: u64,
    pub max_price: u64,
    pub recipient_owner_hash: [u8; 32],
    pub created_at_unix_ts: i64,
    pub expires_at_unix_ts: i64,
    pub execution_price: u64,
    pub quote_version: u64,
    pub max_order_size: u64,
    pub escrow_authority_owner_hash: [u8; 32],
    pub source_asset: [u8; 32],
    pub external_data_hash: [u8; 32],
}

impl EscrowOpenProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<EscrowOpenProofInputs> {
        if self.order_amount == 0 || self.order_amount > self.max_order_size {
            bail!("order amount is outside pair limits");
        }
        if self.execution_price > self.max_price {
            bail!("execution price exceeds private max price");
        }
        let expected_expiry = self
            .created_at_unix_ts
            .checked_add(600)
            .ok_or_else(|| err("order expiry overflows"))?;
        if self.expires_at_unix_ts != expected_expiry {
            bail!("order expiry must be exactly 600 seconds");
        }
        if self.source_in.utxo.amount != self.order_amount
            || self.order_out.amount != self.order_amount
        {
            bail!("create_escrow currently requires an exact-sized source note");
        }
        if asset_field(&self.source_in.utxo.asset).map_err(err)? != self.source_asset {
            bail!("source asset does not match pair");
        }
        let owner = self
            .order_out
            .owner_address
            .ok_or_else(|| err("order output owner missing"))?;
        if owner_hash(&owner.signing_pubkey, &owner.nullifier_pubkey).map_err(err)?
            != self.escrow_authority_owner_hash
        {
            bail!("order output is not owned by escrow authority");
        }

        let source_in = ProofInputUtxo::try_from(&self.source_in).map_err(err)?;
        let order_out = ProofInputUtxo::try_from(&self.order_out).map_err(err)?;
        let private_tx_hash = PrivateTxHash::new(
            &[source_in.hash().map_err(err)?],
            &[order_out.hash().map_err(err)?],
            &self.external_data_hash,
        )
        .hash()
        .map_err(err)?;
        let public_input_hash = EscrowOpenPublicInput {
            private_tx_hash: &private_tx_hash,
            created_at_unix_ts: self.created_at_unix_ts,
            expires_at_unix_ts: self.expires_at_unix_ts,
            execution_price: self.execution_price,
            quote_version: self.quote_version,
            max_order_size: self.max_order_size,
            escrow_authority_owner_hash: &self.escrow_authority_owner_hash,
            source_asset: &self.source_asset,
        }
        .hash()
        .map_err(err)?;

        Ok(EscrowOpenProofInputs {
            public_input_hash,
            private_tx_hash,
            created_at: self.created_at_unix_ts.try_into().map_err(err)?,
            expires_at: self.expires_at_unix_ts.try_into().map_err(err)?,
            execution_price: self.execution_price,
            quote_version: self.quote_version,
            max_order_size: self.max_order_size,
            escrow_authority_owner_hash: self.escrow_authority_owner_hash,
            source_asset: self.source_asset,
            order_amount: self.order_amount,
            max_price: self.max_price,
            recipient_owner_hash: self.recipient_owner_hash,
            source_in,
            order_out,
            external_data_hash: self.external_data_hash,
        })
    }
}
