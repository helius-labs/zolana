use anyhow::{bail, Result};
use dynamic_swap_program::instructions::refund_expired::RefundPublicInput;
use dynamic_swap_prover::{EscrowRefundProofInputs, ProofInputUtxo};
use zolana_transaction::instructions::{
    transact::{PrivateTxHash, SppProofOutputUtxo},
    types::SppProofInputUtxo,
};

use crate::{err, shared::check_output_utxo};

pub struct RefundProofInputParams {
    pub order_in: SppProofInputUtxo,
    pub recipient_out: SppProofOutputUtxo,
    pub order_in_hash: [u8; 32],
    pub recipient_owner_hash: [u8; 32],
    pub max_price: u64,
    pub created_at_unix_ts: i64,
    pub expires_at_unix_ts: i64,
    pub execution_price: u64,
    pub quote_version: u64,
    pub external_data_hash: [u8; 32],
}

impl RefundProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<EscrowRefundProofInputs> {
        let order_in = ProofInputUtxo::try_from(&self.order_in).map_err(err)?;
        if order_in.hash().map_err(err)? != self.order_in_hash {
            bail!("refund order input does not match escrow account");
        }
        let owner = check_output_utxo(
            "recipient_out",
            &self.recipient_out,
            &self.order_in.utxo.asset,
            self.order_in.utxo.amount,
        )?;
        if owner.owner_hash().map_err(err)? != self.recipient_owner_hash {
            bail!("refund recipient does not match order commitment");
        }
        let recipient_out = ProofInputUtxo::try_from(&self.recipient_out).map_err(err)?;
        let private_tx_hash = PrivateTxHash::new(
            &[self.order_in_hash],
            &[recipient_out.hash().map_err(err)?],
            &self.external_data_hash,
        )
        .hash()
        .map_err(err)?;
        let public_input_hash = RefundPublicInput {
            private_tx_hash: &private_tx_hash,
            execution_price: self.execution_price,
            quote_version: self.quote_version,
            order_in_hash: &self.order_in_hash,
        }
        .hash()
        .map_err(err)?;
        Ok(EscrowRefundProofInputs {
            public_input_hash,
            private_tx_hash,
            execution_price: self.execution_price,
            quote_version: self.quote_version,
            order_in_hash: self.order_in_hash,
            max_price: self.max_price,
            recipient_owner_hash: self.recipient_owner_hash,
            created_at: self.created_at_unix_ts.try_into().map_err(err)?,
            expires_at: self.expires_at_unix_ts.try_into().map_err(err)?,
            order_in,
            recipient_out,
            external_data_hash: self.external_data_hash,
        })
    }
}
