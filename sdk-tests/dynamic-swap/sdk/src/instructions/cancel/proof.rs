use anyhow::{bail, Result};
use dynamic_swap_program::instructions::cancel::CancelPublicInput;
use dynamic_swap_prover::{EscrowCancelProofInputs, ProofInputUtxo, CANCEL_REFUND_BLINDING_DOMAIN};
use zolana_transaction::instructions::{
    transact::{PrivateTxHash, SppProofOutputUtxo},
    types::SppProofInputUtxo,
};

use crate::{err, instructions::settle::derive_output_blinding, shared::check_output_utxo};

/// Proof-input params for the `escrow_cancel` circuit: 1-in (order) / 1-out
/// (refund), the exact IN1_OUT1 shape. The full order amount returns, in the
/// source asset, to the recipient committed as the order UTXO's data hash. The
/// expiry gate is program-side; the circuit carries no notion of time.
pub struct CancelProofInputParams {
    pub order_in: SppProofInputUtxo,
    pub refund_out: SppProofOutputUtxo,
    pub order_amount: u64,
    /// The `Escrow` account's on-chain `order_utxo_hash`. `order_in` must hash
    /// to this value.
    pub order_utxo_hash: [u8; 32],
    pub external_data_hash: [u8; 32],
}

impl CancelProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<EscrowCancelProofInputs> {
        let order_in = ProofInputUtxo::try_from(&self.order_in).map_err(err)?;
        let refund_out = ProofInputUtxo::try_from(&self.refund_out).map_err(err)?;

        let order_in_hash = order_in.hash().map_err(err)?;
        if order_in_hash != self.order_utxo_hash {
            bail!("order_in does not hash to the on-chain order_utxo_hash");
        }
        if self.order_in.utxo.amount != self.order_amount {
            bail!("order_in amount does not match order_amount");
        }
        // The recipient the circuit re-opens from the order UTXO's data hash.
        let recipient_owner_hash = self
            .order_in
            .data_hash
            .ok_or_else(|| err("order_in carries no data hash (recipient)"))?;

        let refund_owner = check_output_utxo(
            "refund_out",
            &self.refund_out,
            &self.order_in.utxo.asset,
            self.order_amount,
        )?;
        if refund_owner.owner_hash().map_err(err)? != recipient_owner_hash {
            bail!("refund_out owner does not match the order's committed recipient");
        }
        let expected_blinding =
            derive_output_blinding(&self.order_in.utxo.blinding, CANCEL_REFUND_BLINDING_DOMAIN)?;
        if self.refund_out.blinding != expected_blinding {
            bail!("refund_out blinding does not match the derived cancel blinding");
        }

        // 1-in/1-out, exactly the supported IN1_OUT1 shape.
        let private_tx_hash = PrivateTxHash::new(
            &[order_in_hash],
            &[refund_out.hash().map_err(err)?],
            &self.external_data_hash,
        )
        .hash()
        .map_err(err)?;

        let public_input_hash = CancelPublicInput {
            private_tx_hash: &private_tx_hash,
            order_in_hash: &order_in_hash,
        }
        .hash()
        .map_err(err)?;

        Ok(EscrowCancelProofInputs {
            public_input_hash,
            private_tx_hash,
            order_in_hash,
            order_amount: self.order_amount,
            order_in,
            refund_out,
            external_data_hash: self.external_data_hash,
        })
    }
}
