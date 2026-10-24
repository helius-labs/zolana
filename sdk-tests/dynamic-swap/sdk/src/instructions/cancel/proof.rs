use anyhow::{bail, Result};
use dynamic_swap_program::circuits::{
    EscrowCancel, EscrowCancelPrivateInputs, EscrowCancelPublicInputs,
};
use zolana_transaction::utxo::ProofInputUtxo;
use zolana_transaction::{
    instructions::transact::{PrivateTxHash, SppProofOutputUtxo},
    utxo::SppProofInputUtxo,
};

use crate::{
    err,
    instructions::settle::cancel_blinding_seed,
    shared::{check_output_utxo, transaction_blindings},
    state::order_data_hash,
};

/// Proof-input params for the `escrow_cancel` circuit: 1-in (order) / 1-out
/// (refund). SPP proves the transaction at IN1_OUT2 with a compact second
/// output, which leaves the private transaction hash unchanged. The full order
/// amount returns, in the source asset, to the recipient committed with the
/// minimum price as the order UTXO's data hash. The expiry gate is
/// program-side; the circuit carries no notion of time.
pub struct CancelProofInputParams {
    pub order_in: SppProofInputUtxo,
    pub refund_out: SppProofOutputUtxo,
    pub order_amount: u64,
    pub recipient_owner_hash: [u8; 32],
    pub min_price: u64,
    /// The `Escrow` account's on-chain `order_utxo_hash`. `order_in` must hash
    /// to this value.
    pub order_utxo_hash: [u8; 32],
    /// `SppProofInputs::private_tx_blinding()` under [`cancel_blinding_seed`],
    /// the last `private_tx_hash` preimage element.
    pub private_tx_blinding: [u8; 32],
    /// Raw id of the tree the refund output is appended to.
    pub output_tree_id: u16,
}

impl CancelProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<EscrowCancel> {
        let order_in = ProofInputUtxo::try_from(&self.order_in).map_err(err)?;
        let refund_out =
            ProofInputUtxo::try_from((&self.refund_out, self.output_tree_id)).map_err(err)?;

        let order_in_hash = order_in.hash().map_err(err)?;
        if order_in_hash != self.order_utxo_hash {
            bail!("order_in does not hash to the on-chain order_utxo_hash");
        }
        if self.order_in.utxo.amount != self.order_amount {
            bail!("order_in amount does not match order_amount");
        }
        let expected_data_hash = order_data_hash(&self.recipient_owner_hash, self.min_price)?;
        if self.order_in.data_hash != Some(expected_data_hash) {
            bail!("order_in data hash does not commit recipient and min_price");
        }

        let refund_owner = check_output_utxo(
            "refund_out",
            &self.refund_out,
            &self.order_in.utxo.asset.asset,
            self.order_amount,
        )?;
        if refund_owner.owner_hash().map_err(err)? != self.recipient_owner_hash {
            bail!("refund_out owner does not match the order's committed recipient");
        }

        // The circuit fixes the refund blinding and the private transaction
        // blinding to SPP's derivation under the order-derived seed and the
        // order's nullifier (input 0), so the taker can recompute its refund.
        let first_nullifier = self.order_in.nullifier();
        let blinding_seed = cancel_blinding_seed(&self.order_in.utxo.blinding)?;
        let (private_tx_blinding, output_blindings) =
            transaction_blindings(&first_nullifier, &blinding_seed, 1)?;
        if self.private_tx_blinding != private_tx_blinding {
            bail!("private_tx_blinding must derive from the order opening");
        }
        if output_blindings.first() != Some(&self.refund_out.blinding) {
            bail!("refund_out blinding must derive from the order opening");
        }

        // Compact padding does not enter the private transaction hash.
        let private_tx_hash = PrivateTxHash::new(
            &[order_in_hash],
            &[refund_out.hash().map_err(err)?],
            &self.private_tx_blinding,
        )
        .hash()
        .map_err(err)?;

        Ok(EscrowCancel {
            private: EscrowCancelPrivateInputs {
                private_tx_hash,
                order_amount: self.order_amount,
                recipient_owner_hash: self.recipient_owner_hash,
                min_price: self.min_price,
                order_in: order_in.into(),
                refund_out: refund_out.into(),
                private_tx_blinding: self.private_tx_blinding,
            },
            public: EscrowCancelPublicInputs {
                first_nullifier,
                order_in_hash,
            },
        })
    }
}
