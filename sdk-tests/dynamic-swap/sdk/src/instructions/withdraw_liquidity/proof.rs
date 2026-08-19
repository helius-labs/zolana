use anyhow::{bail, Result};
use dynamic_swap_program::instructions::withdraw_liquidity::PoolWithdrawPublicInput;
use dynamic_swap_prover::{PoolWithdrawProofInputs, ProofInputUtxo};
use zolana_keypair::ShieldedAddress;
use zolana_transaction::instructions::transact::{spp_proof_inputs::asset_field, PrivateTxHash};

use crate::state::PoolUtxo;

fn err(e: impl core::fmt::Debug) -> anyhow::Error {
    anyhow::anyhow!("{e:?}")
}

/// Proof-input params for the `pool_withdraw` circuit: 1-in (pool note) /
/// 1-out (pool change), the exact IN1_OUT1 shape. The public `amount` leaves
/// through the transact's SplWithdrawal leg; the change keeps
/// `booked_in - amount`, so a withdrawal can only consume counted value.
/// `amount = 0` re-blinds a public deposit note into a confidential one.
///
/// The transact-facing note forms are deterministic from the same `PoolUtxo`s
/// (their blindings are caller-fixed), so the caller builds those with
/// `PoolUtxo::{to_input_utxo, output_utxo}` for the external data first and
/// then finishes the witness here with the resulting hash.
pub struct WithdrawProofInputParams {
    pub pool_in: PoolUtxo,
    pub pool_out: PoolUtxo,
    /// The pool authority address for the pair (see
    /// `state::pool_authority_address`); owner of both notes.
    pub pool_authority: ShieldedAddress,
    pub amount: u64,
    /// The `Pair` account's on-chain `destination_asset`.
    pub destination_asset: [u8; 32],
    pub external_data_hash: [u8; 32],
}

impl WithdrawProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<PoolWithdrawProofInputs> {
        if asset_field(&self.pool_in.asset).map_err(err)? != self.destination_asset {
            bail!("pool_in asset does not match the pair destination asset");
        }
        if self.pool_out.asset != self.pool_in.asset {
            bail!("pool_out asset does not match pool_in");
        }
        // The circuit's booked and amount subtractions, mirrored early: both
        // reject at proving time otherwise.
        let expected_amount = self
            .pool_in
            .amount
            .checked_sub(self.amount)
            .ok_or_else(|| err("amount exceeds the pool note amount"))?;
        let expected_booked = self
            .pool_in
            .booked
            .checked_sub(self.amount)
            .ok_or_else(|| err("amount exceeds the pool note's booked value"))?;
        if self.pool_out.amount != expected_amount {
            bail!("pool_out amount does not equal pool_in - amount");
        }
        if self.pool_out.booked != expected_booked {
            bail!("pool_out booked does not equal booked_in - amount");
        }

        let pool_authority_owner_hash = self.pool_authority.owner_hash().map_err(err)?;
        let spp_input = self.pool_in.to_input_utxo(&self.pool_authority)?;
        let spp_output = self.pool_out.output_utxo(&self.pool_authority)?;

        let pool_in = ProofInputUtxo::try_from(&spp_input).map_err(err)?;
        let pool_out = ProofInputUtxo::try_from(&spp_output).map_err(err)?;

        let private_tx_hash = PrivateTxHash::new(
            &[pool_in.hash().map_err(err)?],
            &[pool_out.hash().map_err(err)?],
            &self.external_data_hash,
        )
        .hash()
        .map_err(err)?;

        let public_input_hash = PoolWithdrawPublicInput {
            private_tx_hash: &private_tx_hash,
            pool_authority_owner_hash: &pool_authority_owner_hash,
            destination_asset: &self.destination_asset,
            amount: self.amount,
        }
        .hash()
        .map_err(err)?;

        Ok(PoolWithdrawProofInputs {
            public_input_hash,
            private_tx_hash,
            pool_authority_owner_hash,
            destination_asset: self.destination_asset,
            amount: self.amount,
            pool_in,
            pool_out,
            external_data_hash: self.external_data_hash,
        })
    }
}
