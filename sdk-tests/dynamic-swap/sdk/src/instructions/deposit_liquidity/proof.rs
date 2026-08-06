use anyhow::{bail, Result};
use dynamic_swap_program::instructions::deposit_liquidity::PoolUpdatePublicInput;
use dynamic_swap_prover::{PoolUpdateProofInputs, ProofInputUtxo};
use zolana_transaction::instructions::{
    transact::{spp_proof_inputs::asset_field, PrivateTxHash, SppProofOutputUtxo},
    types::SppProofInputUtxo,
};

use crate::{err, shared::check_output_utxo};

/// Proof-input params for the `pool_update` circuit, shared verbatim by
/// `deposit_liquidity` and `withdraw_liquidity`. The pool credit/debit is
/// balanced against an authority-owned note (`auth_in`/`auth_out`) of the pool
/// asset entirely inside the shielded set (`pool_in + auth_in == pool_out +
/// auth_out`), so no amount is ever public. Direction is decided by the caller:
/// deposit builds `pool_out > pool_in` with `auth_out` as the change; withdraw
/// builds `pool_out < pool_in` with `auth_out` receiving the withdrawn amount.
pub struct PoolUpdateProofInputParams {
    /// The pool's current live UTXO, about to be spent.
    pub pool_in: SppProofInputUtxo,
    /// The authority's own note of the pool asset funding the move (the change
    /// source on deposit; a real note on withdraw -- it cannot be a dummy
    /// because the circuit binds its asset to the pool asset).
    pub auth_in: SppProofInputUtxo,
    /// The pool's recreated UTXO.
    pub pool_out: SppProofOutputUtxo,
    /// The authority's recreated note (deposit change, or withdrawn funds).
    pub auth_out: SppProofOutputUtxo,
    /// The `Liquidity` account's on-chain `available_hash`, as already read
    /// by the caller. `pool_in` must hash to this value or the on-chain
    /// processor will reject the proof (it recomputes `PoolInHash` from this
    /// same account field); checked here so a stale/wrong `pool_in` preimage
    /// fails fast instead of producing a proof doomed to be rejected.
    pub pool_available_hash: [u8; 32],
    pub destination_asset: [u8; 32],
    pub reserved_liability: u64,
    pub slot_value: u64,
    pub available_slots: u64,
    pub refresh_capacity: bool,
    pub external_data_hash: [u8; 32],
}

impl PoolUpdateProofInputParams {
    pub fn to_proof_inputs(&self) -> Result<PoolUpdateProofInputs> {
        let asset = self.pool_in.utxo.asset;
        if asset_field(&asset).map_err(err)? != self.destination_asset {
            bail!("pool asset does not match pair destination asset");
        }
        if self.auth_in.utxo.asset != asset {
            bail!("auth_in asset does not match the pool asset");
        }
        // Value conservation across the pair, all in the pool asset. Widened to
        // i128 so a mis-built witness fails here rather than wrapping.
        let inputs_sum =
            i128::from(self.pool_in.utxo.amount) + i128::from(self.auth_in.utxo.amount);
        let outputs_sum = i128::from(self.pool_out.amount) + i128::from(self.auth_out.amount);
        if inputs_sum != outputs_sum {
            bail!("pool_update is not value-conserving (pool_in + auth_in != pool_out + auth_out)");
        }
        let required = self
            .reserved_liability
            .checked_add(
                self.available_slots
                    .checked_mul(self.slot_value)
                    .ok_or_else(|| err("capacity multiplication overflows"))?,
            )
            .ok_or_else(|| err("capacity requirement overflows"))?;
        if self.pool_out.amount < required {
            bail!("pool_out does not cover reserved liability and advertised capacity");
        }
        if self.refresh_capacity
            && self.pool_out.amount
                >= required
                    .checked_add(self.slot_value)
                    .ok_or_else(|| err("capacity upper bound overflows"))?
        {
            bail!("refreshed available_slots is not exact");
        }
        check_output_utxo("pool_out", &self.pool_out, &asset, self.pool_out.amount)?;
        check_output_utxo("auth_out", &self.auth_out, &asset, self.auth_out.amount)?;

        let pool_in = ProofInputUtxo::try_from(&self.pool_in).map_err(err)?;
        let auth_in = ProofInputUtxo::try_from(&self.auth_in).map_err(err)?;
        let pool_out = ProofInputUtxo::try_from(&self.pool_out).map_err(err)?;
        let auth_out = ProofInputUtxo::try_from(&self.auth_out).map_err(err)?;
        let pool_in_hash = pool_in.hash().map_err(err)?;
        if pool_in_hash != self.pool_available_hash {
            bail!("pool_in does not hash to the on-chain liquidity available_hash");
        }

        // Exact IN2_OUT2 shape, no padding: inputs [pool_in, auth_in], outputs
        // [pool_out, auth_out].
        let private_tx_hash = PrivateTxHash::new(
            &[pool_in_hash, auth_in.hash().map_err(err)?],
            &[pool_out.hash().map_err(err)?, auth_out.hash().map_err(err)?],
            &self.external_data_hash,
        )
        .hash()
        .map_err(err)?;

        // Reuse the program's own public-input hashing so the SDK can never
        // drift from what the on-chain processor recomputes.
        let public_input_hash = PoolUpdatePublicInput {
            private_tx_hash: &private_tx_hash,
            pool_in_hash: &pool_in_hash,
            destination_asset: &self.destination_asset,
            reserved_liability: self.reserved_liability,
            slot_value: self.slot_value,
            available_slots: self.available_slots,
            refresh_capacity: self.refresh_capacity,
        }
        .hash()
        .map_err(err)?;

        Ok(PoolUpdateProofInputs {
            public_input_hash,
            private_tx_hash,
            pool_in_hash,
            destination_asset: self.destination_asset,
            reserved_liability: self.reserved_liability,
            slot_value: self.slot_value,
            available_slots: self.available_slots,
            refresh_capacity: self.refresh_capacity,
            pool_in,
            auth_in,
            pool_out,
            auth_out,
            external_data_hash: self.external_data_hash,
        })
    }
}
