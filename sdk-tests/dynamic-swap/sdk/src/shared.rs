use anyhow::Result;
use solana_address::Address;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{
    instructions::transact::SppProofOutputUtxo,
    utxo::{
        derive_output_blinding_seed, derive_private_tx_blinding, derive_transact_output_blinding,
        Blinding,
    },
};

use crate::err;

/// The private transaction blinding and the first `n_outputs` output blindings
/// SPP derives from `first_nullifier` and `blinding_seed`.
pub fn transaction_blindings(
    first_nullifier: &[u8; 32],
    blinding_seed: &[u8; 32],
    n_outputs: u32,
) -> Result<([u8; 32], Vec<Blinding>)> {
    let seed = derive_output_blinding_seed(first_nullifier, blinding_seed).map_err(err)?;
    let outputs = (0..n_outputs)
        .map(|index| derive_transact_output_blinding(first_nullifier, &seed, index).map_err(err))
        .collect::<Result<Vec<_>>>()?;
    let private_tx_blinding =
        derive_private_tx_blinding(first_nullifier, blinding_seed).map_err(err)?;
    Ok((private_tx_blinding, outputs))
}

pub(crate) fn check_output_utxo(
    label: &str,
    output: &SppProofOutputUtxo,
    mint: &Address,
    amount: u64,
) -> Result<ShieldedAddress> {
    let owner = output
        .owner_address
        .ok_or_else(|| err(format!("{label} owner address missing")))?;
    if &output.asset.asset != mint {
        return Err(err(format!("{label} asset mismatch")));
    }
    if output.amount != amount {
        return Err(err(format!("{label} amount mismatch")));
    }
    if output.data_hash.is_some()
        || output.ring_data_hash.is_some()
        || output.ring_program_id.is_some()
    {
        return Err(err(format!(
            "{label} must not carry data or ring commitments"
        )));
    }
    Ok(owner)
}

/// Like [`check_output_utxo`], for a pool note: the data hash must commit
/// exactly `u64_right_align(booked)` and ring commitments stay forbidden.
pub(crate) fn check_pool_output_utxo(
    label: &str,
    output: &SppProofOutputUtxo,
    mint: &Address,
    amount: u64,
    booked: u64,
) -> Result<ShieldedAddress> {
    let owner = output
        .owner_address
        .ok_or_else(|| err(format!("{label} owner address missing")))?;
    if &output.asset.asset != mint {
        return Err(err(format!("{label} asset mismatch")));
    }
    if output.amount != amount {
        return Err(err(format!("{label} amount mismatch")));
    }
    if output.data_hash
        != Some(dynamic_swap_program::instructions::shared::u64_right_align(
            booked,
        ))
    {
        return Err(err(format!("{label} data hash does not commit booked")));
    }
    if output.ring_data_hash.is_some() || output.ring_program_id.is_some() {
        return Err(err(format!("{label} must not carry ring commitments")));
    }
    if booked > amount {
        return Err(err(format!("{label} booked exceeds amount")));
    }
    Ok(owner)
}
