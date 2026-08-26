use anyhow::Result;
use solana_address::Address;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{instructions::transact::SppProofOutputUtxo, utxo::Blinding};

use crate::err;

// A Blinding is already a 32-byte big-endian field element. Asserted at compile
// time so a Blinding width change is a build error, not a silent mismatch.
const _: () = assert!(core::mem::size_of::<Blinding>() == 32);

pub(crate) fn right_align_blinding(blinding: &Blinding) -> [u8; 32] {
    *blinding
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
    if &output.asset != mint {
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
    if &output.asset != mint {
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
