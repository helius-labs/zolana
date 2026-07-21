use anyhow::Result;
use solana_address::Address;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{instructions::transact::SppProofOutputUtxo, utxo::Blinding};

use crate::err;

// Places the 31-byte blinding in bytes [1..32], leaving the top byte zero so the
// result is a valid BN254 field element. Asserted at compile time so a Blinding
// width change is a build error, not a silent `copy_from_slice` panic.
const _: () = assert!(core::mem::size_of::<Blinding>() == 31);

pub(crate) fn right_align_blinding(blinding: &Blinding) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[1..].copy_from_slice(blinding);
    out
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
        || output.zone_data_hash.is_some()
        || output.zone_program_id.is_some()
    {
        return Err(err(format!(
            "{label} must not carry data or zone commitments"
        )));
    }
    Ok(owner)
}
