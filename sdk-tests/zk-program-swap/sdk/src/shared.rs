use anyhow::Result;
use solana_address::Address;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{
    instructions::{transact::SppProofOutputUtxo, types::SppProofInputUtxo},
    utxo::Blinding,
};

use crate::err;

pub fn input_sum(inputs: &[SppProofInputUtxo], asset: &Address) -> i128 {
    inputs
        .iter()
        .filter(|spend| &spend.utxo.asset == asset)
        .map(|spend| i128::from(spend.utxo.amount))
        .sum()
}

// Places the blinding in bytes [1..32], leaving the top byte zero for field
// validity; only well-defined when a Blinding is exactly 31 bytes. Asserted at
// compile time so a Blinding length change is a build error, not a runtime panic
// in `copy_from_slice`.
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
