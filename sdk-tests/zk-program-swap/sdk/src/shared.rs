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

// A Blinding is already a 32-byte big-endian field element. Asserted at compile
// time so a Blinding width change is a build error, not a silent mismatch.
const _: () = assert!(core::mem::size_of::<Blinding>() == 32);

pub(crate) fn right_align_blinding(blinding: &Blinding) -> [u8; 32] {
    *blinding
}

#[cfg(test)]
pub(crate) fn test_blinding(byte: u8) -> Blinding {
    let mut blinding = [byte; 32];
    blinding[0] = 0;
    blinding
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
