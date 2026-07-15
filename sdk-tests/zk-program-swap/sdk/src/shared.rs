use anyhow::Result;
use solana_address::Address;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::{
    instructions::{transact::OutputUtxo, types::SppProofInputUtxo},
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

pub(crate) fn right_align_blinding(blinding: &Blinding) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[1..].copy_from_slice(blinding);
    out
}

pub(crate) fn check_output_utxo(
    label: &str,
    output: &OutputUtxo,
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
