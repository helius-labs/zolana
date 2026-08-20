use anyhow::Result;
use solana_address::Address;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::instructions::transact::SppProofOutputUtxo;

use crate::err;

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
