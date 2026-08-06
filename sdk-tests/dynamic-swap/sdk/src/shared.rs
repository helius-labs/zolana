use anyhow::Result;
use solana_address::Address;
use zolana_keypair::ShieldedAddress;
use zolana_transaction::instructions::transact::SppProofOutputUtxo;

use crate::err;

pub fn slot_value(max_order_size: u64, price: u64) -> Result<u64> {
    max_order_size
        .checked_mul(price)
        .ok_or_else(|| err("max_order_size * price overflows"))
}

pub fn should_refresh_capacity(
    available_slots: u64,
    slot_value: u64,
    threshold: u64,
) -> Result<bool> {
    Ok(available_slots
        .checked_mul(slot_value)
        .ok_or_else(|| err("advertised liquidity overflows"))?
        < threshold)
}

pub fn exact_available_slots(
    private_liquidity: u64,
    reserved_liability: u64,
    slot_value: u64,
) -> Result<u64> {
    if slot_value == 0 {
        return Err(err("slot value must be nonzero"));
    }
    let free = private_liquidity
        .checked_sub(reserved_liability)
        .ok_or_else(|| err("private liquidity is below reserved liability"))?;
    Ok(free / slot_value)
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

#[cfg(test)]
mod capacity_tests {
    use super::*;

    #[test]
    fn example_refreshes_below_one_hundred_and_republishes_exact_capacity() {
        assert!(!should_refresh_capacity(100, 1, 100).unwrap());
        assert!(should_refresh_capacity(99, 1, 100).unwrap());
        assert_eq!(exact_available_slots(1_000, 0, 1).unwrap(), 1_000);
    }
}
