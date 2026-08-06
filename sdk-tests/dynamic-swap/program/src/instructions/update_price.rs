use borsh::{BorshDeserialize, BorshSerialize};
use light_program_profiler::profile;
use pinocchio::{address::address_eq, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::DynamicSwapError,
    state::{load_liquidity_mut, load_pair_mut},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct UpdatePriceData {
    pub price: u64,
}

#[inline(never)]
#[profile]
pub fn process_update_price_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let UpdatePriceData { price } = UpdatePriceData::try_from_slice(data)
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    // A zero price makes the fixed-capacity slot value zero and permits
    // zero-value settlements.
    if price == 0 {
        return Err(DynamicSwapError::InvalidPrice.into());
    }

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let pair_account = iter.next_mut("pair")?;
    let liquidity_account = iter.next_mut("liquidity")?;

    let mut pair = load_pair_mut(pair_account)?;
    if !address_eq(&pair.authority, authority.address()) {
        return Err(DynamicSwapError::Unauthorized.into());
    }
    pair.price = price;
    pair.quote_version = pair
        .quote_version
        .checked_add(1)
        .ok_or(pinocchio::error::ProgramError::ArithmeticOverflow)?;
    drop(pair);

    // Slots were denominated at the previous quote. Preserve privacy and
    // solvency by withdrawing the advertisement until the next proved refresh.
    let mut liquidity = load_liquidity_mut(liquidity_account)?;
    if liquidity.pair != *pair_account.address() {
        return Err(DynamicSwapError::PairMismatch.into());
    }
    liquidity.available_slots = 0;
    Ok(())
}
