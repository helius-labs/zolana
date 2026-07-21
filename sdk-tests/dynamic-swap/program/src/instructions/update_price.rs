use borsh::{BorshDeserialize, BorshSerialize};
use light_program_profiler::profile;
use pinocchio::{address::address_eq, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{error::DynamicSwapError, state::load_pair_mut};

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct UpdatePriceData {
    pub price: u64,
}

#[inline(never)]
#[profile]
pub fn process_update_price_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let UpdatePriceData { price } = UpdatePriceData::try_from_slice(data)
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    // A zero price would leave `create_escrow` unable to stamp a nonzero
    // `execution_price`, so the escrow could never settle -- reject it so every
    // escrow always has a nonzero `execution_price`.
    if price == 0 {
        return Err(DynamicSwapError::InvalidPrice.into());
    }

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let pair_account = iter.next_mut("pair")?;

    let mut pair = load_pair_mut(pair_account)?;
    if !address_eq(&pair.authority, authority.address()) {
        return Err(DynamicSwapError::Unauthorized.into());
    }
    pair.price = price;
    Ok(())
}
