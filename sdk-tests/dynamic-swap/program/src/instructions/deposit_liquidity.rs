use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::deposit::{
    DepositAssetKind, DepositIxDataRef,
};

use crate::{
    error::DynamicSwapError,
    instructions::shared::{
        asset_field, cpi_spp_deposit, derive_authority_pda, pda_owner_hash, u64_right_align,
    },
    state::load_pair_mut,
};

const DEPOSIT_MINT_INDEX: usize = 4;

// Deposits SPL tokens into the pair's liquidity pool and adds the deposited
// amount to its available liquidity.
//
// Steps:
// 1. Check that the pair account is present and writable.
// 2. Parse the instruction data as shielded-pool deposit data.
// 3. Check that there is exactly one asset.
// 4. Check that there is exactly one deposit entry.
// 5. Check that the asset is an SPL asset.
// 6. Check that the deposit entry references asset index 0.
// 7. Check that the deposited amount is nonzero.
// 8. Check that the entry owner equals the derived `pool_authority` PDA's
//    owner hash.
// 9. Check that the entry view tag equals the raw `pool_authority` PDA bytes.
// 10. Check that the entry contains UTXO data.
// 11. Check that the UTXO data hash commits `booked = amount`.
// 12. Check that the clear UTXO payload contains the same amount encoded as
//     eight-byte big-endian data.
// 13. Check that the forwarded shielded-pool account list is present.
// 14. Check that the SPL mint exists at the expected deposit-account index.
// 15. Load the pair, verifying program ownership, exact `Pair::SIZE`, the pair
//     discriminator, and writable access.
// 16. Check that the supplied SPL mint's asset commitment equals
//     `pair.destination_asset`.
// 17. Add the amount to `pair.available_liquidity` with overflow checking.
// 18. Invoke the shielded-pool program, which validates its account layout,
//     depositor authorization, SPL transfer, and UTXO creation.
#[inline(never)]
#[profile]
pub fn process_deposit_liquidity_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    // Step 1: Check that the pair account is present and writable.
    let pair_account = iter.next_mut("pair")?;
    let pair_address = *pair_account.address();

    // Step 2: Parse the instruction data as shielded-pool deposit data.
    let deposit =
        DepositIxDataRef::from_bytes(data).map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    // Step 3: Check that there is exactly one asset.
    // Step 4: Check that there is exactly one deposit entry.
    if deposit.assets.len() != 1 || deposit.deposits.len() != 1 {
        return Err(DynamicSwapError::InvalidDepositEntry.into());
    }
    let asset = deposit
        .assets
        .first()
        .ok_or(DynamicSwapError::InvalidDepositEntry)?;
    // Step 5: Check that the asset is an SPL asset.
    if !matches!(asset, DepositAssetKind::Spl { .. }) {
        return Err(DynamicSwapError::InvalidDepositEntry.into());
    }
    let entry = deposit
        .deposits
        .first()
        .ok_or(DynamicSwapError::InvalidDepositEntry)?;
    // Step 6: Check that the deposit entry references asset index 0.
    // Step 7: Check that the deposited amount is nonzero.
    if entry.asset_index != 0 || entry.amount == 0 {
        return Err(DynamicSwapError::InvalidDepositEntry.into());
    }

    let (pool_pda, _bump) = derive_authority_pda(crate::POOL_AUTHORITY_PDA_SEED, &pair_address);
    // Step 8: Check that the entry owner equals the pool PDA's owner hash.
    // Step 9: Check that the entry view tag equals the raw pool PDA bytes.
    if entry.owner != &pda_owner_hash(&pool_pda)? || entry.view_tag != pool_pda.as_array() {
        return Err(DynamicSwapError::InvalidDepositEntry.into());
    }

    // Step 10: Check that the entry contains UTXO data.
    let utxo_data = entry
        .utxo_data
        .ok_or(DynamicSwapError::InvalidDepositEntry)?;
    // Step 11: Check that the data hash commits `booked = amount`.
    // Step 12: Check that the payload contains the amount as big-endian data.
    if utxo_data.data_hash != &u64_right_align(entry.amount)
        || utxo_data.data != entry.amount.to_be_bytes().as_slice()
    {
        return Err(DynamicSwapError::InvalidDepositEntry.into());
    }

    // Step 13: Check that the forwarded shielded-pool accounts are present.
    let spp_accounts = iter.remaining()?;
    // Step 14: Check that the mint exists at the expected account index.
    let mint = spp_accounts
        .get(DEPOSIT_MINT_INDEX)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let mint_asset = asset_field(mint.address())?;

    {
        // Step 15: Load and validate the pair account.
        let mut pair = load_pair_mut(pair_account)?;
        // Step 16: Check that the mint matches the pair's destination asset.
        if mint_asset != pair.destination_asset {
            return Err(DynamicSwapError::AssetMismatch.into());
        }
        // Step 17: Add the amount to available liquidity without overflow.
        pair.available_liquidity = pair
            .available_liquidity
            .checked_add(entry.amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }

    // Step 18: Invoke the shielded-pool deposit.
    cpi_spp_deposit(spp_accounts, data)
}
