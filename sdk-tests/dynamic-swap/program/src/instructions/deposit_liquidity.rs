use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::deposit::{
    DepositAssetKind, DepositIxDataRef,
};

use crate::{
    error::DynamicSwapError,
    instructions::shared::{
        asset_field, cpi_spp_deposit, pool_authority_owner_hash, u64_right_align,
    },
    state::load_pair_mut,
};

/// The forwarded SPP deposit tail: `tree, depositor, spp_program,
/// token_program, mint, user_token, spl_interface`. The mint sits at index 4.
const DEPOSIT_TAIL_MINT_INDEX: usize = 4;

/// Shields a public `amount` of the destination asset from the depositor's SPL
/// token account into a new pool UTXO owned by the pair's `pool_authority`
/// PDA, with `booked = amount` committed as the note's data hash. Amount,
/// owner, blinding, and booked are public instruction data, so the SPP deposit
/// processor computes the commitment itself; no proof. Permissionless: the
/// depositor signs its own SPL transfer (SPP checks that signature), and a
/// deposit can only raise the guarantee.
///
/// The instruction data (after the tag) is the verbatim SPP `DepositIxData`
/// bytes; the program validates that the single entry forms a pool note,
/// applies `liquidity_bound += amount`, and forwards the bytes unsigned.
#[inline(never)]
#[profile]
pub fn process_deposit_liquidity_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let pair_account = iter.next_mut("pair")?;
    let pair_address = *pair_account.address();

    let deposit =
        DepositIxDataRef::from_bytes(data).map_err(|_| DynamicSwapError::InvalidInstructionData)?;

    // Exactly one SPL settlement group and one entry: a pool deposit funds one
    // pool note of the pair's destination asset, nothing else.
    if deposit.assets.len() != 1 || deposit.deposits.len() != 1 {
        return Err(DynamicSwapError::InvalidDepositEntry.into());
    }
    let asset = deposit
        .assets
        .first()
        .ok_or(DynamicSwapError::InvalidDepositEntry)?;
    if !matches!(asset, DepositAssetKind::Spl { .. }) {
        return Err(DynamicSwapError::InvalidDepositEntry.into());
    }
    let entry = deposit
        .deposits
        .first()
        .ok_or(DynamicSwapError::InvalidDepositEntry)?;
    if entry.asset_index != 0 || entry.amount == 0 {
        return Err(DynamicSwapError::InvalidDepositEntry.into());
    }

    // The note must be locked under the pair's pool_authority; the owner-hash
    // is recomputed here, never trusted from the client.
    let pool_owner_hash = pool_authority_owner_hash(&pair_address)?;
    if entry.owner != &pool_owner_hash {
        return Err(DynamicSwapError::InvalidDepositEntry.into());
    }

    // Deposit notes start fully booked: the data hash commits
    // `booked = amount` (right-aligned), and the clear payload is the 8-byte
    // big-endian booked value the maker's discovery decodes.
    let utxo_data = entry
        .utxo_data
        .ok_or(DynamicSwapError::InvalidDepositEntry)?;
    if utxo_data.data_hash != &u64_right_align(entry.amount)
        || utxo_data.data != entry.amount.to_be_bytes().as_slice()
    {
        return Err(DynamicSwapError::InvalidDepositEntry.into());
    }

    let spp_accounts = iter.remaining()?;
    let mint = spp_accounts
        .get(DEPOSIT_TAIL_MINT_INDEX)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let mint_asset = asset_field(mint.address())?;

    {
        let mut pair = load_pair_mut(pair_account)?;
        // The deposited mint must be the pair's destination asset: SPP settles
        // the SPL transfer against the mint account it is handed, so binding
        // that mint to `Pair.destination_asset` is what makes the bound
        // increase real.
        if mint_asset != pair.destination_asset {
            return Err(DynamicSwapError::AssetMismatch.into());
        }
        pair.liquidity_bound = pair
            .liquidity_bound
            .checked_add(entry.amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }

    cpi_spp_deposit(spp_accounts, data)
}
