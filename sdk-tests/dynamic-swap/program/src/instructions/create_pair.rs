use borsh::{BorshDeserialize, BorshSerialize};
use light_program_profiler::profile;
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::DynamicSwapError,
    instructions::shared::{verify_pda, CreatePdaAccount},
    state::{discriminator::PAIR, Pair},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct CreatePairData {
    pub price: u64,
    pub source_asset_id: u64,
    pub destination_asset_id: u64,
    /// The authority's own owner-hash commitment; see `Pair::authority_owner_hash`.
    pub authority_owner_hash: [u8; 32],
    /// The source asset's UTXO commitment; see `Pair::source_asset`.
    pub source_asset: [u8; 32],
    /// The destination asset's UTXO commitment; see `Pair::destination_asset`.
    pub destination_asset: [u8; 32],
}

#[inline(never)]
#[profile]
pub fn process_create_pair_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let CreatePairData {
        price,
        source_asset_id,
        destination_asset_id,
        authority_owner_hash,
        source_asset,
        destination_asset,
    } = CreatePairData::try_from_slice(data)
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    // See `update_price`: a zero price leaves `create_escrow` unable to stamp a
    // nonzero `execution_price`, so the escrow could never settle.
    if price == 0 {
        return Err(DynamicSwapError::InvalidPrice.into());
    }

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let pair_account = iter.next_mut("pair")?;
    let system_program = iter.next_account("system_program")?;
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(pinocchio::error::ProgramError::IncorrectProgramId);
    }

    let authority = *payer.address().as_array();
    let source_asset_id_le = source_asset_id.to_le_bytes();
    let destination_asset_id_le = destination_asset_id.to_le_bytes();

    let pair_bump = verify_pda(
        pair_account.address(),
        &[
            Pair::SEED_PREFIX,
            &authority,
            &source_asset_id_le,
            &destination_asset_id_le,
        ],
        &crate::ID,
    )?;
    CreatePdaAccount::<4> {
        fee_payer: payer,
        new_account: pair_account,
        space: Pair::SIZE,
        owner: &crate::ID,
        signer_seeds: [
            Pair::SEED_PREFIX,
            &authority,
            &source_asset_id_le,
            &destination_asset_id_le,
        ],
        bump: pair_bump,
    }
    .execute()?;

    {
        let mut bytes = pair_account
            .try_borrow_mut()
            .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
        let state: &mut Pair = bytemuck::from_bytes_mut(&mut bytes[..]);
        state.discriminator = PAIR;
        state.bump = pair_bump;
        state.authority = *payer.address();
        state.source_asset_id = source_asset_id;
        state.destination_asset_id = destination_asset_id;
        state.price = price;
        state.authority_owner_hash = authority_owner_hash;
        state.source_asset = source_asset;
        state.destination_asset = destination_asset;
    }

    Ok(())
}
