use borsh::{BorshDeserialize, BorshSerialize};
use light_program_profiler::profile;
use pinocchio::{AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::DynamicSwapError,
    instructions::shared::{verify_pda, CreatePdaAccount},
    state::{
        discriminator::{LIQUIDITY, PAIR},
        Liquidity, Pair,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct CreatePairData {
    pub price: u64,
    pub max_order_size: u64,
    pub capacity_refresh_threshold: u64,
    pub source_asset_id: u64,
    pub destination_asset_id: u64,
    /// Hash of the zero-value bootstrap UTXO owned by `pool_authority`.
    pub initial_pool_utxo_hash: [u8; 32],
    pub authority_owner_hash: [u8; 32],
    pub source_asset: [u8; 32],
    pub destination_asset: [u8; 32],
    pub settlement_viewing_pubkey: [u8; 33],
}

#[inline(never)]
#[profile]
pub fn process_create_pair_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let args = CreatePairData::try_from_slice(data)
        .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
    if args.price == 0 || args.max_order_size == 0 {
        return Err(DynamicSwapError::InvalidPrice.into());
    }

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let pair_account = iter.next_mut("pair")?;
    let liquidity_account = iter.next_mut("liquidity")?;
    let system_program = iter.next_account("system_program")?;
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(pinocchio::error::ProgramError::IncorrectProgramId);
    }

    let authority = *payer.address().as_array();
    let source_asset_id_le = args.source_asset_id.to_le_bytes();
    let destination_asset_id_le = args.destination_asset_id.to_le_bytes();
    let pair_seeds = [
        Pair::SEED_PREFIX,
        authority.as_slice(),
        source_asset_id_le.as_slice(),
        destination_asset_id_le.as_slice(),
    ];
    let pair_bump = verify_pda(pair_account.address(), &pair_seeds, &crate::ID)?;
    CreatePdaAccount::<4> {
        fee_payer: payer,
        new_account: pair_account,
        space: Pair::SIZE,
        owner: &crate::ID,
        signer_seeds: pair_seeds,
        bump: pair_bump,
    }
    .execute()?;

    let pair_key = *pair_account.address().as_array();
    let liquidity_bump = verify_pda(
        liquidity_account.address(),
        &[Liquidity::SEED_PREFIX, &pair_key],
        &crate::ID,
    )?;
    CreatePdaAccount::<2> {
        fee_payer: payer,
        new_account: liquidity_account,
        space: Liquidity::SIZE,
        owner: &crate::ID,
        signer_seeds: [Liquidity::SEED_PREFIX, &pair_key],
        bump: liquidity_bump,
    }
    .execute()?;

    {
        let mut bytes = pair_account
            .try_borrow_mut()
            .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
        let state: &mut Pair = bytemuck::from_bytes_mut(&mut bytes);
        state.discriminator = PAIR;
        state.bump = pair_bump;
        state.authority = *payer.address();
        state.source_asset_id = args.source_asset_id;
        state.destination_asset_id = args.destination_asset_id;
        state.price = args.price;
        state.max_order_size = args.max_order_size;
        state.quote_version = 1;
        state.capacity_refresh_threshold = args.capacity_refresh_threshold;
        state.authority_owner_hash = args.authority_owner_hash;
        state.source_asset = args.source_asset;
        state.destination_asset = args.destination_asset;
        state.settlement_viewing_pubkey_prefix = args.settlement_viewing_pubkey[0];
        state
            .settlement_viewing_pubkey_x
            .copy_from_slice(&args.settlement_viewing_pubkey[1..]);
    }
    {
        let mut bytes = liquidity_account
            .try_borrow_mut()
            .map_err(|_| DynamicSwapError::InvalidInstructionData)?;
        let state: &mut Liquidity = bytemuck::from_bytes_mut(&mut bytes);
        state.discriminator = LIQUIDITY;
        state.bump = liquidity_bump;
        state.pair = *pair_account.address();
        state.available_hash = args.initial_pool_utxo_hash;
        state.available_slots = 0;
        state.reserved_liability = 0;
    }
    Ok(())
}
