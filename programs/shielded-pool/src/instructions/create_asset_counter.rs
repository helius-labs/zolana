use bytemuck::from_bytes_mut;
use pinocchio::{account::RefMut, error::ProgramError, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{error::ShieldedPoolError, state::SplAssetCounter};

use crate::instructions::{
    protocol_config::loader::load_protocol_config,
    shared::{verify_pda, CreatePdaAccount},
};

/// Create the singleton SPL asset counter PDA. The counter is a prerequisite of
/// [`crate::instructions::create_spl_interface`], which only ever reads and
/// advances it; this instruction is the one place that allocates and stamps it.
pub fn process_create_asset_counter(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if !data.is_empty() {
        return Err(ShieldedPoolError::InvalidInstructionData.into());
    }
    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let protocol_config = iter.next_account("protocol_config")?;
    let asset_counter = iter.next_mut("asset_counter")?;
    let system_program = iter.next_account("system_program")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }

    {
        let config = load_protocol_config(protocol_config)?;
        config
            .check_protocol_authority(authority.address())
            .map_err(ShieldedPoolError::from)?;
    }

    let bump = verify_pda(
        asset_counter.address(),
        &[SplAssetCounter::SEED],
        &crate::ID,
    )?;

    CreatePdaAccount {
        fee_payer: authority,
        new_account: &mut *asset_counter,
        space: SplAssetCounter::SIZE,
        owner: &crate::ID,
        signer_seeds: [SplAssetCounter::SEED],
        bump,
    }
    .execute()
    .map_err(|_| ShieldedPoolError::InvalidSplAssetRegistry)?;

    load_spl_asset_counter_mut(asset_counter)?.init();
    Ok(())
}

/// Load the program-owned SPL asset counter mutably (ownership + exact length).
/// The discriminator is intentionally not checked here: this same loader serves
/// the freshly created (zeroed) counter in [`process_create_asset_counter`],
/// where the discriminator is stamped by [`SplAssetCounter::init`]. Readers
/// validate it with [`SplAssetCounter::check_discriminator`].
#[inline(always)]
pub fn load_spl_asset_counter_mut<'a>(
    account: &'a mut AccountView,
) -> Result<RefMut<'a, SplAssetCounter>, ProgramError> {
    if !account.owned_by(&crate::ID) {
        return Err(ShieldedPoolError::InvalidSplAssetRegistry.into());
    }
    let data = account
        .try_borrow_mut()
        .map_err(|_| ShieldedPoolError::InvalidSplAssetRegistry)?;
    if data.len() != SplAssetCounter::SIZE {
        return Err(ShieldedPoolError::InvalidSplAssetRegistry.into());
    }
    Ok(RefMut::map(data, |d| from_bytes_mut::<SplAssetCounter>(d)))
}
