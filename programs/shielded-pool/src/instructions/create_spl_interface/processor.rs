use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::{
    instruction::CreateSplInterfaceData, SPL_ASSET_REGISTRY_ACCOUNT_LEN, SPL_ASSET_REGISTRY_MAGIC,
};

use crate::error::ShieldedPoolError;

pub fn process_create_spl_interface(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: CreateSplInterfaceData,
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let (payer_slice, tail) = accounts.split_at_mut(1);
    let payer = &payer_slice[0];
    let (registry_slice, mint_slice) = tail.split_at_mut(1);
    let registry = &mut registry_slice[0];
    let mint = &mint_slice[0];

    if !payer.is_signer()
        || !registry.is_writable()
        || !registry.owned_by(program_id)
        || registry.data_len() < SPL_ASSET_REGISTRY_ACCOUNT_LEN
    {
        return Err(ShieldedPoolError::InvalidSplAssetRegistry.into());
    }

    // SAFETY: the registry account is writable and uniquely borrowed above.
    let registry_data = unsafe { registry.borrow_unchecked_mut() };
    registry_data[..SPL_ASSET_REGISTRY_ACCOUNT_LEN].fill(0);
    registry_data[0..8].copy_from_slice(&SPL_ASSET_REGISTRY_MAGIC);
    registry_data[8..40].copy_from_slice(mint.address().as_ref());
    registry_data[40..48].copy_from_slice(&data.asset_id.to_le_bytes());

    Ok(())
}
