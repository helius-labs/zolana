use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_interface::{
    instruction::BatchUpdateAddressTreeData, CPI_AUTHORITY_PDA_SEED, LIGHT_REGISTRY_PROGRAM_ID,
};

use crate::{
    error::ShieldedPoolError, instructions::loader::MutablePoolTreeAccounts, pda::derive_pda,
};

pub fn verify<'a>(
    program_id: &Address,
    accounts: &'a [AccountView],
    data: &BatchUpdateAddressTreeData,
) -> Result<MutablePoolTreeAccounts<'a>, ProgramError> {
    if data.new_root == [0u8; 32] {
        return Err(ShieldedPoolError::EmptyBatchUpdateRoot.into());
    }
    let loaded =
        crate::instructions::loader::load_mutable_pool_tree_accounts(program_id, accounts, true)?;

    let expected = derive_pda(
        CPI_AUTHORITY_PDA_SEED,
        data.cpi_authority_bump,
        &LIGHT_REGISTRY_PROGRAM_ID,
    );
    if *loaded.signer.address() != expected {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }

    Ok(loaded)
}
