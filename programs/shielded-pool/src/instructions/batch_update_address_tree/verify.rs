use pinocchio::{error::ProgramError, AccountView, Address};
use zolana_interface::{instruction::BatchUpdateAddressTreeData, LIGHT_REGISTRY_CPI_AUTHORITY};

use crate::{error::ShieldedPoolError, instructions::loader::MutableTreeAccounts};

pub fn verify<'a>(
    program_id: &Address,
    accounts: &'a mut [AccountView],
    data: &BatchUpdateAddressTreeData,
) -> Result<MutableTreeAccounts<'a>, ProgramError> {
    if data.new_root == [0u8; 32] {
        return Err(ShieldedPoolError::EmptyBatchUpdateRoot.into());
    }
    let loaded =
        crate::instructions::loader::load_mutable_tree_accounts(program_id, accounts, true)?;

    // Single equality check against the hardcoded registry CPI authority PDA
    // — no on-chain re-derivation needed. The constant is pinned to
    // `find_program_address(b"cpi_authority", LIGHT_REGISTRY_PROGRAM_ID)` by
    // a test in `shielded-pool/tests/instruction_validation.rs`.
    if *loaded.signer.address() != Address::from(LIGHT_REGISTRY_CPI_AUTHORITY) {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }

    Ok(loaded)
}
