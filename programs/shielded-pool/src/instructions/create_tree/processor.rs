use crate::instructions::shared::caused_by;
use borsh::BorshDeserialize;
use pinocchio::{
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::CreateTreeData,
    state::{
        discriminator::TREE_ACCOUNT_DISCRIMINATOR, tree_account_size, tree_creation_lamports,
        STATE_HEIGHT,
    },
    NULLIFIER_PDA_SIZE, TREE_PDA_SEED,
};
use zolana_tree::TreeAccount;

use super::allocate::{fund_tree, grow_tree, is_unallocated, TreeAllocation};
use crate::instructions::{
    protocol_config::loader::load_protocol_config_mut,
    shared::{tree_error, verify_pda},
};

pub fn process_create_tree(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = CreateTreeData::try_from_slice(data)
        .map_err(caused_by(ShieldedPoolError::InvalidInstructionData))?;
    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let protocol_config = iter.next_mut("protocol_config")?;
    let tree = iter.next_mut("tree")?;
    let system_program = iter.next_account("system_program")?;
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ShieldedPoolError::InvalidSystemProgram.into());
    }

    let tree_id_seed = data.tree_id.to_le_bytes();
    let bump = verify_pda(tree.address(), &[TREE_PDA_SEED, &tree_id_seed], &crate::ID)?;
    let unallocated = is_unallocated(tree);
    {
        let mut config = load_protocol_config_mut(protocol_config)?;
        if !config.allows_permissionless_tree_creation()
            && config
                .check_tree_creation_authority(authority.address())
                .is_err()
        {
            return Err(ShieldedPoolError::UnauthorizedCaller.into());
        }
        if unallocated {
            if data.tree_id != config.next_tree_id {
                return Err(ShieldedPoolError::InvalidTreeId.into());
            }
            let next_tree_id = data
                .tree_id
                .checked_add(1)
                .ok_or(ShieldedPoolError::TreeIdOverflow)?;
            config.next_tree_id = next_tree_id;
        }
    }

    let full_size = tree_account_size();
    let rent = Rent::get()?;
    let lamports = tree_creation_lamports(
        &data.nullifier_params,
        rent.try_minimum_balance(full_size)?,
        rent.try_minimum_balance(NULLIFIER_PDA_SIZE)?,
    )
    .ok_or(ProgramError::ArithmeticOverflow)?;

    if unallocated {
        TreeAllocation {
            payer,
            tree,
            tree_id_seed,
            bump,
            full_size,
            lamports,
        }
        .create()?;
    } else {
        grow_tree(tree, full_size)?;
    }
    if tree.data_len() < full_size {
        return Ok(());
    }

    fund_tree(payer, tree, lamports)?;
    let tree_pubkey = tree.address().to_bytes();
    let mut tree_data = tree
        .try_borrow_mut()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    TreeAccount::init(
        &mut tree_data,
        TREE_ACCOUNT_DISCRIMINATOR,
        STATE_HEIGHT as u8,
        tree_pubkey,
        data.tree_id,
        data.nullifier_params,
        data.fees,
    )
    .map_err(tree_error)?;
    Ok(())
}
