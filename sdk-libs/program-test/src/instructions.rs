use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_client::Rpc;
use zolana_interface::{
    instruction::CreateTree,
    pda,
    state::{
        address_tree_params, state_root_offset, tree_account_size, tree_working_capital_lamports,
    },
    NULLIFIER_MARKER_SIZE,
};
use zolana_tree::InitAddressTreeAccountsInstructionData;

use crate::ProgramTestError;

pub const RING_TEST_PROGRAM_ID: [u8; 32] = *b"ring_test_program_aaaaaaaaaaaaaa";

pub fn system_create_account_ix(
    payer: &Pubkey,
    new_account: &Pubkey,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
) -> Instruction {
    let mut data = vec![0u8; 4 + 8 + 8 + 32];
    data[4..12].copy_from_slice(&lamports.to_le_bytes());
    data[12..20].copy_from_slice(&space.to_le_bytes());
    data[20..52].copy_from_slice(&owner.to_bytes());
    Instruction {
        program_id: Pubkey::default(),
        accounts: vec![
            AccountMeta::new(*payer, true),
            AccountMeta::new(*new_account, true),
        ],
        data,
    }
}

pub fn tree_working_capital<R: Rpc>(
    rpc: &R,
    nullifier_params: &InitAddressTreeAccountsInstructionData,
) -> Result<u64, ProgramTestError> {
    let marker_rent = rpc.get_minimum_balance_for_rent_exemption(NULLIFIER_MARKER_SIZE)?;
    tree_working_capital_lamports(nullifier_params, marker_rent)
        .ok_or(ProgramTestError::TreeFundingOverflow)
}

pub fn tree_creation_lamports<R: Rpc>(
    rpc: &R,
    nullifier_params: &InitAddressTreeAccountsInstructionData,
) -> Result<u64, ProgramTestError> {
    let tree_rent = rpc.get_minimum_balance_for_rent_exemption(tree_account_size())?;
    tree_rent
        .checked_add(tree_working_capital(rpc, nullifier_params)?)
        .ok_or(ProgramTestError::TreeFundingOverflow)
}

pub fn create_tree_instructions<R: Rpc>(
    rpc: &R,
    payer: &Pubkey,
    authority: &Pubkey,
    tree: &Pubkey,
    account_size: u64,
) -> Result<Vec<Instruction>, ProgramTestError> {
    let rent = rpc.get_minimum_balance_for_rent_exemption(account_size as usize)?;
    let lamports = rent
        .checked_add(tree_working_capital(rpc, &address_tree_params())?)
        .ok_or(ProgramTestError::TreeFundingOverflow)?;
    Ok(vec![
        system_create_account_ix(
            payer,
            tree,
            lamports,
            account_size,
            &pda::shielded_pool_program_id(),
        ),
        CreateTree {
            authority: *authority,
            tree: *tree,
        }
        .instruction(),
    ])
}

pub fn rpc_state_root<R: Rpc>(rpc: &R, tree: &Pubkey) -> Result<[u8; 32], ProgramTestError> {
    let address = Address::new_from_array(tree.to_bytes());
    let data = rpc
        .get_account(address)
        .map_err(ProgramTestError::from)?
        .ok_or_else(|| ProgramTestError::Rpc(format!("account not found: {tree}")))?
        .data;
    let offset = state_root_offset();
    let slice = data
        .get(offset..offset + 32)
        .ok_or_else(|| ProgramTestError::Rpc("tree account missing state root".into()))?;
    let mut root = [0u8; 32];
    root.copy_from_slice(slice);
    Ok(root)
}
