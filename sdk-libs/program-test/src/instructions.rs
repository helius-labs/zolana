use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use zolana_client::Rpc;
use zolana_interface::{
    instruction::CreateTree,
    pda,
    state::{state_root_offset, ProtocolConfig},
};
use zolana_tree::{NullifierTreeInitParams, TreeFeeSchedule};

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

pub fn next_tree_id<R: Rpc>(rpc: &R) -> Result<u16, ProgramTestError> {
    let config = pda::protocol_config();
    let data = rpc
        .get_account(Address::new_from_array(config.to_bytes()))
        .map_err(ProgramTestError::from)?
        .ok_or_else(|| ProgramTestError::Rpc(format!("protocol config not found: {config}")))?
        .data;
    let config = ProtocolConfig::from_account_bytes(&data)
        .map_err(|error| ProgramTestError::Rpc(format!("invalid protocol config: {error:?}")))?;
    Ok(config.next_tree_id)
}

pub struct TreeCreation {
    pub tree: Pubkey,
    pub instructions: Vec<Instruction>,
}

pub fn create_tree_instructions<R: Rpc>(
    rpc: &R,
    payer: &Pubkey,
    authority: &Pubkey,
    nullifier_params: NullifierTreeInitParams,
    fees: TreeFeeSchedule,
) -> Result<TreeCreation, ProgramTestError> {
    let create = CreateTree {
        payer: *payer,
        authority: *authority,
        tree_id: next_tree_id(rpc)?,
        nullifier_params,
        fees,
    };
    Ok(TreeCreation {
        tree: create.tree(),
        instructions: create.instructions(),
    })
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
