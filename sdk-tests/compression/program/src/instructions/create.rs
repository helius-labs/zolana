use light_program_profiler::profile;
use pinocchio::{address::address_eq, AccountView, ProgramResult};
use wincode::{SchemaRead, SchemaWrite};
use zolana_interface::instruction::instruction_data::transact::{TransactProof, TreeContext};
use zolana_program::compression::{
    AddressSeed, CompressedAccount, NewAddress, PdaOwner, SppTransactCpi,
};

use crate::{
    error::{compressed_account_error, CompressionError},
    instructions::shared::{invoke_signed_by_pda, tree_id, TransitionAccounts, DEFAULT_TREE},
    state::AccountState,
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateIxData {
    pub new_value: u64,
    /// Root indexes of the address tree, which the address slot is proven
    /// against.
    pub address_tree_context: TreeContext,
    pub proof: TransactProof,
}

#[inline(never)]
#[profile]
pub fn process_create_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let CreateIxData {
        new_value,
        address_tree_context,
        proof,
    } = wincode::deserialize_exact(data).map_err(|_| CompressionError::InvalidInstructionData)?;

    let parsed = TransitionAccounts::validate_and_parse(accounts)?;
    if !address_eq(parsed.input_tree.address(), &DEFAULT_TREE)
        || !address_eq(parsed.output_tree.address(), &DEFAULT_TREE)
    {
        return Err(CompressionError::InvalidTree.into());
    }
    let input_tree_id = tree_id(parsed.input_tree)?;
    let authority = *parsed.authority.address();
    let (pda, bump) = (parsed.pda, parsed.bump);

    let owner = PdaOwner::new(&pda).map_err(compressed_account_error)?;
    let address = NewAddress::derive(&owner, AddressSeed::owner(&owner), input_tree_id)
        .map_err(compressed_account_error)?;
    let mut account: CompressedAccount<'_, AccountState> =
        CompressedAccount::new_init(&owner, address, address_tree_context);
    account.authority = authority.to_bytes();
    account.value = new_value;
    let cpi = SppTransactCpi::new(proof).with_compressed_account(account)?;
    invoke_signed_by_pda(accounts, &authority, &pda, bump, cpi)
}
