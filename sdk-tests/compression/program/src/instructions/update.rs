use light_program_profiler::profile;
use pinocchio::{AccountView, ProgramResult};
use wincode::{SchemaRead, SchemaWrite};
use zolana_interface::instruction::instruction_data::transact::TransactProof;
use zolana_program::compression::{
    CompressedAccount, CompressedAccountMeta, PdaOwner, SppTransactCpi,
};

use crate::{
    error::{compressed_account_error, CompressionError},
    instructions::shared::{invoke_signed_by_pda, tree_id, TransitionAccounts},
    state::AccountState,
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct UpdateIxData {
    pub old_value: u64,
    pub version: u64,
    pub new_value: u64,
    /// The current UTXO's address, blinding and root indexes.
    pub meta: CompressedAccountMeta,
    pub proof: TransactProof,
}

#[inline(never)]
#[profile]
pub fn process_update_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let UpdateIxData {
        old_value,
        version,
        new_value,
        meta,
        proof,
    } = wincode::deserialize_exact(data).map_err(|_| CompressionError::InvalidInstructionData)?;

    let parsed = TransitionAccounts::validate_and_parse(accounts)?;
    let input_tree_id = tree_id(parsed.input_tree)?;
    let authority = *parsed.authority.address();
    let (pda, bump) = (parsed.pda, parsed.bump);

    let owner = PdaOwner::new(&pda).map_err(compressed_account_error)?;
    let new_version = version
        .checked_add(1)
        .ok_or(CompressionError::InvalidInstructionData)?;
    let mut account = CompressedAccount::new_mut(
        &owner,
        &meta,
        AccountState {
            authority: authority.to_bytes(),
            value: old_value,
            version,
            ..AccountState::default()
        },
        input_tree_id,
    )?;
    account.value = new_value;
    account.version = new_version;
    let cpi = SppTransactCpi::new(proof).with_compressed_account(account)?;
    invoke_signed_by_pda(accounts, &authority, &pda, bump, cpi)
}
