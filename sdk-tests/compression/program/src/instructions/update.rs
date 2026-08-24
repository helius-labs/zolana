use light_program_profiler::profile;
use pinocchio::{AccountView, ProgramResult};
use wincode::{SchemaRead, SchemaWrite};
use zolana_interface::instruction::instruction_data::transact::TransactIxData;

use crate::{
    error::CompressionError,
    instructions::shared::{
        cpi_spp_transact_signed, validate_transact, Transition, TransitionAccounts,
    },
};

#[derive(Clone, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct UpdateIxData {
    pub old_value: u64,
    pub old_blinding: [u8; 32],
    pub new_value: u64,
    pub output_seed: [u8; 32],
    pub transact: TransactIxData,
}

#[inline(never)]
#[profile]
pub fn process_update_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let UpdateIxData {
        old_value,
        old_blinding,
        new_value,
        output_seed,
        transact,
    } = wincode::deserialize_exact(data).map_err(|_| CompressionError::InvalidInstructionData)?;

    let parsed = TransitionAccounts::validate_and_parse(accounts)?;
    let authority = *parsed.authority.address();
    let (pda, bump) = (parsed.pda, parsed.bump);
    validate_transact(
        &authority,
        &pda,
        &Transition {
            old: Some((old_value, old_blinding)),
            new_value,
            output_seed,
        },
        &transact,
    )?;

    let transact_bytes = transact
        .serialize()
        .map_err(|_| CompressionError::SerializationFailed)?;
    cpi_spp_transact_signed(&authority, &pda, bump, accounts, &transact_bytes)
}
