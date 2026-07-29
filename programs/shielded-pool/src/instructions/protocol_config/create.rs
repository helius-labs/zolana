use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError, instruction::CreateProtocolConfigData, state::ProtocolConfig,
    SPP_PROTOCOL_CONFIG_PDA_SEED,
};

use super::init::ProtocolConfigInitParams;
use crate::instructions::shared::{verify_pda, CreatePdaAccount};

pub fn process_create_protocol_config(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = *bytemuck::try_from_bytes::<CreateProtocolConfigData>(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let fee_payer = iter.next_signer("fee_payer")?;
    let protocol_config = iter.next_mut("protocol_config")?;
    let system_program = iter.next_account("system_program")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if *fee_payer.address() != data.protocol_authority {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }

    let bump = verify_pda(
        protocol_config.address(),
        &[SPP_PROTOCOL_CONFIG_PDA_SEED],
        &crate::ID,
    )?;

    CreatePdaAccount {
        fee_payer,
        new_account: &mut *protocol_config,
        space: ProtocolConfig::SIZE,
        owner: &crate::ID,
        signer_seeds: [SPP_PROTOCOL_CONFIG_PDA_SEED],
        bump,
    }
    .execute()
    .map_err(|_| ShieldedPoolError::InvalidProtocolConfig)?;

    ProtocolConfigInitParams {
        protocol_authority: data.protocol_authority,
        tree_creation_authority: data.tree_creation_authority,
        tree_creation_is_permissionless: data.tree_creation_is_permissionless,
        forester_authority: data.forester_authority,
        zone_creation_authority: data.zone_creation_authority,
        zone_creation_is_permissionless: data.zone_creation_is_permissionless,
        spl_interface_creation_is_permissionless: data.spl_interface_creation_is_permissionless,
    }
    .init(protocol_config)
}
