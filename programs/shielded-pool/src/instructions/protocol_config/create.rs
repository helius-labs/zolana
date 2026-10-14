use crate::instructions::shared::caused_by;
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_account_checks::{upgrade_authority::is_upgrade_authority, AccountIterator};
use zolana_interface::{
    error::ShieldedPoolError, instruction::CreateProtocolConfigData, state::ProtocolConfig,
    SPP_PROTOCOL_CONFIG_PDA_SEED,
};

use super::init::ProtocolConfigInitParams;
use crate::instructions::shared::{verify_pda, CreatePdaAccount};

pub fn process_create_protocol_config(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = *bytemuck::try_from_bytes::<CreateProtocolConfigData>(data)
        .map_err(caused_by(ShieldedPoolError::InvalidInstructionData))?;
    let mut iter = AccountIterator::new(accounts);
    let fee_payer = iter.next_signer("fee_payer")?;
    // Do not require this account to remain read-only: when the fee payer and
    // upgrade authority are the same key, Solana merges the two metas and the
    // writable fee-payer privilege necessarily applies to both positions.
    let initialization_authority = iter.next_signer("initialization_authority")?;
    let protocol_config = iter.next_mut("protocol_config")?;
    let system_program = iter.next_account("system_program")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }
    check_initialization_authority(initialization_authority, program, program_data)?;

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
    .map_err(caused_by(ShieldedPoolError::InvalidProtocolConfig))?;

    ProtocolConfigInitParams {
        protocol_authority: data.protocol_authority,
        tree_creation_authority: data.tree_creation_authority,
        tree_creation_is_permissionless: data.tree_creation_is_permissionless,
        forester_authority: data.forester_authority,
        ring_creation_authority: data.ring_creation_authority,
        ring_activation_is_permissionless: data.ring_activation_is_permissionless,
        spl_interface_creation_is_permissionless: data.spl_interface_creation_is_permissionless,
        fee_authority: data.fee_authority,
    }
    .init(protocol_config)
}

/// Front-run protection (INV-CREATE-PC-10): one-time initialization is allowed
/// only while this program is a loader-v3 deployment with a real, nonzero
/// upgrade authority, and that authority signs this instruction. The signer is
/// independent of the rent payer and the protocol authority written into the
/// config, so a Squads vault may authorize initialization through CPI while an
/// ordinary transaction payer funds the account.
///
/// Non-loader-v3 deployments and unset, zeroed, malformed, forged, or
/// mismatched loader state all fail closed. Consequently the protocol config
/// must be initialized before the program is made immutable or migrated to a
/// different loader.
fn check_initialization_authority(
    initialization_authority: &AccountView,
    program: &AccountView,
    program_data: &AccountView,
) -> ProgramResult {
    if !is_upgrade_authority(&crate::ID, initialization_authority, program, program_data)? {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    Ok(())
}
