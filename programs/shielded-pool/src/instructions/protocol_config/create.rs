use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError, instruction::CreateProtocolConfigData, state::ProtocolConfig,
    BPF_LOADER_UPGRADEABLE_ID, SPP_PROTOCOL_CONFIG_PDA_SEED,
};

use super::init::ProtocolConfigInitParams;
use crate::instructions::shared::{verify_pda, CreatePdaAccount};

/// Decode the loader-v3 account state with the canonical agave type (bincode
/// legacy layout). Returns `None` for malformed or non-loader state; callers
/// map that to their fail-closed error. bincode 2.x reads only the enum
/// fields, so the ProgramData account's trailing ELF bytecode is untouched.
fn decode_loader_state(data: &[u8]) -> Option<UpgradeableLoaderState> {
    bincode::serde::decode_from_slice(data, bincode::config::legacy())
        .ok()
        .map(|(state, _)| state)
}

pub fn process_create_protocol_config(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let data = *bytemuck::try_from_bytes::<CreateProtocolConfigData>(data)
        .map_err(|_| ShieldedPoolError::InvalidInstructionData)?;
    let mut iter = AccountIterator::new(accounts);
    let fee_payer = iter.next_signer("fee_payer")?;
    let protocol_config = iter.next_mut("protocol_config")?;
    let system_program = iter.next_account("system_program")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }
    if *fee_payer.address() != data.protocol_authority {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    check_initialization_authority(fee_payer, program, program_data)?;

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

/// Front-run protection (INV-CREATE-PC-10): on an upgradeable deployment whose
/// `ProgramData` names an upgrade authority, only that authority may pay for
/// (and thereby name) the one-time protocol config. The deployment shape
/// itself gates the check -- an attacker cannot influence the owner or
/// contents of the program's own account, so:
///
/// - non-upgradeable deployments skip the check (the gate applies to loader-v3
///   upgradeable deployments only; loader-v4/native deploys skip it);
/// - an unset or zeroed upgrade authority (immutable program, LiteSVM harness,
///   localnet `--bpf-program` on solana-test-validator 4.x, which loads via
///   the upgradeable loader with a zeroed authority) skips it.
///
/// Operational note: renouncing the upgrade authority BEFORE init reopens
/// permissionless init (the gate no longer names an authority), so deploys
/// must init the config before `--final`.
///
/// Anything malformed or forged (wrong program account, wrong `ProgramData`
/// address/owner, truncated state) fails closed.
fn check_initialization_authority(
    fee_payer: &AccountView,
    program: &AccountView,
    program_data: &AccountView,
) -> ProgramResult {
    if program.address() != &crate::ID {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    if program.owner().as_array() != &BPF_LOADER_UPGRADEABLE_ID {
        return Ok(());
    }
    let program_state = program
        .try_borrow()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    let Some(UpgradeableLoaderState::Program {
        programdata_address,
    }) = decode_loader_state(&program_state)
    else {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    };
    if program_data.address().as_array() != programdata_address.as_array()
        || program_data.owner().as_array() != &BPF_LOADER_UPGRADEABLE_ID
    {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    let program_data_state = program_data
        .try_borrow()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    let Some(UpgradeableLoaderState::ProgramData {
        upgrade_authority_address,
        ..
    }) = decode_loader_state(&program_data_state)
    else {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    };
    match upgrade_authority_address.map(|key| key.to_bytes()) {
        Some(authority)
            if authority != [0u8; 32] && authority != *fee_payer.address().as_array() =>
        {
            Err(ShieldedPoolError::UnauthorizedCaller.into())
        }
        // No authority set, or a zeroed authority (immutable; the shape
        // solana-test-validator gives `--bpf-program` deployments).
        _ => Ok(()),
    }
}
