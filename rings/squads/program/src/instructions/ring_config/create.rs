use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use solana_loader_v3_interface::state::UpgradeableLoaderState;
use zolana_interface::BPF_LOADER_UPGRADEABLE_ID;
use zolana_squads_interface::{
    constants::REQUIRED_AUDITOR_KEY_COUNT, error::SquadsZoneError,
    instruction::instruction_data::CreateZoneConfigIxData, state::zone_config::ZoneConfig,
    ZONE_CONFIG_PDA_SEED,
};

use crate::shared::pda::{verify_pda, CreatePdaAccount};

/// `create_zone_config` (tag 3): initialize the singleton zone config PDA.
///
/// Accounts: `[creator (signer, writable, fee payer), zone_config (writable, the
/// new PDA), system_program, program, program_data]`. The config is created at
/// the canonical `[b"zone_config"]` PDA, sized exactly for its serialized form,
/// and stamped with the discriminator via [`ZoneConfig::new`]. On an
/// upgradeable loader-v3 deployment, `creator` must be the program's deploy
/// upgrade authority.
#[inline(never)]
pub fn process_create_zone_config_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() < 5 {
        return Err(SquadsZoneError::InvalidInstructionData.into());
    }
    let (creator, rest) = accounts
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (zone_config, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (system_program, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let (program, rest) = rest
        .split_first_mut()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;
    let program_data = rest
        .first()
        .ok_or(SquadsZoneError::InvalidInstructionData)?;

    if !creator.is_signer() {
        return Err(SquadsZoneError::MissingAuthoritySignature.into());
    }
    if !pinocchio_system::check_id(system_program.address()) {
        return Err(ProgramError::IncorrectProgramId);
    }
    check_initialization_authority(creator, program, program_data)?;

    let ix = CreateZoneConfigIxData::deserialize(data)
        .map_err(|_| SquadsZoneError::InvalidInstructionData)?;

    if ix.auditor_keys.len() != REQUIRED_AUDITOR_KEY_COUNT {
        return Err(SquadsZoneError::InvalidAuditorKeyCount.into());
    }

    let bump = verify_pda(zone_config.address(), &[ZONE_CONFIG_PDA_SEED], &crate::ID)?;

    let config = ZoneConfig::new(
        ix.authority,
        ix.co_signer,
        ix.max_proposal_lifetime,
        ix.auditor_keys.clone(),
        ix.merge_authorities.clone(),
    );
    let space = ZoneConfig::account_size(ix.auditor_keys.len(), ix.merge_authorities.len());

    CreatePdaAccount {
        fee_payer: creator,
        new_account: &mut *zone_config,
        space,
        owner: &crate::ID,
        signer_seeds: [ZONE_CONFIG_PDA_SEED],
        bump,
    }
    .execute()
    .map_err(|_| SquadsZoneError::InvalidZoneConfig)?;

    write_zone_config(zone_config, &config)
}

/// Decode the canonical loader-v3 account state without reading the trailing
/// program bytecode in a `ProgramData` account.
fn decode_loader_state(data: &[u8]) -> Option<UpgradeableLoaderState> {
    bincode::serde::decode_from_slice(data, bincode::config::legacy())
        .ok()
        .map(|(state, _)| state)
}

/// Prevent front-running of the singleton config. Initialization is supported
/// only while this program is a loader-v3 upgradeable deployment whose live
/// upgrade authority signs. Unsupported loaders, malformed metadata, and an
/// immutable ProgramData account all fail closed. Deployments must initialize
/// the singleton before relinquishing upgrade authority.
fn check_initialization_authority(
    creator: &AccountView,
    program: &AccountView,
    program_data: &AccountView,
) -> ProgramResult {
    if program.address() != &crate::ID {
        return Err(SquadsZoneError::InvalidInitializationAuthority.into());
    }
    if program.owner().as_array() != &BPF_LOADER_UPGRADEABLE_ID {
        return Err(SquadsZoneError::InvalidInitializationAuthority.into());
    }

    let program_state = program
        .try_borrow()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    let Some(UpgradeableLoaderState::Program {
        programdata_address,
    }) = decode_loader_state(&program_state)
    else {
        return Err(SquadsZoneError::InvalidInitializationAuthority.into());
    };
    if program_data.address().as_array() != programdata_address.as_array()
        || program_data.owner().as_array() != &BPF_LOADER_UPGRADEABLE_ID
    {
        return Err(SquadsZoneError::InvalidInitializationAuthority.into());
    }

    let program_data_state = program_data
        .try_borrow()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    let Some(UpgradeableLoaderState::ProgramData {
        upgrade_authority_address,
        ..
    }) = decode_loader_state(&program_data_state)
    else {
        return Err(SquadsZoneError::InvalidInitializationAuthority.into());
    };
    match upgrade_authority_address.map(|key| key.to_bytes()) {
        Some(authority) if authority != [0u8; 32] && authority == *creator.address().as_array() => {
            Ok(())
        }
        _ => Err(SquadsZoneError::InvalidInitializationAuthority.into()),
    }
}

/// Serialize `config` and overwrite the account data in place. The account must
/// already be sized to exactly the serialized length. The create path allocates
/// it that way. The update path resizes it first.
#[inline(never)]
pub(super) fn write_zone_config(account: &mut AccountView, config: &ZoneConfig) -> ProgramResult {
    let bytes = config
        .serialize()
        .map_err(|_| SquadsZoneError::Deserialization)?;
    let mut data = account
        .try_borrow_mut()
        .map_err(|_| SquadsZoneError::InvalidZoneConfig)?;
    let slot = data
        .get_mut(..bytes.len())
        .ok_or(SquadsZoneError::InvalidAccountSize)?;
    slot.copy_from_slice(&bytes);
    Ok(())
}
