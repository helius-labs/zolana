use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    error::ShieldedPoolError, instruction::CreateProtocolConfigData, state::ProtocolConfig,
    BPF_LOADER_UPGRADEABLE_ID, SPP_PROTOCOL_CONFIG_PDA_SEED,
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

/// Front-run protection (F-07): on an upgradeable deployment whose
/// `ProgramData` names an upgrade authority, only that authority may pay for
/// (and thereby name) the one-time protocol config. The deployment shape
/// itself gates the check -- an attacker cannot influence the owner or
/// contents of the program's own account, so:
///
/// - non-upgradeable deployments skip the check;
/// - an unset or zeroed upgrade authority (immutable program, LiteSVM harness,
///   localnet `--bpf-program` on solana-test-validator 4.x, which loads via
///   the upgradeable loader with a zeroed authority) skips it.
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
    let program_data_address = parse_program_data_address(&program_state)
        .ok_or(ShieldedPoolError::UnauthorizedCaller)?;
    if program_data.address().as_array() != &program_data_address
        || program_data.owner().as_array() != &BPF_LOADER_UPGRADEABLE_ID
    {
        return Err(ShieldedPoolError::UnauthorizedCaller.into());
    }
    let program_data_state = program_data
        .try_borrow()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;
    match parse_upgrade_authority(&program_data_state)
        .ok_or(ShieldedPoolError::UnauthorizedCaller)?
    {
        Some(authority) if authority != [0u8; 32] && authority != *fee_payer.address().as_array() => {
            Err(ShieldedPoolError::UnauthorizedCaller.into())
        }
        // No authority set, or a zeroed authority (immutable; the shape
        // solana-test-validator gives `--bpf-program` deployments).
        _ => Ok(()),
    }
}

/// `UpgradeableLoaderState::Program { programdata_address }`: u32 tag 2
/// followed by the 32-byte address (bincode).
fn parse_program_data_address(program_state: &[u8]) -> Option<[u8; 32]> {
    let (tag, address) = program_state.split_first_chunk::<4>()?;
    if u32::from_le_bytes(*tag) != 2 {
        return None;
    }
    address.first_chunk::<32>().copied()
}

/// `UpgradeableLoaderState::ProgramData { slot, upgrade_authority_address }`:
/// u32 tag 3, u64 slot, u8 option tag, optional 32-byte authority (bincode
/// encodes `Option` as a single byte, not a u32).
fn parse_upgrade_authority(program_data_state: &[u8]) -> Option<Option<[u8; 32]>> {
    let (tag, rest) = program_data_state.split_first_chunk::<4>()?;
    if u32::from_le_bytes(*tag) != 3 {
        return None;
    }
    let (_, rest) = rest.split_first_chunk::<8>()?;
    let (&option_tag, rest) = rest.split_first()?;
    match option_tag {
        0 => Some(None),
        1 => Some(Some(rest.first_chunk::<32>().copied()?)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn program_state(program_data_address: [u8; 32]) -> Vec<u8> {
        let mut state = 2u32.to_le_bytes().to_vec();
        state.extend_from_slice(&program_data_address);
        state
    }

    fn program_data_state(authority: Option<[u8; 32]>) -> Vec<u8> {
        let mut state = 3u32.to_le_bytes().to_vec();
        state.extend_from_slice(&7u64.to_le_bytes());
        match authority {
            // bincode encodes `Option` as a single byte; the trailing bytes
            // mimic the ELF bytecode that follows the header on-chain.
            Some(authority) => {
                state.push(1);
                state.extend_from_slice(&authority);
            }
            None => state.push(0),
        }
        state.extend_from_slice(&[0x7f, 0x45, 0x4c, 0x46]);
        state
    }

    #[test]
    fn parses_program_data_address() {
        let address = [0xAB; 32];
        assert_eq!(parse_program_data_address(&program_state(address)), Some(address));
        assert_eq!(parse_program_data_address(&[]), None);
        assert_eq!(parse_program_data_address(&3u32.to_le_bytes()), None);
        // Wrong variant tag (ProgramData, not Program).
        assert_eq!(parse_program_data_address(&program_data_state(None)), None);
    }

    #[test]
    fn parses_upgrade_authority() {
        let authority = [0xCD; 32];
        assert_eq!(
            parse_upgrade_authority(&program_data_state(Some(authority))),
            Some(Some(authority))
        );
        assert_eq!(parse_upgrade_authority(&program_data_state(None)), Some(None));
        // The solana-test-validator `--bpf-program` shape: authority set to
        // the zeroed address, ELF bytecode trailing the header.
        assert_eq!(
            parse_upgrade_authority(&program_data_state(Some([0u8; 32]))),
            Some(Some([0u8; 32]))
        );
        // Unknown option tag and truncated payloads fail closed.
        let mut bad_option = program_data_state(None);
        *bad_option.get_mut(12).expect("option tag byte") = 9;
        assert_eq!(parse_upgrade_authority(&bad_option), None);
        let mut truncated = program_data_state(Some(authority));
        truncated.truncate(20);
        assert_eq!(parse_upgrade_authority(&truncated), None);
        // Wrong variant tag (Program, not ProgramData).
        assert_eq!(parse_upgrade_authority(&program_state(authority)), None);
    }
}
