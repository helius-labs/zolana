use custom_ring_interface::{
    CreateConfigIxData, CustomRingError, RingProgramConfig, RING_PROGRAM_CONFIG,
};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    instructions::{
        loader::check_upgrade_authority,
        shared::{check_system_program, create_pda, parse},
    },
    state::{is_p256_key, Init},
};

/// Only the active loader-v3 upgrade authority creates the ring's singleton config.
#[inline(never)]
pub fn process_create_config_ix(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let CreateConfigIxData {
        auditor_pubkey,
        has_policy,
    } = parse(data)?;
    // Transact reads any nonzero as policy, a stored 2 would look distinct.
    if has_policy > 1 {
        return Err(CustomRingError::InvalidInstructionData.into());
    }

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("config")?;
    let system_program = iter.next_account("system_program")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;

    check_system_program(system_program)?;
    check_upgrade_authority(program_id, authority, program, program_data)?;
    // The circuit recompresses the auditor key, another prefix never matches a proof.
    if !is_p256_key(&auditor_pubkey) {
        return Err(CustomRingError::InvalidAuditorPubkey.into());
    }
    let bump =
        create_pda::<RingProgramConfig, 1>(program_id, payer, config, &[RingProgramConfig::SEED])?;
    Init(&RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: *authority.address(),
        auditor_pubkey,
        bump,
        has_policy,
        key_escrow: 0,
    })
    .init(config)
}
