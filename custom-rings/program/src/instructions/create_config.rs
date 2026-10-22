use bytemuck::Zeroable;
use custom_ring_interface::{
    CreateConfigIxData, CustomRingError, RingMode, RingProgramConfig, DEFAULT_INSERT_FEE,
    RING_PROGRAM_CONFIG,
};
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::{
    instructions::{
        loader::UpgradeAuthorityCheck,
        shared::{check_system_program, parse, Pda},
    },
    state::{is_x25519_key, Init},
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
        kind,
    } = parse(data)?;

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config = iter.next_mut("config")?;
    let system_program = iter.next_account("system_program")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;

    // 1. The caller controls the deployed binary the config configures.
    check_system_program(system_program)?;
    UpgradeAuthorityCheck {
        program_id,
        authority,
        program,
        program_data,
    }
    .verify()?;
    // 2. The envelope proves agreement with the tagged canonical X25519 key.
    if !is_x25519_key(&auditor_pubkey) {
        return Err(CustomRingError::InvalidAuditorPubkey.into());
    }
    // 3. The canonical PDA holds the kind for the ring's life.
    let bump = Pda {
        program_id,
        seeds: &[RingProgramConfig::SEED],
    }
    .create::<RingProgramConfig>(payer, config)?;
    Init(&RingProgramConfig {
        discriminator: RING_PROGRAM_CONFIG,
        authority: *authority.address(),
        auditor_pubkey,
        bump,
        has_policy: u8::from(kind.has_policy()),
        mode: if kind.anonymous() {
            RingMode::Anonymous
        } else {
            RingMode::Off
        } as u8,
        insert_fee: DEFAULT_INSERT_FEE.to_le_bytes(),
        created_slot: Clock::get()?.slot.to_le_bytes(),
        ..RingProgramConfig::zeroed()
    })
    .init(config)
}
