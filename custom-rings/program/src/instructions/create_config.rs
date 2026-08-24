use custom_ring_interface::{CreateConfigIxData, RingProgramConfig};
use pinocchio::{
    cpi::{Seed, Signer},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{loader::UpgradeAuthorityCheck, shared::PdaCheck},
    state::{is_p256_key, RingProgramConfigInitParams},
};

/// Creates the ring's singleton config account (authority + auditor key).
///
/// Only the active Loader v3 upgrade authority can initialize the config.
#[inline(never)]
pub fn process_create_config_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let CreateConfigIxData { auditor_pubkey } =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;

    let mut iter = AccountIterator::new(accounts);
    let payer = iter.next_signer_mut("payer")?;
    let authority = iter.next_signer("authority")?;
    let config_account = iter.next_mut("config")?;
    let system_program = iter.next_account("system_program")?;
    let program = iter.next_account("program")?;
    let program_data = iter.next_account("program_data")?;

    if !pinocchio_system::check_id(system_program.address()) {
        return Err(CustomRingError::InvalidSystemProgram.into());
    }
    UpgradeAuthorityCheck {
        authority,
        program,
        program_data,
    }
    .verify()?;
    // Only SEC1-compressed points are stored: the circuit witnesses the
    // uncompressed auditor key and re-compresses it in-circuit, so a key with
    // any other prefix could never match a proof.
    if !is_p256_key(&auditor_pubkey) {
        return Err(CustomRingError::InvalidAuditorPubkey.into());
    }

    // The config account must be the canonical derivation of `[b"config"]`; a bump
    // from instruction data is never accepted for account creation.
    let bump = PdaCheck {
        address: config_account.address(),
        seeds: &[RingProgramConfig::SEED],
        mismatch: CustomRingError::InvalidConfigPda,
    }
    .verify()?;
    // Reject re-initialization before touching the system program: an already
    // allocated config would otherwise fail inside `Allocate` with an opaque
    // system-program error instead of a named one.
    if config_account.data_len() != 0 {
        return Err(CustomRingError::ConfigAlreadyInitialized.into());
    }

    let authority = *authority.address();
    let bump_seed = [bump];
    let seeds = [
        Seed::from(RingProgramConfig::SEED),
        Seed::from(bump_seed.as_ref()),
    ];
    // Handles the hot path (no lamports) and the cold path (an attacker donated
    // lamports to the address to make a bare `CreateAccount` fail).
    pinocchio_system::create_account_with_minimum_balance_signed(
        config_account,
        RingProgramConfig::SIZE,
        &crate::ID,
        payer,
        None,
        &[Signer::from(seeds.as_ref())],
    )?;

    RingProgramConfigInitParams {
        authority,
        auditor_pubkey,
        bump,
    }
    .init(config_account)
}
