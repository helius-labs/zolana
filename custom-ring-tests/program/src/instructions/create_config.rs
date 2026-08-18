use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use wincode::{SchemaRead, SchemaWrite};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::loader::check_upgrade_authority,
    state::{RingProgramConfig, RingProgramConfigInitParams},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, SchemaRead, SchemaWrite)]
pub struct CreateConfigIxData {
    /// Auditor P256 public key in SEC1 compressed form.
    pub auditor_pubkey: [u8; 33],
}

/// Creates the ring's singleton config account (authority + auditor key).
///
/// Accounts `[payer(w,s), authority(s), config(w), system_program, program,
/// program_data]`. When the deployment names an upgrade authority, only that
/// key may sign as `authority`; otherwise the first caller wins.
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
    check_upgrade_authority(authority, program, program_data)?;
    // Only SEC1-compressed points are stored: the circuit witnesses the
    // uncompressed auditor key and re-compresses it in-circuit, so a key with
    // any other prefix could never match a proof.
    match auditor_pubkey.first() {
        Some(2) | Some(3) => {}
        _ => return Err(CustomRingError::InvalidAuditorPubkey.into()),
    }

    let bump = verify_config_pda(config_account.address())?;
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

/// The config account must be the canonical derivation of `[b"config"]`; a bump
/// from instruction data is never accepted for account creation.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn verify_config_pda(config: &Address) -> Result<u8, ProgramError> {
    let (derived, bump) = Address::find_program_address(&[RingProgramConfig::SEED], &crate::ID);
    if !pinocchio::address::address_eq(config, &derived) {
        return Err(CustomRingError::InvalidConfigPda.into());
    }
    Ok(bump)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn verify_config_pda(_config: &Address) -> Result<u8, ProgramError> {
    unimplemented!("config PDA derivation requires Solana runtime syscalls")
}
