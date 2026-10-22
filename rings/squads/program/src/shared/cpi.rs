//! `ring_auth`-signed CPIs into the shielded-pool program (SPP).
//!
//! The ring forwards SPP account lists unchanged, so the CPI metas are rebuilt
//! one-to-one from the received account views, with this program's
//! `[b"ring_auth"]` PDA (SPP's `ring_config`) flipped to a signer.

use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_interface::SHIELDED_POOL_PROGRAM_ID;
use zolana_squads_interface::error::SquadsRingError;

/// Upper bound on forwarded SPP accounts; a v1 message names at most 64.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
const MAX_SPP_CPI_ACCOUNTS: usize = 64;

/// Require the SPP program account in the forwarded list: SPP's `emit_event`
/// self-CPI resolves only if its own program account is present.
#[inline(always)]
pub fn validate_spp_program<A: AsRef<AccountView>>(accounts: &[A]) -> Result<(), ProgramError> {
    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    let spp = accounts
        .iter()
        .map(AsRef::as_ref)
        .find(|account| account.address() == &spp_id)
        .ok_or(SquadsRingError::InvalidSppProgram)?;
    if !spp.executable() {
        return Err(SquadsRingError::InvalidSppProgram.into());
    }
    Ok(())
}

/// Forward a settlement to SPP: the forwarded account list must carry the SPP
/// program account for SPP's event self-CPI.
#[inline(always)]
pub fn forward_to_spp<A: AsRef<AccountView>>(accounts: &[A], data: &[u8]) -> ProgramResult {
    validate_spp_program(accounts)?;
    cpi_spp_signed(accounts, data)
}

/// Invoke SPP with `data` (tag included) over `accounts`, signing with the
/// `ring_auth` PDA. `accounts` must already be in the target SPP instruction's
/// order and contain the `ring_auth` PDA.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(never)]
pub fn cpi_spp_signed<A: AsRef<AccountView>>(accounts: &[A], data: &[u8]) -> ProgramResult {
    use pinocchio::{
        cpi::{invoke_signed_with_slice, Seed, Signer},
        instruction::{InstructionAccount, InstructionView},
    };
    use zolana_squads_interface::RING_AUTH_PDA_SEED;

    let (ring_auth, bump) = Address::find_program_address(&[RING_AUTH_PDA_SEED], &crate::ID);
    if !accounts
        .iter()
        .any(|account| account.as_ref().address() == &ring_auth)
    {
        return Err(SquadsRingError::InvalidRingAuth.into());
    }
    if accounts.len() > MAX_SPP_CPI_ACCOUNTS {
        return Err(SquadsRingError::InvalidInstructionData.into());
    }

    let metas: Vec<InstructionAccount> = accounts
        .iter()
        .map(|account| {
            let account = account.as_ref();
            let is_signer = account.is_signer() || account.address() == &ring_auth;
            InstructionAccount::new(account.address(), account.is_writable(), is_signer)
        })
        .collect();
    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    let instruction = InstructionView {
        program_id: &spp_id,
        accounts: &metas,
        data,
    };
    let bump = [bump];
    let seeds = [Seed::from(RING_AUTH_PDA_SEED), Seed::from(bump.as_ref())];
    let signer = Signer::from(seeds.as_ref());
    invoke_signed_with_slice(&instruction, accounts, core::slice::from_ref(&signer))
        .map_err(|_| SquadsRingError::SppCpiFailed.into())
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[inline(never)]
pub fn cpi_spp_signed<A: AsRef<AccountView>>(_accounts: &[A], _data: &[u8]) -> ProgramResult {
    Err(SquadsRingError::SppCpiFailed.into())
}
