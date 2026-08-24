use pinocchio::Address;
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use pinocchio::{
    cpi::{invoke_signed_with_slice, Seed, Signer, MAX_CPI_ACCOUNTS},
    instruction::{InstructionAccount, InstructionView},
};
use pinocchio::{error::ProgramError, AccountView, ProgramResult};
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use zolana_interface::{RING_AUTH_PDA_SEED, SHIELDED_POOL_PROGRAM_ID};

use crate::error::CustomRingError;

#[must_use]
pub(crate) struct PdaCheck<'a> {
    pub address: &'a Address,
    pub seeds: &'a [&'a [u8]],
    pub mismatch: CustomRingError,
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
impl PdaCheck<'_> {
    #[inline(always)]
    pub fn verify(self) -> Result<u8, ProgramError> {
        let (derived, bump) = Address::find_program_address(self.seeds, &crate::ID);
        if !pinocchio::address::address_eq(self.address, &derived) {
            return Err(self.mismatch.into());
        }
        Ok(bump)
    }
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
impl PdaCheck<'_> {
    pub fn verify(self) -> Result<u8, ProgramError> {
        let Self {
            address,
            seeds,
            mismatch,
        } = self;
        let _ = (address, seeds);
        Err(mismatch.into())
    }
}

/// Forward `data` to SPP with this ring's `ring_auth` PDA flipped to a signer.
///
/// `accounts` must already be ordered exactly as the target SPP instruction
/// expects: the CPI metas are rebuilt from it one-to-one, and pinocchio matches
/// account views to metas by position. `data` keeps its leading tag byte because
/// SPP's dispatcher strips it.
///
/// Only the `ring_auth` account gains a signature; every other privilege is
/// copied from the account view, so the ring cannot escalate an account the
/// caller passed as readonly or unsigned.
///
/// The generic account type lets callers either forward their whole account list
/// (`deposit`, `transact`) or hand-pick a reordered subset (`init_spp_ring_config`).
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(never)]
pub(crate) fn cpi_spp_signed<A: AsRef<AccountView>>(accounts: &[A], data: &[u8]) -> ProgramResult {
    let (ring_auth, bump) = Address::find_program_address(&[RING_AUTH_PDA_SEED], &crate::ID);
    if !accounts
        .iter()
        .any(|account| account.as_ref().address() == &ring_auth)
    {
        return Err(CustomRingError::MissingRingAuth.into());
    }

    if accounts.len() > MAX_CPI_ACCOUNTS {
        return Err(CustomRingError::TooManyAccounts.into());
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
    // Upper bound: a five-mint ring deposit carries the fixed prefix, ring_auth
    // and five SPL settlement groups.
    invoke_signed_with_slice(&instruction, accounts, core::slice::from_ref(&signer))
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[inline(never)]
pub(crate) fn cpi_spp_signed<A: AsRef<AccountView>>(
    _accounts: &[A],
    _data: &[u8],
) -> ProgramResult {
    Err(CustomRingError::InvalidShieldedPoolProgram.into())
}
