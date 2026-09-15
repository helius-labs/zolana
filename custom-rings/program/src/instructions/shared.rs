use pinocchio::Address;
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use pinocchio::{
    cpi::{invoke_signed_with_slice, MAX_CPI_ACCOUNTS},
    instruction::{InstructionAccount, InstructionView},
};
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, ProgramResult,
};
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use zolana_interface::{RING_AUTH_PDA_SEED, SHIELDED_POOL_PROGRAM_ID};
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use zolana_ring_policy::NAMESPACE_PDA_SEED;

use crate::{
    error::CustomRingError, instructions::policy_shared::namespace_address, state::Account,
};

/// Refunds the rent and closes, `mismatch` when the recipient is the account.
pub(crate) fn close_into(
    account: &mut AccountView,
    rent_recipient: &mut AccountView,
    mismatch: CustomRingError,
) -> ProgramResult {
    if account.address() == rent_recipient.address() {
        return Err(mismatch.into());
    }
    let refund = rent_recipient
        .lamports()
        .checked_add(account.lamports())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    rent_recipient.set_lamports(refund);
    account.set_lamports(0);
    account.close()
}

#[must_use]
pub(crate) struct PdaCheck<'a> {
    pub program_id: &'a Address,
    pub address: &'a Address,
    pub seeds: &'a [&'a [u8]],
    pub mismatch: CustomRingError,
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
impl PdaCheck<'_> {
    #[inline(always)]
    pub fn verify(self) -> Result<u8, ProgramError> {
        let (derived, bump) = Address::find_program_address(self.seeds, self.program_id);
        if !pinocchio::address::address_eq(self.address, &derived) {
            return Err(self.mismatch.into());
        }
        Ok(bump)
    }

    /// The program creates PDA accounts only at the canonical bump, so a
    /// stored bump that re-derives the address proves canonicality.
    #[inline(always)]
    pub fn verify_stored_bump(self, bump: u8) -> Result<(), ProgramError> {
        let bump = [bump];
        let mut seeds: [&[u8]; 3] = [&[]; 3];
        let len = self.seeds.len();
        if len >= seeds.len() {
            return Err(self.mismatch.into());
        }
        seeds[..len].copy_from_slice(self.seeds);
        seeds[len] = &bump;
        let derived = Address::create_program_address(&seeds[..=len], self.program_id)
            .map_err(|_| self.mismatch)?;
        if !pinocchio::address::address_eq(self.address, &derived) {
            return Err(self.mismatch.into());
        }
        Ok(())
    }
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
impl PdaCheck<'_> {
    pub fn verify(self) -> Result<u8, ProgramError> {
        let Self {
            program_id,
            address,
            seeds,
            mismatch,
        } = self;
        let _ = (program_id, address, seeds);
        Err(mismatch.into())
    }

    pub fn verify_stored_bump(self, _bump: u8) -> Result<(), ProgramError> {
        Err(self.mismatch.into())
    }
}

/// Creates `T`'s account at the canonical bump, refusing an occupied one.
#[must_use]
pub(crate) struct PdaCreate<'a> {
    pub program_id: &'a Address,
    pub payer: &'a AccountView,
    pub seeds: &'a [&'a [u8]],
    pub mismatch: CustomRingError,
}

impl PdaCreate<'_> {
    #[inline(always)]
    pub fn create<T: Account>(self, account: &mut AccountView) -> Result<u8, ProgramError> {
        let bump = PdaCheck {
            program_id: self.program_id,
            address: account.address(),
            seeds: self.seeds,
            mismatch: self.mismatch,
        }
        .verify()?;
        if account.data_len() != 0 {
            return Err(T::ALREADY_INITIALIZED.into());
        }
        let bump_seed = [bump];
        let len = self.seeds.len();
        let mut seeds: [Seed; 3] = core::array::from_fn(|_| Seed::from(&bump_seed));
        let Some(signed) = seeds.get_mut(..=len) else {
            return Err(self.mismatch.into());
        };
        for (seed, bytes) in signed.iter_mut().zip(self.seeds) {
            *seed = Seed::from(*bytes);
        }
        pinocchio_system::create_account_with_minimum_balance_signed(
            account,
            T::SIZE,
            self.program_id,
            self.payer,
            None,
            &[Signer::from(&*signed)],
        )?;
        Ok(bump)
    }
}

/// PDAs the ring raises to signers on the forwarded SPP instruction.
#[derive(Clone, Copy)]
pub(crate) enum SppSigners {
    RingAuth,
    RingAuthAndNamespace { bump: u8 },
}

impl SppSigners {
    fn namespace(self, program_id: &Address) -> Result<Option<Address>, CustomRingError> {
        match self {
            Self::RingAuth => Ok(None),
            Self::RingAuthAndNamespace { bump } => namespace_address(program_id, bump).map(Some),
        }
    }
}

/// Forward `data` to SPP with this ring's `ring_auth` PDA flipped to a signer.
///
/// `accounts` must already be ordered exactly as the target SPP instruction
/// expects: the CPI metas are rebuilt from it one-to-one, and pinocchio matches
/// account views to metas by position. `data` keeps its leading tag byte because
/// SPP's dispatcher strips it.
///
/// The generic account type lets callers either forward their whole account list
/// (`deposit`, `transact`) or hand-pick a reordered subset (`init_spp_ring_config`).
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(never)]
pub(crate) fn cpi_spp_signed<A: AsRef<AccountView>>(
    program_id: &Address,
    accounts: &[A],
    data: &[u8],
    signers: SppSigners,
) -> ProgramResult {
    let (ring_auth, bump) = Address::find_program_address(&[RING_AUTH_PDA_SEED], program_id);
    let namespace = signers.namespace(program_id)?;
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
            let is_signer = account.is_signer()
                || account.address() == &ring_auth
                || namespace.is_some_and(|namespace| account.address() == &namespace);
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
    let ring_signer = Signer::from(seeds.as_ref());
    match signers {
        SppSigners::RingAuthAndNamespace {
            bump: namespace_bump,
        } => {
            let namespace_bump = [namespace_bump];
            let namespace_seeds = [
                Seed::from(NAMESPACE_PDA_SEED),
                Seed::from(namespace_bump.as_ref()),
            ];
            let signers = [ring_signer, Signer::from(namespace_seeds.as_ref())];
            invoke_signed_with_slice(&instruction, accounts, &signers)
        }
        SppSigners::RingAuth => {
            invoke_signed_with_slice(&instruction, accounts, core::slice::from_ref(&ring_signer))
        }
    }
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
#[inline(never)]
pub(crate) fn cpi_spp_signed<A: AsRef<AccountView>>(
    program_id: &Address,
    _accounts: &[A],
    _data: &[u8],
    signers: SppSigners,
) -> ProgramResult {
    signers.namespace(program_id)?;
    Err(CustomRingError::InvalidShieldedPoolProgram.into())
}
