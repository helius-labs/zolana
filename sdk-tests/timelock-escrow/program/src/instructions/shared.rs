#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use light_program_profiler::profile;
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
};
use pinocchio::{AccountView, Address, ProgramResult};
use zolana_interface::instruction::instruction_data::transact::TransactIxData;
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use zolana_program::cpi::{SppTransactAccounts, TransactAccountsError};

use crate::error::TimelockEscrowError;

pub fn u64_right_align(value: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&value.to_be_bytes());
    bytes
}

#[inline(always)]
pub fn check_after_window(now: i64, unlock_unix_ts: u64) -> ProgramResult {
    if now >= 0 && (now as u64) > unlock_unix_ts {
        Ok(())
    } else {
        Err(TimelockEscrowError::NotYetUnlocked.into())
    }
}

pub struct EscrowAuthority {
    address: Address,
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    bump: u8,
}

impl EscrowAuthority {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    pub fn find() -> Self {
        let (address, bump) =
            Address::find_program_address(&[crate::ESCROW_AUTHORITY_PDA_SEED], &crate::ID);
        Self { address, bump }
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    pub fn find() -> Self {
        unimplemented!("EscrowAuthority::find requires Solana runtime syscalls")
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    #[inline(never)]
    #[profile]
    pub fn invoke_transact(
        &self,
        spp_accounts: &[AccountView],
        transact: &TransactIxData,
    ) -> ProgramResult {
        let transact_bytes = transact
            .serialize()
            .map_err(|_| TimelockEscrowError::InvalidInstructionData)?;
        let signer_pdas = [&self.address];
        let spp = SppTransactAccounts::new(spp_accounts, &signer_pdas)
            .map_err(transact_accounts_error)?;
        let bump = [self.bump];
        let seeds = [
            Seed::from(crate::ESCROW_AUTHORITY_PDA_SEED),
            Seed::from(&bump),
        ];
        spp.invoke::<16>(&transact_bytes, &[Signer::from(&seeds)])
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    pub fn invoke_transact(
        &self,
        _spp_accounts: &[AccountView],
        _transact: &TransactIxData,
    ) -> ProgramResult {
        unimplemented!("EscrowAuthority::invoke_transact requires Solana runtime syscalls")
    }
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn transact_accounts_error(error: TransactAccountsError) -> ProgramError {
    match error {
        TransactAccountsError::InvalidSppProgram => {
            TimelockEscrowError::InvalidShieldedPoolProgram.into()
        }
        TransactAccountsError::MissingPdaSigner { .. } => {
            TimelockEscrowError::MissingEscrowAuthority.into()
        }
        TransactAccountsError::NotEnoughAccounts => ProgramError::NotEnoughAccountKeys,
    }
}
