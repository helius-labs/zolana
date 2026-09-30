#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use light_program_profiler::profile;
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use pinocchio::cpi::{Seed, Signer};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use wincode::{config::DefaultConfig, SchemaReadOwned};
use zolana_interface::instruction::instruction_data::transact::TransactIxDataRef;
use zolana_program::compression::PdaOwner;
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use zolana_program::cpi::{SppTransactAccounts, TransactAccountsError};

use crate::error::TimelockEscrowError;

pub struct IxData<'a, A> {
    pub args: A,
    pub private_tx_hash: &'a [u8; 32],
    pub transact: &'a [u8],
}

impl<'a, A: SchemaReadOwned<DefaultConfig, Dst = A>> IxData<'a, A> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ProgramError> {
        let mut transact = data;
        let args = wincode::deserialize_from(&mut transact)
            .map_err(|_| TimelockEscrowError::InvalidInstructionData)?;
        let private_tx_hash = TransactIxDataRef::from_bytes(transact)
            .map_err(|_| TimelockEscrowError::InvalidInstructionData)?
            .private_tx_hash;
        Ok(Self {
            args,
            private_tx_hash,
            transact,
        })
    }
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
    creator: Address,
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    bump: u8,
}

impl EscrowAuthority {
    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    pub fn find(creator: &Address) -> Self {
        let (address, bump) =
            Address::find_program_address(&crate::escrow_authority_seeds(creator), &crate::ID);
        Self {
            address,
            creator: *creator,
            bump,
        }
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    pub fn find(_creator: &Address) -> Self {
        unimplemented!("EscrowAuthority::find requires Solana runtime syscalls")
    }

    pub fn address(&self) -> &Address {
        &self.address
    }

    pub fn owner_hash(&self) -> Result<[u8; 32], TimelockEscrowError> {
        Ok(*PdaOwner::new(&self.address)
            .map_err(|_| TimelockEscrowError::HashingFailed)?
            .owner_hash())
    }

    #[cfg(any(target_os = "solana", target_arch = "bpf"))]
    #[inline(never)]
    #[profile]
    pub fn invoke_transact(&self, spp_accounts: &[AccountView], transact: &[u8]) -> ProgramResult {
        let signer_pdas = [&self.address];
        let spp = SppTransactAccounts::new(spp_accounts, &signer_pdas)
            .map_err(transact_accounts_error)?;
        let bump = [self.bump];
        let seeds = [
            Seed::from(crate::ESCROW_AUTHORITY_PDA_SEED),
            Seed::from(self.creator.as_array()),
            Seed::from(&bump),
        ];
        spp.invoke::<16>(transact, &[Signer::from(&seeds)])
    }

    #[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
    pub fn invoke_transact(
        &self,
        _spp_accounts: &[AccountView],
        _transact: &[u8],
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
