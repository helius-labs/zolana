use custom_ring_interface::{CustomRingError, QueueEntry, RecordQueue, RingProgramConfig};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use zolana_account_checks::AccountIterator;

use crate::instructions::shared::check_system_program;

/// A member record write, its writer pays the insert fee unless it is the config authority.
#[must_use]
pub(crate) struct MemberWrite<'c> {
    pub config: &'c RingProgramConfig,
    pub writer: &'c Address,
    pub entry: &'c QueueEntry,
}

impl MemberWrite<'_> {
    pub fn fee(&self) -> Option<u64> {
        let fee = self.config.insert_fee();
        (fee != 0 && self.writer != &self.config.authority).then_some(fee)
    }

    pub fn push(self, queue: &mut RecordQueue) -> ProgramResult {
        queue.push(self.entry, Clock::get()?.slot)?;
        Ok(())
    }
}

/// Read only when a fee is owed.
pub(crate) struct InsertFeeAccounts<'a> {
    payer: &'a AccountView,
    authority: &'a AccountView,
}

impl<'a> InsertFeeAccounts<'a> {
    pub fn validate_and_parse(
        accounts: &mut AccountIterator<'a>,
        config: &RingProgramConfig,
    ) -> Result<Self, ProgramError> {
        let payer = accounts.next_signer_mut("payer")?;
        let authority = accounts.next_mut("authority")?;
        check_system_program(accounts.next_account("system_program")?)?;
        if authority.address() != &config.authority {
            return Err(CustomRingError::FeeRecipient.into());
        }
        Ok(Self { payer, authority })
    }

    pub fn pay(self, lamports: u64) -> ProgramResult {
        Transfer {
            from: self.payer,
            to: self.authority,
            lamports,
        }
        .invoke()
    }
}
