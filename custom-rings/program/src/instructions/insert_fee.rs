use custom_ring_interface::{CustomRingError, QueueEntry, RecordQueue, RingProgramConfig};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::Transfer;
use zolana_account_checks::AccountIterator;

use crate::instructions::shared::check_system_program;

#[must_use]
pub(crate) struct MemberWrite<'c> {
    pub config: &'c RingProgramConfig,
    pub writer: &'c Address,
    pub entry: &'c QueueEntry,
    pub max_fee: u64,
}

impl MemberWrite<'_> {
    pub fn validate_fee<'a>(
        &self,
        accounts: &mut AccountIterator<'a>,
    ) -> Result<Option<InsertFee<'a>>, ProgramError> {
        let Some(lamports) = self.config.insert_fee_for(self.writer) else {
            return Ok(None);
        };
        if lamports > self.max_fee {
            return Err(CustomRingError::InsertFeeAboveMax.into());
        }
        let payer = accounts.next_signer_mut("payer")?;
        let authority = accounts.next_mut("authority")?;
        check_system_program(accounts.next_account("system_program")?)?;
        if authority.address() != &self.config.authority {
            return Err(CustomRingError::FeeRecipient.into());
        }
        Ok(Some(InsertFee {
            payer,
            authority,
            lamports,
        }))
    }

    pub fn push(self, queue: &mut RecordQueue) -> ProgramResult {
        queue.push(self.entry, Clock::get()?.slot)?;
        Ok(())
    }
}

#[must_use]
pub(crate) struct InsertFee<'a> {
    payer: &'a AccountView,
    authority: &'a AccountView,
    lamports: u64,
}

impl InsertFee<'_> {
    pub fn pay(self) -> ProgramResult {
        Transfer {
            from: self.payer,
            to: self.authority,
            lamports: self.lamports,
        }
        .invoke()
    }
}
