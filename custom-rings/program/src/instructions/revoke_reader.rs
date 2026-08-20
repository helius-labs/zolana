use pinocchio::{error::ProgramError, AccountView, ProgramResult};
use zolana_account_checks::AccountIterator;

use crate::{
    error::CustomRingError,
    instructions::{
        grant_reader::ReaderIxData,
        loader::{load_config, load_reader_record},
    },
};

/// Closes `reader`'s record, which ends its delegated ring-scope reads.
///
/// Accounts `[authority(s), config, reader_record(w), rent_recipient(w)]`.
#[inline(never)]
pub fn process_revoke_reader_ix(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let ReaderIxData { reader } =
        wincode::deserialize_exact(data).map_err(|_| CustomRingError::InvalidInstructionData)?;

    let mut iter = AccountIterator::new(accounts);
    let authority = iter.next_signer("authority")?;
    let config_account = iter.next_account("config")?;
    let record_account = iter.next_mut("reader_record")?;
    let rent_recipient = iter.next_mut("rent_recipient")?;

    let config = load_config(config_account)?;
    if authority.address() != &config.authority {
        return Err(CustomRingError::UnauthorizedAuthority.into());
    }
    // The record must name the key in the data, or revoking one reader could
    // close another reader's record.
    if load_reader_record(record_account)?.reader != reader {
        return Err(CustomRingError::InvalidReaderRecord.into());
    }

    let refund = rent_recipient
        .lamports()
        .checked_add(record_account.lamports())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    rent_recipient.set_lamports(refund);
    record_account.set_lamports(0);
    record_account.close()
}
