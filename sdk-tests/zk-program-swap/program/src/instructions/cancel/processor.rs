use borsh::{BorshDeserialize, BorshSerialize};
use light_program_profiler::profile;
use pinocchio::{
    sysvars::{clock::Clock, Sysvar},
    AccountView, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::instruction::instruction_data::transact::TransactIxDataRef;

use crate::{
    error::SwapError,
    instructions::{
        cancel::verify::CancelPublicInput,
        shared::{cpi_spp_transact_signed, hash_field},
    },
};

#[inline(always)]
pub(crate) fn check_after_window(now: i64, expiry_unix_ts: u64) -> ProgramResult {
    if now >= 0 && (now as u64) > expiry_unix_ts {
        Ok(())
    } else {
        Err(SwapError::NotYetExpired.into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct CancelProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
}

#[inline(never)]
#[profile]
pub fn process_cancel(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let _payer = iter.next_signer_mut("payer")?;
    // The maker signs the cancel; the escrow's committed maker_owner_hash binds
    // this pubkey (owner_pk_field) in the cancel proof, so only the maker can
    // cancel and the maker knows the refund blinding it chose.
    let maker_owner_pk_field = hash_field(iter.next_signer("maker")?.address().as_array())?;

    let mut cursor = data;
    let proof =
        CancelProof::deserialize(&mut cursor).map_err(|_| SwapError::InvalidInstructionData)?;
    let order_expiry =
        u64::deserialize(&mut cursor).map_err(|_| SwapError::InvalidInstructionData)?;
    let transact_bytes = cursor;
    let transact = TransactIxDataRef::from_bytes(transact_bytes)
        .map_err(|_| SwapError::InvalidInstructionData)?;

    let clock = Clock::get()?;
    check_after_window(clock.unix_timestamp, order_expiry)?;

    CancelPublicInput {
        private_tx_hash: transact.private_tx_hash,
        expiry: order_expiry,
        maker_owner_pk_field: &maker_owner_pk_field,
    }
    .verify(&proof)?;

    let spp_accounts = iter.remaining()?;
    cpi_spp_transact_signed(spp_accounts, transact_bytes)
}

#[cfg(test)]
mod tests {
    use super::check_after_window;

    #[test]
    fn cancel_window_boundary() {
        assert!(check_after_window(100, 100).is_err());
        assert!(check_after_window(99, 100).is_err());
        assert!(check_after_window(101, 100).is_ok());
        assert!(check_after_window(-1, 100).is_err());
    }
}
