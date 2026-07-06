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
        fill_verifiable_encryption::verify::FillVerifiableEncryptionPublicInput,
        shared::cpi_spp_transact_signed,
    },
};

#[inline(always)]
pub(crate) fn check_within_window(now: i64, expiry_unix_ts: u64) -> ProgramResult {
    if now >= 0 && (now as u64) <= expiry_unix_ts {
        Ok(())
    } else {
        Err(SwapError::Expired.into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshDeserialize, BorshSerialize)]
pub struct FillVerifiableEncryptionProof {
    pub proof_a: [u8; 32],
    pub proof_b: [u8; 64],
    pub proof_c: [u8; 32],
    pub commitment: [u8; 32],
    pub commitment_pok: [u8; 32],
}

#[inline(never)]
#[profile]
pub fn process_fill_verifiable_encryption(
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let mut iter = AccountIterator::new(accounts);
    let _payer = iter.next_signer_mut("payer")?;

    let mut cursor = data;
    let proof = FillVerifiableEncryptionProof::deserialize(&mut cursor)
        .map_err(|_| SwapError::InvalidInstructionData)?;
    let transact_bytes = cursor;
    let transact = TransactIxDataRef::from_bytes(transact_bytes)
        .map_err(|_| SwapError::InvalidInstructionData)?;

    let clock = Clock::get()?;
    check_within_window(clock.unix_timestamp, transact.expiry_unix_ts)?;

    let destination_ciphertext = transact
        .output_ciphertexts
        .last()
        .ok_or(SwapError::InvalidInstructionData)?
        .data;

    FillVerifiableEncryptionPublicInput {
        private_tx_hash: transact.private_tx_hash,
        expiry: transact.expiry_unix_ts,
        destination_ciphertext,
    }
    .verify(&proof)?;

    let spp_accounts = iter.remaining()?;
    cpi_spp_transact_signed(spp_accounts, transact_bytes)
}

#[cfg(test)]
mod tests {
    use super::check_within_window;
    use crate::instructions::cancel::processor::check_after_window;

    #[test]
    fn fill_window_boundary() {
        assert!(check_within_window(0, 100).is_ok());
        assert!(check_within_window(100, 100).is_ok());
        assert!(check_within_window(99, 100).is_ok());
        assert!(check_within_window(101, 100).is_err());
        assert!(check_within_window(-1, 100).is_err());
    }

    #[test]
    fn windows_are_mutually_exclusive() {
        for now in [0i64, 50, 100, 101, 1_000] {
            let expiry = 100u64;
            assert_ne!(
                check_within_window(now, expiry).is_ok(),
                check_after_window(now, expiry).is_ok()
            );
        }
    }
}
